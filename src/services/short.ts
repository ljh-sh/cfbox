// src/services/short.ts — short-link service.
//
// Endpoints:
//   POST /short               JSON { url, code? }     → 201 { code, url, short, createdAt }
//   GET  /short?url=X&code=Y                            → 302 to /r/<code>  (browser-friendly)
//   GET  /r/<code>                                      → 302 to original  (+ fire-and-forget click tick)
//
// Codes:
//   - Custom: 2-32 chars matching /^[A-Za-z0-9_-]{2,32}$/ (taken → 409, invalid → 400)
//   - Auto:   8-char random base62 (~47 bits entropy, 281T code space)
//
// Storage: Workers KV, binding `env.SHORT_KV`.
//
// URL validation: only http(s) accepted; javascript:, data:, etc. → 400.
// Collision retry: 5 attempts before 503.

import type { Service } from '../types';

const RANDOM_CODE_LEN = 8;
const BASE62 =
	'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const VALID_CODE_RE = /^[A-Za-z0-9_-]{2,32}$/;

/**
 * Admin password gate — protects every write to /short.
 * Pass can be supplied via JSON body field `pass` (POST) or query param `?pass=...` (GET).
 * This is the v0.3 hardcode for a single-user personal toolbox; swap for a real
 * secret (or CF API token check) when multi-user.
 */
const ADMIN_PASS = '123';

function checkAdmin(
	u: URL,
	body?: { pass?: unknown },
): { ok: true } | { ok: false; response: Response } {
	const provided =
		(typeof body?.pass === 'string' ? body.pass : null) ??
		u.searchParams.get('pass');
	if (provided === ADMIN_PASS) return { ok: true };
	return {
		ok: false,
		response: json(
			{
				error:
					'admin pass required (POST body field `pass` or `?pass=` query; v0.3 personal toolbox)',
			},
			401,
		),
	};
}

interface ShortMeta {
	url: string;
	createdAt: number;
	clicks: number;
}

function generateCode(): string {
	const buf = new Uint8Array(RANDOM_CODE_LEN);
	crypto.getRandomValues(buf);
	let out = '';
	for (const b of buf) out += BASE62[b % BASE62.length];
	return out;
}

function isHttpUrl(s: string): boolean {
	try {
		const u = new URL(s);
		return u.protocol === 'http:' || u.protocol === 'https:';
	} catch {
		return false;
	}
}

function isValidCode(s: unknown): s is string {
	return typeof s === 'string' && VALID_CODE_RE.test(s);
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

function text(body: string, status = 200, extra: Record<string, string> = {}): Response {
	return new Response(body, {
		status,
		headers: { 'content-type': 'text/plain; charset=utf-8', ...extra },
	});
}

/**
 * Allocate a code for a new short link.
 *
 * - If `customCode` is given and valid, use it (409 if already taken).
 * - Otherwise generate random 8-char base62 (503 after 5 collision retries).
 */
async function allocateCode(
	env: Env,
	customCode?: string | null,
): Promise<{ ok: true; code: string } | { ok: false; response: Response }> {
	if (customCode) {
		if (!isValidCode(customCode)) {
			return {
				ok: false,
				response: json(
					{
						error: 'code must be 2-32 chars matching /^[A-Za-z0-9_-]{2,32}$/',
					},
					400,
				),
			};
		}
		if ((await env.SHORT_KV.get(customCode)) !== null) {
			return {
				ok: false,
				response: json(
					{ error: `code "${customCode}" is already taken` },
					409,
				),
			};
		}
		return { ok: true, code: customCode };
	}

	for (let attempt = 0; attempt < 5; attempt++) {
		const candidate = generateCode();
		if ((await env.SHORT_KV.get(candidate)) === null) {
			return { ok: true, code: candidate };
		}
	}
	return {
		ok: false,
		response: json({ error: 'could not generate unique code (retry)' }, 503),
	};
}

export const short: Service = {
	meta: {
		name: 'short',
		path: '/short',
		desc: {
			en: 'Short-link service (POST {url,code?} → JSON; GET /short?url=&code= → 302; GET /r/<code> → 302)',
			cn: '短链服务（POST {url,code?} → JSON；GET /short?url=&code= → 302；GET /r/<code> → 302 跳转）',
		},
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);

		// POST /short — programmatic create (returns JSON; custom code optional)
		if (req.method === 'POST' && u.pathname === '/short') {
			let body: { url?: unknown; code?: unknown; pass?: unknown };
			try {
				body = (await req.json()) as {
					url?: unknown;
					code?: unknown;
					pass?: unknown;
				};
			} catch {
				return json({ error: 'invalid JSON body' }, 400);
			}

			// Admin gate.
			const auth = checkAdmin(u, body);
			if (!auth.ok) return auth.response;

			const target = body.url;
			if (typeof target !== 'string' || !isHttpUrl(target)) {
				return json(
					{ error: 'url must be a string starting with http:// or https://' },
					400,
				);
			}

			const customCode = typeof body.code === 'string' ? body.code : null;
			const alloc = await allocateCode(env, customCode);
			if (!alloc.ok) return alloc.response;

			const meta: ShortMeta = {
				url: target,
				createdAt: Date.now(),
				clicks: 0,
			};
			await env.SHORT_KV.put(alloc.code, JSON.stringify(meta));

			return json(
				{
					code: alloc.code,
					url: target,
					short: `${u.protocol}//${u.host}/r/${alloc.code}`,
					createdAt: meta.createdAt,
				},
				201,
			);
		}

		// GET /short?url=X[&code=Y] — browser-friendly, optional custom code, returns 302
		if (req.method === 'GET' && u.pathname === '/short') {
			// Admin gate.
			const auth = checkAdmin(u);
			if (!auth.ok) return auth.response;

			const target = u.searchParams.get('url');
			if (!target) {
				return text(
					'GET /short?url=https://... [&pass=xxx&code=myslug]  → creates a short link and 302s to /r/<code>',
					400,
				);
			}
			if (!isHttpUrl(target)) {
				return text('url must start with http:// or https://', 400);
			}

			const customCode = u.searchParams.get('code');
			const alloc = await allocateCode(env, customCode);
			if (!alloc.ok) {
				// Surface the JSON error as plain text so a browser address bar shows it.
				const errBody = (await alloc.response.clone().json()) as { error: string };
				const extra =
					alloc.response.status === 409
						? {}
						: { 'x-cfbox-hint': 'omit &code= to get an auto-generated code' };
				return text(errBody.error, alloc.response.status, extra);
			}

			const meta: ShortMeta = {
				url: target,
				createdAt: Date.now(),
				clicks: 0,
			};
			await env.SHORT_KV.put(alloc.code, JSON.stringify(meta));

			return Response.redirect(`${u.protocol}//${u.host}/r/${alloc.code}`, 302);
		}

		// GET /r/<code> → 302 redirect + fire-and-forget click tick
		const m = u.pathname.match(/^\/r\/([A-Za-z0-9_-]{2,32})$/);
		if (req.method === 'GET' && m) {
			const code = m[1];
			const raw = await env.SHORT_KV.get(code);
			if (raw === null) {
				return text(`short link "${code}" not found`, 404);
			}
			let meta: ShortMeta;
			try {
				meta = JSON.parse(raw) as ShortMeta;
			} catch {
				return text('short link record corrupt', 500);
			}

			// Best-effort click increment — fire and forget via waitUntil so the
			// redirect doesn't block on a KV write.
			ctx.waitUntil(
				env.SHORT_KV.put(
					code,
					JSON.stringify({ ...meta, clicks: meta.clicks + 1 }),
				),
			);

			return Response.redirect(meta.url, 302);
		}

		// Anything else under this service → usage hint
		return text(
			'cfbox /short — POST {url, code?} ; or GET /short?url=...&code= ; then GET /r/<code> to redirect',
			405,
			{ allow: 'POST, GET' },
		);
	},
};

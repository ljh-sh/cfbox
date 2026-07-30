// src/services/paste.ts — pastebin (KV-backed).
//   POST /paste      { text, ttl? }  (token via x-cfbox-token)  → 201 { code, url, ttl, size }
//   GET  /paste/<code>                              → plain text body
// Reuses SHORT_KV namespace.

import type { Service } from '../types';
import { checkToken } from '../auth';

const MAX_TEXT = 100_000;
const BASE62 =
	'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			...extra,
		},
	});
}

function genCode(): string {
	const buf = new Uint8Array(8);
	crypto.getRandomValues(buf);
	let out = '';
	for (const b of buf) out += BASE62[b % BASE62.length];
	return out;
}

export const paste: Service = {
	meta: {
		name: 'paste',
		path: '/paste',
		desc: {
			en: 'Pastebin (POST {text,pass,ttl?}; GET /paste/<code>)',
			cn: '粘贴板（POST {text,pass,ttl?}；GET /paste/<code>）',
		},
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		// POST /paste — create
		if (req.method === 'POST' && u.pathname === '/paste') {
			// Token gate.
			const t = await checkToken(req, env);
			if (!t.ok) return t.response!;

			let body: {
				text?: unknown;
				ttl?: unknown;
			};
			try {
				body = (await req.json()) as typeof body;
			} catch {
				return json({ error: 'invalid JSON' }, 400);
			}
			if (typeof body?.text !== 'string') {
				return json({ error: '`text` required' }, 400);
			}
			if (body.text.length > MAX_TEXT) {
				return json(
					{ error: `text too long (max ${MAX_TEXT} chars)` },
					413,
				);
			}
			const code = genCode();
			const ttl =
				typeof body.ttl === 'number'
					? Math.min(Math.max(Math.floor(body.ttl), 60), 86400 * 30)
					: undefined;
			await env.SHORT_KV.put(
				code,
				body.text,
				ttl ? { expirationTtl: ttl } : undefined,
			);
			return json(
				{
					code,
					url: `${u.protocol}//${u.host}/paste/${code}`,
					ttl: ttl ?? null,
					size: body.text.length,
				},
				201,
			);
		}

		// GET /paste/<code> — read
		const m = u.pathname.match(/^\/paste\/([A-Za-z0-9]{6,16})$/);
		if (req.method === 'GET' && m) {
			const code = m[1];
			const text = await env.SHORT_KV.get(code);
			if (text === null) {
				return new Response(`paste "${code}" not found`, {
					status: 404,
					headers: { 'content-type': 'text/plain; charset=utf-8' },
				});
			}
			return new Response(text, {
				headers: {
					'content-type': 'text/plain; charset=utf-8',
					'cache-control': 'no-store',
				},
			});
		}

		return json(
			{ error: 'POST /paste {text, pass, ttl?}; GET /paste/<code>' },
			405,
		);
	},
};

// src/auth.ts — token gate for cfbox.
//
// Token is a single shared secret stored in `env.CFBOX_TOKEN` (set via
// `wrangler secret put CFBOX_TOKEN`).
//
// Backward compat: if CFBOX_TOKEN is unset, the worker runs in public mode
// (no token required). Set the secret to opt-in. This allows staged roll-out
// and keeps the dev experience low-friction.
//
// Token is supplied via either:
//   - `x-cfbox-token: <token>` header
//   - `Authorization: Bearer <token>` header
//
// Rate-limit buckets are keyed on a SHA-256 prefix of the token (never the
// raw token). Constant-time comparison prevents timing attacks.

export interface TokenInfo {
	/** True if request is allowed (either token matches, or public mode). */
	ok: boolean;
	/** Bucket key for rate-limit. `ip:<ip>` for public mode, `token:<hash>` for authed. */
	bucket: string;
	/** 401 response when ok=false. */
	response?: Response;
}

export interface AuthEnv {
	CFBOX_TOKEN?: string;
}

export async function checkToken(req: Request, env: AuthEnv): Promise<TokenInfo> {
	const expected = env.CFBOX_TOKEN;
	if (!expected) {
		// Public mode — no token configured. The route's `tokenRequired` flag
		// (in config.ts) decides whether the request is allowed at all.
		const ip = req.headers.get('cf-connecting-ip') || 'unknown';
		return { ok: true, bucket: `ip:${ip}` };
	}
	const provided = extractToken(req);
	if (!provided) {
		return {
			ok: false,
			bucket: 'unauthenticated',
			response: jsonError(
				{
					error: 'token required',
					hint: 'set x-cfbox-token header (or Authorization: Bearer <token>)',
				},
				401,
			),
		};
	}
	if (!safeEqual(provided, expected)) {
		return {
			ok: false,
			bucket: 'unauthenticated',
			response: jsonError({ error: 'invalid token' }, 401),
		};
	}
	const hash = await sha256Hex(provided);
	return { ok: true, bucket: `token:${hash.slice(0, 16)}` };
}

/**
 * Returns the token if it would be valid (used to decide per-token vs per-IP
 * rate limit even when the route doesn't require auth). Does NOT require the
 * env — only validates the token's shape and matching against env.CFBOX_TOKEN.
 */
export async function peekToken(req: Request, env: AuthEnv): Promise<TokenInfo> {
	return checkToken(req, env);
}

function extractToken(req: Request): string | null {
	const h = req.headers.get('x-cfbox-token');
	if (h) return h.trim();
	const auth = req.headers.get('authorization');
	if (auth) {
		const m = auth.match(/^Bearer\s+(.+)$/);
		if (m) return m[1]!.trim();
	}
	return null;
}

function safeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return diff === 0;
}

async function sha256Hex(s: string): Promise<string> {
	const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
	const bytes = new Uint8Array(buf);
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

function jsonError(body: unknown, status: number): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

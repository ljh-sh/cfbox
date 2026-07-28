// src/services/jwt.ts — decode JWT (header + payload) without signature verification.
// Debug-only; do NOT trust for auth decisions.

import type { Service } from '../types';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

function base64urlDecode(s: string): string {
	const pad = (4 - (s.length % 4)) % 4;
	return atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad));
}

export const jwt: Service = {
	meta: {
		name: 'jwt',
		path: '/jwt',
		desc: { en: 'Decode JWT (header + payload; not signature-verified)', cn: '解码 JWT（仅解析，不验签）' },
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const token =
			u.searchParams.get('token') ??
			(req.method === 'POST' ? await req.text() : '');
		if (!token) {
			return json(
				{ error: 'token query param or POST body required' },
				400,
			);
		}
		const parts = token.trim().split('.');
		if (parts.length !== 3) {
			return json(
				{ error: 'invalid JWT: must have 3 parts (header.payload.signature)' },
				400,
			);
		}
		try {
			const header = JSON.parse(base64urlDecode(parts[0]));
			const payload = JSON.parse(base64urlDecode(parts[1]));
			return json({
				header,
				payload,
				signaturePresent: parts[2].length > 0,
				signatureLength: parts[2].length,
				decodedAt: new Date().toISOString(),
				note: 'signature NOT verified — debug only',
			});
		} catch {
			return json(
				{ error: 'failed to decode (malformed base64url or JSON)' },
				400,
			);
		}
	},
};

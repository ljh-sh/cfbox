// src/services/hash.ts — text → hex hash using crypto.subtle.
// Supported: SHA-1, SHA-256, SHA-384, SHA-512.
// (MD5 not in subtle; skip.)

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

const SUPPORTED = new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);

export const hash: Service = {
	meta: {
		name: 'hash',
		path: '/hash',
		desc: { en: 'Hash text using SHA-1/256/384/512', cn: 'SHA 系列文本哈希' },
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const text =
			u.searchParams.get('text') ??
			(req.method === 'POST' ? await req.text() : '');
		if (!text) {
			return json(
				{ error: 'text query param or POST body required' },
				400,
			);
		}
		const algo = (u.searchParams.get('algo') ?? 'sha-256').toUpperCase();
		if (!SUPPORTED.has(algo)) {
			return json(
				{
					error: `algo must be one of sha-1, sha-256, sha-384, sha-512 (MD5 not supported in subtle)`,
				},
				400,
			);
		}
		const data = new TextEncoder().encode(text);
		const buf = await crypto.subtle.digest(algo, data);
		const hex = Array.from(new Uint8Array(buf))
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');
		return json({
			algo,
			inputLength: text.length,
			hex,
			lengthBytes: buf.byteLength,
		});
	},
};

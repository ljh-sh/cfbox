// src/services/headers.ts — dump all received headers (debug + educational).

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

export const headers: Service = {
	meta: {
		name: 'headers',
		path: '/headers',
		desc: { en: 'Dump all received HTTP headers', cn: '回显所有 HTTP headers' },
	},
	fetch: async (req) => {
		const hdrs: Record<string, string> = {};
		req.headers.forEach((v, k) => {
			hdrs[k] = v;
		});
		return json({
			headers: hdrs,
			count: Object.keys(hdrs).length,
		});
	},
};

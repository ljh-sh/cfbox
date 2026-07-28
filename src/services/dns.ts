// src/services/dns.ts — DNS-over-HTTPS query to 1.1.1.1.
//   GET /dns?host=example.com[&type=A|AAAA|MX|TXT|CNAME|NS]
// Returns JSON with Answer records.

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

const ALLOWED_TYPES = new Set([
	'A',
	'AAAA',
	'MX',
	'TXT',
	'CNAME',
	'NS',
	'SRV',
	'CAA',
	'PTR',
]);

export const dns: Service = {
	meta: {
		name: 'dns',
		path: '/dns',
		desc: { en: 'DNS-over-HTTPS lookup via 1.1.1.1', cn: '通过 1.1.1.1 的 DoH 查询' },
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const host = u.searchParams.get('host');
		const typeRaw = (u.searchParams.get('type') ?? 'A').toUpperCase();
		if (!host) return json({ error: 'host query param required' }, 400);
		if (!ALLOWED_TYPES.has(typeRaw)) {
			return json(
				{ error: `type must be one of: ${[...ALLOWED_TYPES].join(', ')}` },
				400,
			);
		}

		const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${typeRaw}`;
		const t0 = Date.now();
		const res = await fetch(dohUrl, {
			headers: { accept: 'application/dns-json' },
		});
		if (!res.ok) {
			return json({ error: `DoH upstream returned ${res.status}` }, 502);
		}
		const data = (await res.json()) as {
			Status: number;
			Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
		};

		const answers = (data.Answer ?? []).map((a) => ({
			name: a.name,
			type: a.type,
			TTL: a.TTL,
			data: a.data,
		}));

		return json({
			query: { host, type: typeRaw },
			status: data.Status,
			answers,
			answerCount: answers.length,
			tookMs: Date.now() - t0,
		});
	},
};

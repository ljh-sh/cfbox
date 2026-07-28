// src/services/httpinfo.ts — full request visibility: IP + geo + headers + UA + TLS.

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

function parseUA(ua: string): {
	browser: string | null;
	os: string | null;
	device: string | null;
	bot: boolean;
} {
	const r = { browser: null, os: null, device: null, bot: false };
	if (/bot|crawl|spider|slurp|mediapartners/i.test(ua)) r.bot = true;
	if (/Edg\//.test(ua)) r.browser = 'Edge';
	else if (/OPR\//.test(ua)) r.browser = 'Opera';
	else if (/Chrome\//.test(ua)) r.browser = 'Chrome';
	else if (/Firefox\//.test(ua)) r.browser = 'Firefox';
	else if (/Safari\//.test(ua) && /Version\//.test(ua)) r.browser = 'Safari';
	if (/Windows NT/.test(ua)) r.os = 'Windows';
	else if (/Mac OS X|macOS/.test(ua)) r.os = 'macOS';
	else if (/Android/.test(ua)) r.os = 'Android';
	else if (/iPhone|iPad|iPod/.test(ua)) r.os = 'iOS';
	else if (/Linux/.test(ua)) r.os = 'Linux';
	if (/Mobile|iPhone|Android.*Mobile/.test(ua)) r.device = 'mobile';
	else if (/iPad|Tablet/.test(ua)) r.device = 'tablet';
	else r.device = 'desktop';
	return r;
}

export const httpinfo: Service = {
	meta: {
		name: 'httpinfo',
		path: '/httpinfo',
		desc: {
			en: 'Full request info: IP, geo, headers, UA, TLS',
			cn: '请求全貌：IP、地理位置、headers、UA、TLS',
		},
	},
	fetch: async (req) => {
		const cf = (req as unknown as { cf?: Record<string, unknown> }).cf ?? {};
		const headers: Record<string, string> = {};
		req.headers.forEach((v, k) => {
			headers[k] = v;
		});
		const uaStr = req.headers.get('user-agent') ?? '';
		return json({
			ip:
				cf.clientIp as string | undefined ??
				req.headers.get('cf-connecting-ip') ??
				null,
			network: {
				country: cf.country ?? null,
				region: cf.region ?? null,
				regionCode: cf.regionCode ?? null,
				city: cf.city ?? null,
				continent: cf.continent ?? null,
				latitude: cf.latitude ?? null,
				longitude: cf.longitude ?? null,
				timezone: cf.timezone ?? null,
				postalCode: cf.postalCode ?? null,
				asn: cf.asn ?? null,
				asOrganization: cf.asOrganization ?? null,
				colo: cf.colo ?? null,
			},
			tls: {
				version: cf.tlsVersion ?? null,
				cipher: cf.tlsCipher ?? null,
				httpProtocol: cf.httpProtocol ?? null,
				requestPriority: cf.requestPriority ?? null,
			},
			request: {
				method: req.method,
				url: req.url,
				headers,
				headersCount: Object.keys(headers).length,
			},
			ua: { raw: uaStr, ...parseUA(uaStr) },
			timestamp: new Date().toISOString(),
		});
	},
};

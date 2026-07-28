// src/services/myip.ts — v0.1 service: echo the client's IP.
//
// Returns JSON: { "ip": "203.0.113.42" }
//
// Source of truth for the IP is CF's `req.cf.clientIp`; we fall back to
// `cf-connecting-ip` header for safety. Output is `no-store` because every
// request is unique to the client.
//
// Implementation cost: < 0.1ms CPU, 0 subrequests.

import type { Service } from '../types';

export const myip: Service = {
	meta: {
		name: 'myip',
		path: '/myip',
		desc: {
			en: 'Return the client IP as JSON',
			cn: '以 JSON 形式返回客户端 IP',
		},
	},
	fetch: async (req) => {
		const ip =
			req.cf?.clientIp ??
			req.headers.get('cf-connecting-ip') ??
			'unknown';

		// CF populates `req.cf` at the edge — geo / network info for the connecting
		// client. NOT a header. Available only in Workers runtime on CF edge;
		// `wrangler dev` locally leaves it undefined (so `location` is null).
		//
		// Fields: clientIp, country, region, regionCode, city, continent,
		// latitude, longitude, postalCode, timezone, asn, asOrganization, colo, ...
		const cf = req.cf;
		const location = cf
			? {
					country: cf.country ?? null,
					region: cf.region ?? null,
					regionCode: cf.regionCode ?? null,
					city: cf.city ?? null,
					continent: cf.continent ?? null,
					latitude: cf.latitude ?? null,
					longitude: cf.longitude ?? null,
					postalCode: cf.postalCode ?? null,
					timezone: cf.timezone ?? null,
					asn: cf.asn ?? null,
					asOrganization: cf.asOrganization ?? null,
					colo: cf.colo ?? null,
				}
			: null;

		return new Response(JSON.stringify({ ip, location }, null, 2), {
			headers: {
				'content-type': 'application/json; charset=utf-8',
				'cache-control': 'no-store',
			},
		});
	},
};

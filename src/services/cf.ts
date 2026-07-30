// src/services/cf.ts — Cloudflare edge debug toolkit.
// Sub-paths (all under /cf/*):
//   /cf or /cf/inspect  → full dump (everything at once)
//   /cf/pop             → which CF POP served this + where it is
//   /cf/tls             → TLS handshake info (version, cipher, ALPN)
//   /cf/clock           → edge wallclock (use to detect clock skew)
//   /cf/debug           → all CF-* headers (cf-ray, cf-cache-status, cf-pop, …)
//   /cf/fetch?url=…     → fetch from edge IP (token via x-cfbox-token, SSRF guard)

import type { Service } from '../types';
import { checkToken } from '../auth';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

function text(body: string, status = 200): Response {
	return new Response(body, {
		status,
		headers: { 'content-type': 'text/plain; charset=utf-8' },
	});
}

function isHttpUrl(s: string): boolean {
	try {
		const u = new URL(s);
		return u.protocol === 'http:' || u.protocol === 'https:';
	} catch {
		return false;
	}
}

function isInternalHost(url: string): boolean {
	try {
		const h = new URL(url).hostname.toLowerCase();
		if (
			h === 'localhost' ||
			h === '0.0.0.0' ||
			h === '::' ||
			h.endsWith('.local') ||
			h.endsWith('.internal')
		) {
			return true;
		}
		if (
			/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)/.test(
				h,
			)
		) {
			return true;
		}
		return false;
	} catch {
		return true;
	}
}

function cfProps(req: Request): Record<string, unknown> {
	return ((req as unknown as { cf?: Record<string, unknown> }).cf ??
		{}) as Record<string, unknown>;
}

function fullDump(req: Request): Record<string, unknown> {
	const cf = cfProps(req);
	const headers: Record<string, string> = {};
	req.headers.forEach((v, k) => {
		headers[k] = v;
	});
	return {
		ip: cf.clientIp ?? req.headers.get('cf-connecting-ip') ?? null,
		pop: {
			colo: cf.colo ?? null,
			country: cf.country ?? null,
			region: cf.region ?? null,
			city: cf.city ?? null,
			continent: cf.continent ?? null,
			latitude: cf.latitude ?? null,
			longitude: cf.longitude ?? null,
			timezone: cf.timezone ?? null,
			postalCode: cf.postalCode ?? null,
			asn: cf.asn ?? null,
			asOrganization: cf.asOrganization ?? null,
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
			headersCount: req.headers.size,
		},
		headers,
		timestamp: new Date().toISOString(),
	};
}

export const cf: Service = {
	meta: {
		name: 'cf',
		path: '/cf',
		desc: {
			en: 'Cloudflare edge debug toolkit (/cf/pop | /cf/tls | /cf/clock | /cf/debug | /cf/fetch)',
			cn: 'Cloudflare edge 调试工具集（/cf/pop | /cf/tls | /cf/clock | /cf/debug | /cf/fetch）',
		},
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const path = u.pathname;

		// /cf or /cf/inspect — full dump
		if (path === '/cf' || path === '/cf/' || path === '/cf/inspect') {
			return json(fullDump(req));
		}

		// /cf/pop — which CF POP served this
		if (path === '/cf/pop') {
			const c = cfProps(req);
			return json({
				colo: c.colo ?? null,
				country: c.country ?? null,
				region: c.region ?? null,
				city: c.city ?? null,
				continent: c.continent ?? null,
				latitude: c.latitude ?? null,
				longitude: c.longitude ?? null,
				timezone: c.timezone ?? null,
			});
		}

		// /cf/tls — TLS handshake info
		if (path === '/cf/tls') {
			const c = cfProps(req);
			return json({
				version: c.tlsVersion ?? null,
				cipher: c.tlsCipher ?? null,
				httpProtocol: c.httpProtocol ?? null,
				requestPriority: c.requestPriority ?? null,
			});
		}

		// /cf/clock — edge wallclock
		if (path === '/cf/clock') {
			const now = new Date();
			return json({
				node: 'edge',
				iso: now.toISOString(),
				epochMs: now.getTime(),
				epochSec: Math.floor(now.getTime() / 1000),
				utcOffsetMin: -now.getTimezoneOffset(),
				note: 'CF edge wallclock; not user device clock',
			});
		}

		// /cf/debug — all CF-* headers
		if (path === '/cf/debug') {
			const cfHeaders: Record<string, string> = {};
			for (const [k, v] of req.headers) {
				if (k.toLowerCase().startsWith('cf-')) cfHeaders[k] = v;
			}
			return json({
				cfHeaders,
				cfHeaderCount: Object.keys(cfHeaders).length,
				allHeaderCount: req.headers.size,
			});
		}

		// /cf/fetch?url=... — fetch from edge IP (token via x-cfbox-token, SSRF guard)
		if (path === '/cf/fetch') {
			// Token gate.
			const t = await checkToken(req, env);
			if (!t.ok) return t.response!;

			const target = u.searchParams.get('url');
			if (!target) return json({ error: 'url query param required' }, 400);
			if (!isHttpUrl(target)) return json({ error: 'must be http(s)' }, 400);
			if (isInternalHost(target)) {
				return json({ error: 'internal host blocked (SSRF guard)' }, 403);
			}

			try {
				const t0 = Date.now();
				const res = await fetch(target, {
					headers: { 'user-agent': 'cfbox-cf-fetch/0.5' },
					redirect: 'follow',
				});
				const respHeaders: Record<string, string> = {};
				res.headers.forEach((v, k) => {
					respHeaders[k] = v;
				});
				const text_body = await res.text();
				const truncated = text_body.length > 4096;
				const bodySample = truncated
					? text_body.slice(0, 4096) + '\n...[truncated at 4KB]'
					: text_body;

				return json({
					target,
					finalUrl: res.url,
					status: res.status,
					statusText: res.statusText,
					headers: respHeaders,
					bodyLength: text_body.length,
					bodyTruncated: truncated,
					body: bodySample,
					tookMs: Date.now() - t0,
					edgeIp: cfProps(req).clientIp ?? null,
					note: 'fetched from CF edge IP, not client IP',
				});
			} catch (e) {
				return json(
					{ error: `fetch failed: ${(e as Error).message}` },
					502,
				);
			}
		}

		// Fallback / unknown sub-path
		return text(
			'cfbox /cf — sub-paths: /cf/inspect | /cf/pop | /cf/tls | /cf/clock | /cf/debug | /cf/fetch?url=... (token required)',
			405,
		);
	},
};

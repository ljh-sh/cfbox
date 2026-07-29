// src/services/unshorten.ts — follow redirect chain to reveal final URL.
// SSRF guard: reject localhost / RFC1918 / link-local targets (now shared via
// ../safety).

import type { Service } from '../types';
import { preflight, checkUrl } from '../safety';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

const MAX_HOPS = 10;
const UA = 'cfbox/0.5 (+https://cfbox.ljh.sh)';
const SELF_HOST = 'cfbox.ljh.sh';

export const unshorten: Service = {
	meta: {
		name: 'unshorten',
		path: '/unshorten',
		desc: { en: 'Follow redirect chain, reveal final URL', cn: '跟随重定向链，揭示最终 URL' },
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const target = u.searchParams.get('url');
		if (!target) return json({ error: 'url query param required' }, 400);

		// Rate limit + SSRF guard on the initial target. Block the request's
		// own host to prevent loopback amplification (e.g. unshorten through
		// /httpget on the same zone).
		const selfHost = new URL(req.url).hostname.toLowerCase();
		const pre = await preflight(req, {
			route: 'unshorten',
			limit: 30,
			windowSec: 60,
			targetUrl: target,
			extraDenyHosts: [selfHost],
		});
		if (pre) return pre;

		const chain: Array<{
			url: string;
			status: number;
			location: string | null;
			error?: string;
		}> = [];
		let current = target;
		let depth = 0;
		const seen = new Set<string>([target]);

		while (depth < MAX_HOPS) {
			let res: Response;
			try {
				res = await fetch(current, {
					redirect: 'manual',
					headers: { 'user-agent': UA },
				});
			} catch (e) {
				chain.push({
					url: current,
					status: 0,
					location: null,
					error: `fetch failed: ${(e as Error).message}`,
				});
				break;
			}
			const loc = res.headers.get('location');
			chain.push({ url: current, status: res.status, location: loc });
			if (res.status < 300 || res.status >= 400 || !loc) break;
			let next: string;
			try {
				next = new URL(loc, current).toString();
			} catch {
				chain.push({ url: current, status: res.status, location: loc, error: 'invalid location' });
				break;
			}
			if (next === current || seen.has(next)) {
				chain.push({ url: next, status: 0, location: null, error: 'loop detected' });
				break;
			}
			// SSRF guard on each hop (DNS rebinding / cross-origin redirector).
			// Block self-host (cfbox.ljh.sh) to prevent loopback amplification.
			const hop = checkUrl(next, { extraDenyHosts: [SELF_HOST] });
			if (!hop.ok) {
				chain.push({ url: next, status: 0, location: null, error: `blocked: ${hop.reason}` });
				break;
			}
			seen.add(next);
			current = next;
			depth++;
		}

		return json({
			original: target,
			final: current,
			hitsFinal: chain[chain.length - 1]?.status && chain[chain.length - 1]!.status >= 200 && chain[chain.length - 1]!.status < 400,
			hops: chain.length,
			chain,
		});
	},
};

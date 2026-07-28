// src/services/unshorten.ts — follow redirect chain to reveal final URL.
// SSRF guard: reject localhost / RFC1918 / link-local targets.

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
		const u = new URL(url);
		const host = u.hostname.toLowerCase();
		if (host === 'localhost' || host === '0.0.0.0' || host === '::') return true;
		if (host.endsWith('.local') || host.endsWith('.internal')) return true;
		// RFC1918 + link-local + loopback
		if (
			/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)/.test(
				host,
			)
		) {
			return true;
		}
		return false;
	} catch {
		return true;
	}
}

const MAX_HOPS = 10;
const UA = 'cfbox/0.5 (+https://cfbox.ljh.sh)';

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
		if (!isHttpUrl(target)) return json({ error: 'must be http(s)' }, 400);
		if (isInternalHost(target)) {
			return json({ error: 'internal host blocked (SSRF guard)' }, 403);
		}

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

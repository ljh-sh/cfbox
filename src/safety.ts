// src/safety.ts — shared SSRF guard + rate limiter for cfbox services.
//
// Two responsibilities:
//   1. URL safety: reject private/loopback/link-local targets before fetch().
//      DNS-rebinding is a known residual risk (see cfbox-design/abuse-risk.md §3).
//   2. Per-IP per-route rate limiting using Cache API edge state.
//
// Why Cache API:
//   - Worker-isolated, no extra bindings needed.
//   - Cheap read (in-memory in most PoPs).
//   - Soft enforcement (CF can evict); fine for personal-toolbox tier.
//   - For a paid tier, swap to KV with hard EX TTL.

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV4_MAPPED_RE = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;

// CIDR list we want to deny. Conservative: covers RFC1918, loopback, link-local,
// CGN, multicast, broadcast, IETF reserved, plus 100.0.0.0/10 (CGN).
const DENY_V4: Array<[string, number]> = [
	['0.0.0.0', 8], // current network
	['10.0.0.0', 8], // RFC1918
	['100.64.0.0', 10], // CGN
	['127.0.0.0', 8], // loopback
	['169.254.0.0', 16], // link-local
	['172.16.0.0', 12], // RFC1918
	['192.0.0.0', 24], // IETF protocol
	['192.0.2.0', 24], // TEST-NET-1
	['192.88.99.0', 24], // 6to4 anycast (deprecated)
	['192.168.0.0', 16], // RFC1918
	['198.18.0.0', 15], // benchmarking
	['198.51.100.0', 24], // TEST-NET-2
	['203.0.113.0', 24], // TEST-NET-3
	['224.0.0.0', 4], // multicast
	['240.0.0.0', 4], // reserved
	['255.255.255.255', 32], // broadcast
];

function ipv4ToInt(ip: string): number {
	const m = IPV4_RE.exec(ip);
	if (!m) return -1;
	let n = 0;
	for (let i = 1; i <= 4; i++) {
		const oct = parseInt(m[i]!, 10);
		if (oct < 0 || oct > 255) return -1;
		n = (n * 256 + oct) >>> 0;
	}
	return n;
}

function ipv4InList(ip: string): boolean {
	const n = ipv4ToInt(ip);
	if (n < 0) return false;
	for (const [net, bits] of DENY_V4) {
		const netN = ipv4ToInt(net);
		if (bits === 0) {
			if (n === netN) return true;
		} else {
			const mask = bits === 32 ? -1 : ((~0 << (32 - bits)) >>> 0);
			if ((n & mask) === (netN & mask)) return true;
		}
	}
	return false;
}

function isPrivateIPv4(ip: string): boolean {
	return ipv4InList(ip);
}

// IPv6 — covers the common attack surfaces. Full IPv6 CIDR matching is
// impractical in a Worker without ipaddr.js; the residual is documented.
function isPrivateIPv6(ip: string): boolean {
	const lc = ip.toLowerCase().split('%')[0]!.split('/')[0]!;
	if (lc === '::' || lc === '::1') return true;
	const mapped = IPV4_MAPPED_RE.exec(lc);
	if (mapped) return isPrivateIPv4(mapped[1]!);
	if (lc.startsWith('fc') || lc.startsWith('fd')) return true; // fc00::/7 ULA
	if (/^fe[89ab][0-9a-f]:/i.test(lc)) return true; // fe80::/10 link-local
	if (lc.startsWith('ff')) return true; // ff00::/8 multicast
	if (lc.startsWith('2001:db8')) return true; // 2001:db8::/32 docs
	// 100::/64 discard prefix
	if (lc.startsWith('100:0:0:0:0:0:0:0') || lc === '100::') return true;
	return false;
}

export interface CheckUrlResult {
	ok: boolean;
	reason?: string;
}

export interface CheckUrlOpts {
	/** Hosts (hostnames, lowercased) the caller wants to deny in addition to
	 *  the private-IP/loopback list. Used to prevent loopback amplification
	 *  (e.g. attacker uses /httpget to fetch cfbox.ljh.sh/* which then hits
	 *  another /httpget, costing us N outbound fetches per attacker req). */
	extraDenyHosts?: string[];
}

export function checkUrl(raw: string, opts: CheckUrlOpts = {}): CheckUrlResult {
	let u: URL;
	try {
		u = new URL(raw);
	} catch {
		return { ok: false, reason: 'invalid url' };
	}
	if (u.protocol !== 'http:' && u.protocol !== 'https:') {
		return { ok: false, reason: 'scheme must be http(s)' };
	}
	const host = u.hostname.toLowerCase();
	if (host === '') return { ok: false, reason: 'empty host' };
	if (host === 'localhost' || host === 'ip6-localhost' || host === 'ip6-loopback') {
		return { ok: false, reason: 'localhost blocked' };
	}
	if (host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
		return { ok: false, reason: 'mDNS/internal TLD blocked' };
	}
	if (host.endsWith('.onion') || host.endsWith('.onion.io')) {
		return { ok: false, reason: 'tor hidden service blocked' };
	}
	if (opts.extraDenyHosts) {
		for (const deny of opts.extraDenyHosts) {
			if (host === deny || host.endsWith('.' + deny)) {
				return { ok: false, reason: `host blocked: ${host}` };
			}
		}
	}
	if (IPV4_RE.test(host)) {
		if (isPrivateIPv4(host)) return { ok: false, reason: `private IPv4 ${host}` };
		return { ok: true };
	}
	if (host.startsWith('[') && host.endsWith(']')) {
		const ip = host.slice(1, -1);
		if (isPrivateIPv6(ip)) return { ok: false, reason: `private IPv6 ${ip}` };
		return { ok: true };
	}
	if (host.includes(':')) {
		if (isPrivateIPv6(host)) return { ok: false, reason: `private IPv6 ${host}` };
		return { ok: true };
	}
	return { ok: true };
}

function errJson(body: unknown, status: number): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

export function guardUrl(raw: string, opts: CheckUrlOpts = {}): Response | null {
	const r = checkUrl(raw, opts);
	if (!r.ok) return errJson({ error: 'blocked', reason: r.reason }, 403);
	return null;
}

// ----- Rate limiter ------------------------------------------------------

export interface RateLimitOpts {
	route: string;
	limit: number;
	windowSec: number;
}

export async function rateLimit(req: Request, opts: RateLimitOpts): Promise<Response | null> {
	const ip = req.headers.get('cf-connecting-ip') || 'unknown';
	const bucket = Math.floor(Date.now() / 1000 / opts.windowSec);
	const key = `https://ratelimit.internal/${opts.route}/${ip}/${bucket}`;
	const cache = caches.default;
	let count = 0;
	try {
		const cached = await cache.match(key);
		if (cached) {
			const text = await cached.text();
			count = parseInt(text, 10) || 0;
		}
	} catch {
		/* cache miss or evicted — treat as 0 */
	}
	if (count >= opts.limit) {
		return new Response(
			JSON.stringify({
				error: 'rate limit exceeded',
				route: opts.route,
				limit: opts.limit,
				windowSec: opts.windowSec,
			}),
			{
				status: 429,
				headers: {
					'content-type': 'application/json; charset=utf-8',
					'cache-control': 'no-store',
					'retry-after': String(opts.windowSec),
				},
			},
		);
	}
	try {
		await cache.put(
			new Request(key),
			new Response(String(count + 1), {
				headers: { 'cache-control': `max-age=${opts.windowSec * 2}` },
			}),
		);
	} catch {
		/* cache write may fail — we don't fail the request */
	}
	return null;
}

// ----- Body size cap -----------------------------------------------------

/**
 * Read a request body with a hard byte cap. Returns the bytes, or a 413
 * Response if the body exceeds `maxBytes`. Pre-checks Content-Length to
 * short-circuit huge uploads without buffering.
 */
export async function readBoundedBody(req: Request, maxBytes: number): Promise<Uint8Array | Response> {
	const cl = req.headers.get('content-length');
	if (cl) {
		const n = parseInt(cl, 10);
		if (!isNaN(n) && n > maxBytes) {
			return errJson({ error: 'body too large', maxBytes, got: n }, 413);
		}
	}
	const ab = await req.arrayBuffer();
	if (ab.byteLength > maxBytes) {
		return errJson({ error: 'body too large', maxBytes, got: ab.byteLength }, 413);
	}
	return new Uint8Array(ab);
}

// ----- Pre-flight (rate limit + URL guard, no body) ----------------------

export interface PreflightOpts {
	route: string;
	limit: number;
	windowSec: number;
	targetUrl?: string;
	extraDenyHosts?: string[];
}

/**
 * Combined rate-limit + URL guard. Returns null to proceed, or a Response
 * to short-circuit (429 rate, 403 URL).
 */
export async function preflight(req: Request, opts: PreflightOpts): Promise<Response | null> {
	const rl = await rateLimit(req, { route: opts.route, limit: opts.limit, windowSec: opts.windowSec });
	if (rl) return rl;
	if (opts.targetUrl) {
		const g = guardUrl(opts.targetUrl, { extraDenyHosts: opts.extraDenyHosts });
		if (g) return g;
	}
	return null;
}

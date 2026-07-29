// src/safety.ts — shared SSRF guard + rate limiter for cfbox services.
//
// Two responsibilities:
//   1. URL safety: reject private/loopback/link-local targets before fetch().
//      DNS-rebinding is a known residual risk (see cfbox-design/abuse-risk.md §3).
//   2. Per-bucket per-route rate limiting using Cache API edge state.
//
// Why Cache API:
//   - Worker-isolated, no extra bindings needed.
//   - Cheap read (in-memory in most PoPs).
//   - Soft enforcement (CF can evict); fine for personal-toolbox tier.
//   - For a paid tier, swap to KV with hard EX TTL.

import { checkToken, type AuthEnv } from './auth';
import { getRouteConfig } from './config';

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
	/**
	 * Bucket key (per-IP if not set). Caller passes either
	 * `ip:<ip>` (public mode) or `token:<hash>` (token-gated mode).
	 */
	key?: string;
}

export async function rateLimit(req: Request, opts: RateLimitOpts): Promise<Response | null> {
	const ip = req.headers.get('cf-connecting-ip') || 'unknown';
	const keyName = opts.key ?? `ip:${ip}`;
	const bucket = Math.floor(Date.now() / 1000 / opts.windowSec);
	const key = `https://ratelimit.internal/${opts.route}/${keyName}/${bucket}`;
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
	/**
	 * When true, the request must carry a valid token (or CFBOX_TOKEN must be
	 * unset → public mode). The rate-limit bucket is keyed on the token
	 * hash (or per-IP in public mode).
	 */
	requireToken?: boolean;
}

export interface PreflightOpts {
	/** Route name from config.ts (or any custom key for ad-hoc). */
	route: string;
	/** Override the route's configured rate limit. Optional. */
	limit?: number;
	/** Override the route's configured window. Optional. */
	windowSec?: number;
	targetUrl?: string;
	extraDenyHosts?: string[];
	/**
	 * Override the route's `tokenRequired` flag. If undefined, reads from
	 * config.ts. Default false (public, with per-IP rate limit).
	 */
	tokenRequired?: boolean;
}

/**
 * Lockdown check — returns 503 if lockdown is active and caller is anonymous.
 * Token-holders bypass lockdown.
 *
 * Lockdown flag is stored in KV (`cfbox:lockdown`). Auto-expires (TTL set
 * when written) so a forgotten admin won't accidentally block public access
 * forever.
 */
export async function checkLockdown(req: Request, env: AuthEnv): Promise<Response | null> {
	// Token-holders bypass lockdown.
	if (env.CFBOX_TOKEN) {
		const t = await checkToken(req, env);
		if (t.ok) return null;
	}
	// Anonymous: check the flag.
	const v = await env.SHORT_KV.get('cfbox:lockdown');
	if (v === null) return null;
	// Lockdown active. Return 503 with hint.
	const until = v; // free-form text, e.g. ISO timestamp or "until-cleared"
	return new Response(
		JSON.stringify({
			error: 'public access paused',
			reason: 'cfbox is in lockdown mode (anonymous access blocked)',
			until,
			hint: 'supply x-cfbox-token header to bypass',
		}),
		{
			status: 503,
			headers: {
				'content-type': 'application/json; charset=utf-8',
				'cache-control': 'no-store',
				'retry-after': '3600',
			},
		},
	);
}

/**
 * Set the lockdown flag. Body: { ttlSec: number, until: string? }.
 * Token required.
 */
export async function setLockdown(env: AuthEnv, body: { ttlSec?: number; until?: string }): Promise<void> {
	const ttl = Math.min(Math.max(body.ttlSec ?? 3600, 60), 86400 * 7);
	const until = body.until ?? new Date(Date.now() + ttl * 1000).toISOString();
	await env.SHORT_KV.put('cfbox:lockdown', until, { expirationTtl: ttl });
}

/** Clear the lockdown flag. Token required. */
export async function clearLockdown(env: AuthEnv): Promise<void> {
	await env.SHORT_KV.delete('cfbox:lockdown');
}

/** Read the current lockdown status. */
export async function getLockdownStatus(env: AuthEnv): Promise<{ active: boolean; until?: string }> {
	const v = await env.SHORT_KV.get('cfbox:lockdown');
	if (v === null) return { active: false };
	return { active: true, until: v };
}

/**
 * Pre-flight: token + lockdown + rate-limit + URL guard. Returns null to
 * proceed, or a Response to short-circuit.
 *
 * Order:
 *   1. Lockdown (anonymous only)      → 503 if active
 *   2. Token / tokenRequired check    → 401 if needed
 *   3. Rate limit (per-token or per-IP) → 429 if exceeded
 *   4. URL guard                      → 403 if blocked
 */
export async function preflight(
	req: Request,
	env: AuthEnv,
	opts: PreflightOpts,
): Promise<Response | null> {
	const cfg = getRouteConfig(opts.route);
	const tokenRequired = opts.tokenRequired ?? cfg.tokenRequired;

	// 1. Lockdown (anonymous only — token-holders bypass).
	const lock = await checkLockdown(req, env);
	if (lock) return lock;

	// 2. Token check.
	let tokenOk = false;
	let tokenBucket: string | null = null;
	if (env.CFBOX_TOKEN) {
		const t = await checkToken(req, env);
		if (t.ok) {
			tokenOk = true;
			tokenBucket = t.bucket;
		} else if (tokenRequired) {
			return t.response!;
		}
	} else if (tokenRequired) {
		return new Response(
			JSON.stringify({
				error: 'route requires token, but CFBOX_TOKEN is unset',
				hint: 'set CFBOX_TOKEN via `wrangler secret put CFBOX_TOKEN`, or flip tokenRequired to false in config.ts',
			}),
			{
				status: 503,
				headers: { 'content-type': 'application/json; charset=utf-8' },
			},
		);
	}

	// 3. Rate limit.
	let limit: number;
	let windowSec: number;
	let bucketKey: string;
	if (tokenOk && tokenBucket) {
		limit = opts.limit ?? cfg.ratePerToken;
		windowSec = opts.windowSec ?? cfg.windowSec;
		bucketKey = tokenBucket;
	} else {
		const ip = req.headers.get('cf-connecting-ip') || 'unknown';
		limit = opts.limit ?? cfg.ratePerIP;
		windowSec = opts.windowSec ?? cfg.windowSec;
		bucketKey = `ip:${ip}`;
	}
	if (limit > 0) {
		const rl = await rateLimit(req, {
			route: opts.route,
			limit,
			windowSec,
			key: bucketKey,
		});
		if (rl) return rl;
	}

	// 4. URL guard.
	if (opts.targetUrl) {
		const g = guardUrl(opts.targetUrl, { extraDenyHosts: opts.extraDenyHosts });
		if (g) return g;
	}
	return null;
}

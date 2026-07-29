// src/config.ts — per-route configuration. Edit this file to tune cfbox
// without touching service handlers.
//
// **Design principle: safe by default, public by opt-in.**
//
// Routes in the `config` table below default to `tokenRequired: true`. To
// allow anonymous access to a specific route, change its `tokenRequired`
// to `false` and re-deploy. Routes not in the table (low-risk reads like
// `/myip`, `/hash`, `/cron`) are always public via `defaultConfig`.
//
// Rate-limit semantics:
//   - `ratePerIP` (anonymous) → 5/30s = 10 req/min/IP per high-risk route
//   - `ratePerToken` (token supplied) → 200 req/min/token
//   - Set `ratePerIP: 0` to disable anonymous access entirely (then
//     `tokenRequired: true` is implied).
//   - Set `ratePerIP: -1` to disable rate limit. (Avoid; defense-in-depth.)

export interface RouteConfig {
	/** Anonymous rate limit. 0 = block, -1 = disabled, positive = count. */
	ratePerIP: number;
	/** Token-authenticated rate limit. */
	ratePerToken: number;
	/** Sliding window length in seconds. */
	windowSec: number;
	/** Inbound body cap (POST/PUT). null = no body allowed; 0 = no cap. */
	bodyCap: number | null;
	/** Default true: require token. Flip to false to allow anonymous use. */
	tokenRequired: boolean;
}

export const config: Record<string, RouteConfig> = {
	// ── High-cost reads (default safe; 5/30s for public opt-in) ──
	httpget: {
		ratePerIP: 5,
		ratePerToken: 200,
		windowSec: 30, // 5 req per 30s window
		bodyCap: 10 * 1024 * 1024, // 10 MiB
		tokenRequired: true,
	},
	md: {
		ratePerIP: 5,
		ratePerToken: 200,
		windowSec: 30,
		bodyCap: 5 * 1024 * 1024, // 5 MiB
		tokenRequired: true,
	},
	unshorten: {
		ratePerIP: 10,
		ratePerToken: 200,
		windowSec: 30,
		bodyCap: null,
		tokenRequired: true,
	},

	// ── Medium-cost reads (default safe; 60/min for public opt-in) ──
	doh: {
		ratePerIP: 60,
		ratePerToken: 300,
		windowSec: 60,
		bodyCap: null,
		tokenRequired: true,
	},
	ipinfo: {
		ratePerIP: 30,
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: null,
		tokenRequired: true,
	},

	// ── Stateful writes (always token-required) ──
	short: {
		ratePerIP: 0, // anonymous = 401
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: 64 * 1024, // 64 KiB JSON
		tokenRequired: true,
	},
	paste: {
		ratePerIP: 0,
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: 200 * 1024, // 200 KiB (paste text)
		tokenRequired: true,
	},
	sendmail: {
		ratePerIP: 0,
		ratePerToken: 30,
		windowSec: 60,
		bodyCap: 100 * 1024, // 100 KiB (mail body)
		tokenRequired: true,
	},
	cf: {
		// /cf/fetch is the gated sub-path; cf/pop|tls|clock|debug are public
		// low-risk reads. Routing through the same handler; the gate applies
		// only to /cf/fetch.
		ratePerIP: 0,
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: null,
		tokenRequired: true,
	},
	admin: {
		// Runtime-mutable admin endpoints. Always token-required.
		ratePerIP: 0,
		ratePerToken: 30,
		windowSec: 60,
		bodyCap: 64 * 1024,
		tokenRequired: true,
	},
};

/**
 * Default for routes not in the config table — pure-read, no abuse surface.
 * `/myip`, `/httpinfo`, `/ua`, `/headers`, `/hash`, `/jwt`, `/cron`,
 * `/services`, `/cf/{pop,tls,clock,debug,inspect}`.
 */
export const defaultConfig: RouteConfig = {
	ratePerIP: 60,
	ratePerToken: 200,
	windowSec: 60,
	bodyCap: null,
	tokenRequired: false,
};

export function getRouteConfig(name: string): RouteConfig {
	return config[name] ?? defaultConfig;
}

/** True if config says the route requires token by default. */
export function isTokenRequiredByDefault(name: string): boolean {
	const cfg = config[name];
	if (cfg) return cfg.tokenRequired;
	return defaultConfig.tokenRequired;
}

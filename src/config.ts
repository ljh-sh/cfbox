// src/config.ts — per-deployment + per-route configuration. Edit this
// file to tune cfbox without touching service handlers.
//
// **Path secret** — set this to a random string per deployment. When set,
// real endpoints live only at /<pathSecret>/api/v2/<svc>. All other paths
// return 404 (no hint at cfbox existence). Default `null` = backward-compat
// mode (routes at /<svc>).
//
//   - pathSecret: null           → /<svc>                  (backward compat)
//   - pathSecret: 'x7g9k2...'    → /<secret>/api/v2/<svc>   (URL-secret gate)
//
// To rotate: change the string, redeploy. Old URLs stop working.
//
// **Design principle: token gates operator privacy, not user traffic.**
//
// Lexicon:
//   "Operator privacy" — data the operator OWNS that an endpoint exposes:
//     - /cf/fetch       → operator's edge-fetched content / URLs
//     - /short /paste   → operator's KV state
//     - /sendmail       → operator's SMTP credentials
//     - /admin/*        → operator's lockdown state
//   "User traffic"    — request/response data the user already knows:
//     - /httpget /md /unshorten /doh /ipinfo  → user-supplied URLs/IPs/hosts
//     - These expose operator's privacy only as CF access logs (CF-retained)
//
// Token rule:
//   - Operator privacy exposed → tokenRequired: true (rate + token)
//   - User traffic only          → tokenRequired: false (rate limit only)
//
// Rate-limit semantics:
//   - ratePerIP  (anonymous) → 5/30s per high-risk route
//   - ratePerToken (token)  → 200 req/min/token
//   - ratePerIP: 0      → disable anonymous access (implies tokenRequired)
//   - ratePerIP: -1     → disable rate limit (avoid; defense-in-depth)
//
// SSRF guard (`safety.ts`) applies to all routes that fetch user-supplied URLs.

/**
 * Deployment-wide path secret. Operator sets this to a unique random
 * string per deployment. Generated with e.g. `openssl rand -hex 16`.
 *
 * Leave `null` to disable the URL-secret gate (backward-compat mode).
 * All routes then live at /<svc> under the public hostname.
 */
export const pathSecret: string | null = null;

export interface RouteConfig {
	/** Anonymous rate limit. 0 = block, -1 = disabled, positive = count. */
	ratePerIP: number;
	/** Token-authenticated rate limit. */
	ratePerToken: number;
	/** Sliding window length in seconds. */
	windowSec: number;
	/** Inbound body cap (POST/PUT). null = no body allowed; 0 = no cap. */
	bodyCap: number | null;
	/**
	 * Default true: require token. Flip to false to allow anonymous use.
	 * Routes only in defaultConfig (no entry below) are always anonymous.
	 */
	tokenRequired: boolean;
}

export const config: Record<string, RouteConfig> = {
	// ── User traffic (no operator privacy; rate-limit only) ──
	httpget: {
		ratePerIP: 5,
		ratePerToken: 200,
		windowSec: 30, // 5 req per 30s window
		bodyCap: 10 * 1024 * 1024, // 10 MiB
		tokenRequired: false, // public — rate limit + SSRF guard
	},
	md: {
		ratePerIP: 5,
		ratePerToken: 200,
		windowSec: 30,
		bodyCap: 5 * 1024 * 1024, // 5 MiB
		tokenRequired: false, // public — rate limit + SSRF guard
	},
	unshorten: {
		ratePerIP: 10,
		ratePerToken: 200,
		windowSec: 30,
		bodyCap: null,
		tokenRequired: false, // public — rate limit + SSRF guard
	},
	doh: {
		ratePerIP: 60,
		ratePerToken: 300,
		windowSec: 60,
		bodyCap: null,
		tokenRequired: false, // public — rate limit only
	},
	ipinfo: {
		ratePerIP: 30,
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: null,
		tokenRequired: false, // public — rate limit only
	},

	// ── Operator privacy (token-required) ──
	short: {
		ratePerIP: 0, // anonymous = 401
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: 64 * 1024, // 64 KiB JSON
		tokenRequired: true, // writes to operator's KV
	},
	paste: {
		ratePerIP: 0,
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: 200 * 1024, // 200 KiB (paste text)
		tokenRequired: true, // writes to operator's KV
	},
	sendmail: {
		ratePerIP: 0,
		ratePerToken: 30,
		windowSec: 60,
		bodyCap: 100 * 1024, // 100 KiB (mail body)
		tokenRequired: true, // uses operator's SMTP credentials
	},
	cf: {
		// /cf/fetch is the gated sub-path; cf/pop|tls|clock|debug|inspect are
		// public low-risk reads. The handler enforces /cf/fetch token check
		// directly; routes for the other sub-paths use defaultConfig below.
		ratePerIP: 0,
		ratePerToken: 60,
		windowSec: 60,
		bodyCap: null,
		tokenRequired: true, // /cf/fetch is operator-controlled edge IP fetcher
	},
	admin: {
		ratePerIP: 0,
		ratePerToken: 30,
		windowSec: 60,
		bodyCap: 64 * 1024,
		tokenRequired: true, // operator control
	},
};

/**
 * Default for routes not in the config table — pure-read, no abuse surface.
 * `/myip`, `/httpinfo`, `/ua`, `/headers`, `/hash`, `/jwt`, `/cron`,
 * `/services`, `/cf/{pop,tls,clock,debug,inspect}`.
 *
 * No token, anonymous rate limit only. Public by default.
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

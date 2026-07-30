// src/types.ts — Service interface contract.
//
// Every service in cfbox conforms to this interface. The dispatcher
// (src/index.ts) reads `registry[serviceName].fetch(req, env, ctx)`.

export interface ServiceMeta {
	/** Stable identifier; used as registry key (and as URL path segment). */
	name: string;
	/** Public URL path with leading slash (e.g. `/myip`). */
	path: string;
	/** Bilingual description for documentation / future dashboard. */
	desc: { en: string; cn: string };
}

/**
 * Cloudflare Worker bindings (KV, R2, D1, Durable Objects, vars, secrets, ...).
 */
export interface Env {
	/** KV namespace backing the /short service. Created via `wrangler kv namespace create SHORT_KV`. */
	SHORT_KV: KVNamespace;
	/**
	 * Optional shared-secret token. When set, gated services require the
	 * `x-cfbox-token` header (or `Authorization: Bearer <token>`). Set via
	 * `wrangler secret put CFBOX_TOKEN`. Fail-closed: unset → gated services 401.
	 */
	CFBOX_TOKEN?: string;
	/**
	 * Optional path secret. When set, real endpoints live only at
	 * `/<secret>/api/v2/<svc>`. All other paths return 404 (no exposure of
	 * which routes exist). Set via `wrangler secret put CFBOX_PATHSECRET`.
	 */
	CFBOX_PATHSECRET?: string;
}

/**
 * A cfbox service = one HTTP endpoint.
 *
 * @example
 * ```ts
 * export const myip: Service = {
 *   meta: { name: 'myip', path: '/myip', desc: { en: '...', cn: '...' } },
 *   fetch: async (req, env, ctx) => new Response(...),
 * };
 * ```
 */
export interface Service {
	meta: ServiceMeta;
	fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response>;
}

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

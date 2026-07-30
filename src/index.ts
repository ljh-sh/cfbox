// src/index.ts — Worker entry. The only fetch() handler in cfbox.
//
// Every URL arrives here; we look up the service in `registry` by pathname
// segment and dispatch to its `fetch` method.
//
// **Path secret gate** (opt-in via `CFBOX_PATHSECRET` env var):
//   - Set CFBOX_PATHSECRET to a random string per deployment
//   - Real endpoints live at /<secret>/api/v2/<svc>
//   - All other paths return 404 (regardless of HTTP method)
//   - Unset CFBOX_PATHSECRET → backward-compat: routes at /<svc>
//
// **Token gate** (separate layer, optional): CFBOX_TOKEN.
//
// Both mechanisms can be combined — path secret is the deployment
// credential, token is the per-user credential.

import { registry } from './registry';
import { checkLockdown } from './safety';
import { pathSecret } from './config';

export default {
	async fetch(
		req: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(req.url);

		// 1. Path secret gate. If config.pathSecret is set, only /<secret>/api/v2/<svc>
		//    is recognized. Other paths are 404 (we don't even hint that cfbox lives here).
		if (pathSecret) {
			const prefix = `/${pathSecret}/api/v2`;
			if (url.pathname !== prefix && !url.pathname.startsWith(prefix + '/')) {
				return new Response('not found', {
					status: 404,
					headers: { 'content-type': 'text/plain; charset=utf-8' },
				});
			}
			// Strip the prefix so downstream handlers see the canonical path.
			const rest = url.pathname.slice(prefix.length) || '/';
			url.pathname = rest;
			req = new Request(url, req);
		}

		// 2. Global lockdown check (anonymous only — token-holders bypass).
		//    Runs BEFORE route dispatch so /myip, /hash, etc. also block.
		const lock = await checkLockdown(req, env);
		if (lock) return lock;

		// 3. Service dispatch.
		const segments = url.pathname.split('/').filter(Boolean);
		const serviceName = segments[0];

		if (!serviceName) {
			return new Response(
				'cfbox: no service specified. Try /myip.',
				{
					status: 400,
					headers: { 'content-type': 'text/plain; charset=utf-8' },
				},
			);
		}

		const handler = registry[serviceName];
		if (!handler) {
			return new Response(`cfbox: unknown service "${serviceName}"`, {
				status: 404,
				headers: { 'content-type': 'text/plain; charset=utf-8' },
			});
		}

		return handler.fetch(req, env, ctx);
	},
};

// src/index.ts — Worker entry. The only fetch() handler in cfbox.
//
// Every URL arrives here; we look up the service in `registry` by pathname
// segment and dispatch to its `fetch` method. v0.1 ships `/myip`; the
// index service (`/`) is NOT part of cfbox (deferred to a separate project).

import { registry } from './registry';

export default {
	async fetch(
		req: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(req.url);
		const segments = url.pathname.split('/').filter(Boolean);
		const serviceName = segments[0];

		if (!serviceName) {
			return new Response(
				'cfbox: no service specified. Try /myip (the only service in v0.1).',
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

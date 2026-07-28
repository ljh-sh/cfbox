// src/services/services.ts — service catalog for hub integration.
// Returns the registry's meta exposed so hubs can introspect
// what services cfbox exposes (paths, methods, auth level, desc).

import type { Service } from '../types';
import { registry } from '../registry';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

const SERVICES_PATH = '/services';

// Heuristic auth detection — service name patterns we gate with ADMIN_PASS.
// Hub uses this to know which endpoints to pre-acquire a session for.
function authLevel(name: string): 'none' | 'admin' | 'session' {
	const writes = ['short', 'paste', 'sendmail', 'cf']; // cf owns /cf/fetch which is admin
	const reads = ['r']; // alias to short, doesn't add auth
	if (writes.includes(name)) return 'admin';
	if (reads.includes(name)) return 'none';
	return 'none';
}

function methodsFor(name: string): string[] {
	// Most services accept both GET and (sometimes) POST/PUT.
	// For v0.5 we only emit GET; multipart methods come when the service grows.
	const m = ['GET'];
	if (name === 'short' || name === 'paste' || name === 'sendmail') m.push('POST');
	if (name === 'cf-fetch') m.push('POST'); // /cf/fetch also accepts POST via the same path
	return m;
}

export const services: Service = {
	meta: {
		name: 'services',
		path: SERVICES_PATH,
		desc: {
			en: 'Service catalog for hub integration (introspect paths/auth/descs)',
			cn: '服务目录（hub 集成用：自省 paths/auth/desc）',
		},
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const method = req.method.toUpperCase();
		if (method !== 'GET') {
			return json({ error: 'GET only' }, 405);
		}
		// Reject anything beyond /services[/...]
		if (u.pathname !== SERVICES_PATH && u.pathname !== SERVICES_PATH + '/') {
			return json({ error: 'unknown sub-path' }, 404);
		}

		const list = Object.entries(registry).map(([name, svc]) => ({
			name,
			path: svc.meta.path,
			methods: methodsFor(name),
			auth: authLevel(name),
			desc: svc.meta.desc,
		}));

		return json({
			version: '1',
			runtime: 'cloudflare-workers',
			serviceCount: list.length,
			services: list,
		});
	},
};

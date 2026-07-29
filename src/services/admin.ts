// src/services/admin.ts — runtime-mutable admin endpoints.
//
// All endpoints require the CFBOX_TOKEN (same auth as the rest of cfbox).
//
// Sub-paths:
//   GET    /admin/lockdown          → status { active, until? }
//   POST   /admin/lockdown  { ttlSec: number, until?: string }  → set
//   DELETE /admin/lockdown          → clear
//
// Why this lives in KV (not config.ts):
//   - Lockdown is short-lived (1h TTL) and may change daily during an attack.
//   - No redeploy needed.
//   - config.ts is git-audited for static settings; KV is for ops state.

import type { Service } from '../types';
import { checkToken } from '../auth';
import { getLockdownStatus, setLockdown, clearLockdown } from '../safety';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

export const admin: Service = {
	meta: {
		name: 'admin',
		path: '/admin',
		desc: {
			en: 'Runtime-mutable admin endpoints (lockdown toggle, token required)',
			cn: '运行时管理端点（lockdown 开关，需 token）',
		},
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);

		// Token gate (always required for /admin/*).
		const t = await checkToken(req, env);
		if (!t.ok) {
			return json(
				{
					error: 'admin endpoints require token',
					hint: 'supply x-cfbox-token header',
				},
				401,
			);
		}

		// --- /admin/lockdown ---
		if (u.pathname === '/admin/lockdown' || u.pathname === '/admin/lockdown/') {
			// GET → status
			if (req.method === 'GET') {
				const status = await getLockdownStatus(env);
				return json(status);
			}
			// POST → set
			if (req.method === 'POST') {
				let body: { ttlSec?: unknown; until?: unknown } = {};
				try {
					body = (await req.json()) as typeof body;
				} catch {
					// empty body OK — uses default ttl
				}
				const ttlSec =
					typeof body.ttlSec === 'number' ? body.ttlSec : 3600;
				const until =
					typeof body.until === 'string' ? body.until : undefined;
				await setLockdown(env, { ttlSec, until });
				const status = await getLockdownStatus(env);
				return json({ ok: true, ...status });
			}
			// DELETE → clear
			if (req.method === 'DELETE') {
				await clearLockdown(env);
				return json({ ok: true, active: false });
			}
			return json({ error: 'GET / POST / DELETE only' }, 405);
		}

		return json(
			{
				error: `unknown admin path ${u.pathname}`,
				known: ['/admin/lockdown'],
			},
			404,
		);
	},
};

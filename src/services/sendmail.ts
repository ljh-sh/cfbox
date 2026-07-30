// src/services/sendmail.ts — self-mail service via MailChannels.
// v0.6 personal toolbox: token-gated; intended for user→self mail
// (notifications, OOB approval, etc.). Swap to Resend/SendGrid API
// key for production-grade delivery & abuse controls.

import type { Service } from '../types';
import { checkToken } from '../auth';

const FROM_EMAIL = 'noreply@cfbox.ljh.sh';
const FROM_NAME = 'cfbox';
const MAILCHANNELS_URL = 'https://api.mailchannels.net/tx/v1/send';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

export const sendmail: Service = {
	meta: {
		name: 'sendmail',
		path: '/sendmail',
		desc: {
			en: 'Self-mail via MailChannels (admin pass required)',
			cn: 'MailChannels 自邮件（需 admin pass）',
		},
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		if (req.method !== 'POST' || u.pathname !== '/sendmail') {
			return json(
				{ error: 'POST /sendmail {to, subject, text} (token via x-cfbox-token)' },
				405,
			);
		}

		// Token gate.
		const t = await checkToken(req, env);
		if (!t.ok) return t.response!;

		let body: {
			to?: unknown;
			subject?: unknown;
			text?: unknown;
		};
		try {
			body = (await req.json()) as typeof body;
		} catch {
			return json({ error: 'invalid JSON body' }, 400);
		}

		if (typeof body.to !== 'string' || !body.to.includes('@')) {
			return json({ error: 'valid `to` email required' }, 400);
		}
		if (typeof body.subject !== 'string' || body.subject.length === 0) {
			return json({ error: '`subject` required' }, 400);
		}
		if (typeof body.text !== 'string') {
			return json({ error: '`text` required' }, 400);
		}

		const res = await fetch(MAILCHANNELS_URL, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				personalizations: [{ to: [{ email: body.to }] }],
				from: { email: FROM_EMAIL, name: FROM_NAME },
				subject: body.subject,
				content: [{ type: 'text/plain', value: body.text }],
			}),
		});
		const resBody = await res.text();

		return json(
			{
				ok: res.ok,
				mailchannels_status: res.status,
				mailchannels_body: resBody.slice(0, 500),
				to: body.to,
				subject: body.subject,
			},
			res.ok ? 200 : 502,
		);
	},
};

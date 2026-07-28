// src/services/ua.ts — parse User-Agent string into browser/OS/device/bot.
// Uses ?ua=<string> or falls back to the request's own UA.

import type { Service } from '../types';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

function parseUA(ua: string): {
	browser: string | null;
	os: string | null;
	device: string | null;
	bot: boolean;
} {
	const r = { browser: null, os: null, device: null, bot: false };
	if (/bot|crawl|spider|slurp|mediapartners|headless|curl|wget/i.test(ua))
		r.bot = true;
	if (/Edg\//.test(ua)) r.browser = 'Edge';
	else if (/OPR\//.test(ua)) r.browser = 'Opera';
	else if (/Chrome\//.test(ua)) r.browser = 'Chrome';
	else if (/Firefox\//.test(ua)) r.browser = 'Firefox';
	else if (/Safari\//.test(ua) && /Version\//.test(ua)) r.browser = 'Safari';
	if (/Windows NT/.test(ua)) r.os = 'Windows';
	else if (/Mac OS X|macOS/.test(ua)) r.os = 'macOS';
	else if (/Android/.test(ua)) r.os = 'Android';
	else if (/iPhone|iPad|iPod/.test(ua)) r.os = 'iOS';
	else if (/Linux/.test(ua)) r.os = 'Linux';
	if (/Mobile|iPhone|Android.*Mobile/.test(ua)) r.device = 'mobile';
	else if (/iPad|Tablet/.test(ua)) r.device = 'tablet';
	else r.device = 'desktop';
	return r;
}

export const ua: Service = {
	meta: {
		name: 'ua',
		path: '/ua',
		desc: { en: 'Parse User-Agent string', cn: '解析 User-Agent 字符串' },
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const raw = u.searchParams.get('ua') ?? req.headers.get('user-agent') ?? '';
		return json({ raw, ...parseUA(raw) });
	},
};

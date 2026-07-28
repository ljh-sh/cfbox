// src/services/cron.ts — parse 5-field cron expression into human-readable parts.
//   GET /cron?expr=*%20*%20*%20*%20*

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

const MONTHS = [
	'',
	'January',
	'February',
	'March',
	'April',
	'May',
	'June',
	'July',
	'August',
	'September',
	'October',
	'November',
	'December',
];
const DAYS = [
	'Sunday',
	'Monday',
	'Tuesday',
	'Wednesday',
	'Thursday',
	'Friday',
	'Saturday',
];

function describeField(
	field: string,
	min: number,
	max: number,
	names?: string[],
): string {
	if (field === '*') return `every (${min}-${max})`;
	if (field.includes(',')) {
		return field
			.split(',')
			.map((f) => describeField(f, min, max, names))
			.join(', ');
	}
	if (field.startsWith('*/')) {
		const step = field.slice(2);
		const n = parseInt(step, 10);
		if (!isNaN(n))
			return n === 1
				? `every minute`
				: `every ${step} (${min}-${max})`;
	}
	if (field.includes('/')) {
		const [base, step] = field.split('/');
		const n = parseInt(step, 10);
		if (!isNaN(n))
			return `every ${step} starting at ${base} (${min}-${max})`;
	}
	if (field.includes('-')) {
		const [from, to] = field.split('-');
		return `${from} through ${to}`;
	}
	if (names) {
		const idx = parseInt(field, 10);
		if (!isNaN(idx) && idx >= 0 && idx < names.length) return names[idx];
	}
	return `${field} (${min}-${max})`;
}

export const cron: Service = {
	meta: {
		name: 'cron',
		path: '/cron',
		desc: { en: 'Parse 5-field cron into human-readable parts', cn: '解析 cron 表达式' },
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);
		const expr = u.searchParams.get('expr') ?? '';
		if (!expr) return json({ error: 'expr query param required' }, 400);
		const parts = expr.trim().split(/\s+/);
		if (parts.length !== 5) {
			return json(
				{ error: 'cron must have exactly 5 fields: minute hour dom month dow' },
				400,
			);
		}
		const [m, h, dom, mon, dow] = parts;
		return json({
			expr,
			fields: {
				minute: { value: m, name: 'minute', range: '0-59' },
				hour: { value: h, name: 'hour', range: '0-23' },
				dayOfMonth: { value: dom, name: 'day of month', range: '1-31' },
				month: { value: mon, name: 'month', range: '1-12' },
				dayOfWeek: { value: dow, name: 'day of week', range: '0-6 (Sun=0)' },
			},
			description: {
				minute: describeField(m, 0, 59),
				hour: describeField(h, 0, 23),
				dayOfMonth: describeField(dom, 1, 31),
				month: describeField(mon, 1, 12, MONTHS),
				dayOfWeek: describeField(dow, 0, 6, DAYS),
			},
		});
	},
};

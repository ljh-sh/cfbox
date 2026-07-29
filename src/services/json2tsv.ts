// src/services/json2tsv.ts — JSON / JSONL → TSV converter.
// Sub-paths:
//   /json2tsv    JSON array of objects → TSV
//   /jsonl2tsv   JSONL (one JSON per line) → TSV
//
// Both accept either:
//   POST body    (Content-Type: application/json or text/plain; raw data in body)
//   GET ?url=X   (fetch the URL, then convert)
//
// Pure stateless, ~80 lines, no deps.

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

function tsvResponse(s: string, mode: 'json' | 'jsonl'): Response {
	return new Response(s, {
		status: 200,
		headers: {
			'content-type': 'text/tab-separated-values; charset=utf-8',
			'cache-control': 'no-store',
			'x-cfbox-mode': mode,
		},
	});
}

// Escape tab/newline inside a TSV cell so the output stays a valid grid.
function cell(v: unknown): string {
	if (v === undefined || v === null) return '';
	const s =
		typeof v === 'string' ? v : JSON.stringify(v);
	return s.replace(/\t/g, ' ').replace(/[\r\n]+/g, ' ');
}

// Convert an array of objects (or array of arrays) to a TSV string.
function rowsToTsv(rows: unknown[]): string {
	if (rows.length === 0) return '';

	// Path A: array-of-arrays → keep row 0 as header, values per column
	if (Array.isArray(rows[0])) {
		return rows
			.map((row) =>
				(Array.isArray(row) ? row : []).map((c) => cell(c)).join('\t'),
			)
			.join('\n');
	}

	// Path B: array-of-objects → union of all keys as header row
	const cols = new Set<string>();
	for (const r of rows) {
		if (r && typeof r === 'object') {
			for (const k of Object.keys(r as Record<string, unknown>)) {
				cols.add(k);
			}
		}
	}
	const colList = [...cols];
	if (colList.length === 0) return '';
	const header = colList.join('\t');
	const body = rows
		.map((r) => {
			if (!r || typeof r !== 'object') return '';
			const obj = r as Record<string, unknown>;
			return colList.map((c) => cell(obj[c])).join('\t');
		})
		.join('\n');
	return header + '\n' + body + (body.endsWith('\n') ? '' : '\n');
}

// JSONL: each non-blank line is one JSON object.
function jsonlToTsv(input: string): string {
	const rows: unknown[] = [];
	const errors: string[] = [];
	for (const line of input.split('\n')) {
		const t = line.trim();
		if (!t) continue;
		try {
			rows.push(JSON.parse(t));
		} catch (e) {
			errors.push(line.slice(0, 80));
		}
	}
	if (rows.length === 0 && errors.length > 0) {
		throw new Error(`no valid JSONL rows (first bad line: ${errors[0]})`);
	}
	return rowsToTsv(rows);
}

async function fetchText(url: string): Promise<string> {
	const res = await fetch(url, {
		headers: { 'user-agent': 'cfbox-json2tsv/0.5 (+https://cfbox.ljh.sh)' },
		redirect: 'follow',
	});
	if (!res.ok) throw new Error(`fetch HTTP ${res.status}`);
	return res.text();
}

export const json2tsv: Service = {
	meta: {
		name: 'json2tsv',
		path: '/json2tsv',
		desc: {
			en: 'JSON / JSONL → TSV (POST body or GET ?url=X). Array of objects → header + rows.',
			cn: 'JSON / JSONL → TSV（POST 主体或 GET ?url=X）',
		},
	},
	fetch: async (req, env, ctx) => {
		if (req.method !== 'GET' && req.method !== 'POST') {
			return json({ error: 'GET or POST only' }, 405);
		}

		const u = new URL(req.url);
		const mode: 'jsonl' | 'json' = u.pathname.startsWith('/jsonl2tsv')
			? 'jsonl'
			: 'json';

		// Acquire input: from body (POST) or URL (GET)
		let input = '';
		if (req.method === 'GET') {
			const targetUrl = u.searchParams.get('url');
			if (!targetUrl) return json({ error: 'GET requires ?url=X (or use POST body)' }, 400);
			if (!/^https?:\/\//.test(targetUrl)) return json({ error: 'url must start with http(s)://' }, 400);
			try {
				input = await fetchText(targetUrl);
			} catch (e) {
				return json({ error: `fetch failed: ${(e as Error).message}` }, 502);
			}
		} else {
			input = await req.text();
			if (!input.trim()) return json({ error: 'empty POST body' }, 400);
		}

		// Convert
		let tsv: string;
		try {
			if (mode === 'jsonl') {
				tsv = jsonlToTsv(input);
			} else {
				const parsed = JSON.parse(input);
				if (!Array.isArray(parsed)) {
					return json({ error: 'json input must be an array of objects (or array of arrays)' }, 400);
				}
				tsv = rowsToTsv(parsed);
			}
		} catch (e) {
			return json({ error: `${mode} parse failed: ${(e as Error).message}` }, 400);
		}
		return tsvResponse(tsv, mode);
	},
};

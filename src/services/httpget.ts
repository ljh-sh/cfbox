// src/services/httpget.ts — Smart download proxy + on-the-fly transforms.
//
// GET  /httpget?url=X                  → pass-through (returns what upstream serves)
// GET  /httpget?url=X&conv=ungz       → gzip-decompress to raw bytes
// GET  /httpget?url=X&conv=gzip       → re-compress to gzip
// GET  /httpget?url=X&conv=json2tsv   → fetch JSON, transform to TSV
// GET  /httpget?url=X&conv=jsonl2tsv  → fetch NDJSON, transform to TSV
// POST /httpget?conv=…                → transform body in place (URL optional)
//
// Built-in: gzip via Workers-native `CompressionStream` (0 deps). For NDJSON/TSV
// transforms, uses pure regex parsers (0 deps).
//
// Privacy note: when used as a download proxy, the data transits CF edge. Use
// only with URLs you trust, or POST in your own data.

import type { Service } from '../types';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
	});
}

function textOut(body: string, status = 200, extra: Record<string, string> = {}): Response {
	return new Response(body, {
		status,
		headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...extra },
	});
}

function bytesOut(body: Uint8Array, ct: string, extra: Record<string, string> = {}): Response {
	return new Response(body, {
		status: 200,
		headers: { 'content-type': ct, 'cache-control': 'no-store', ...extra },
	});
}

const UA = 'cfbox-httpget/0.5 (+https://cfbox.ljh.sh)';

// ---------- transforms ----------

async function gzip(data: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([data]).stream().pipeThrough(new CompressionStream('gzip'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function ungzip(data: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

function cell(v: unknown): string {
	if (v === undefined || v === null) return '';
	const s = typeof v === 'string' ? v : JSON.stringify(v);
	return s.replace(/\t/g, ' ').replace(/[\r\n]+/g, ' ');
}
function rowsToTsv(rows: unknown[]): string {
	if (rows.length === 0) return '';
	if (Array.isArray(rows[0])) {
		return rows
			.map((row) => (Array.isArray(row) ? row : []).map((c) => cell(c)).join('\t'))
			.join('\n');
	}
	const cols = new Set<string>();
	for (const r of rows) {
		if (r && typeof r === 'object') {
			for (const k of Object.keys(r as Record<string, unknown>)) cols.add(k);
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

// Parse a single cols spec: "name=user.name,city=user.address.city".
// Col names are taken literally (no _ prefix, no reserved-name check). The URL
// query parser already separates on &, so a col name like "url" or "cols"
// inside `cols=...` is unambiguous — the col value is read as a single
// URLSearchParams entry.
interface ColSpec {
	outName: string;
	path: string[];
}
function parseColsSpec(spec: string): ColSpec[] {
	return spec
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean)
		.map((part) => {
			const eq = part.indexOf('=');
			if (eq < 0) throw new Error(`bad col "${part}" — expected name=path`);
			const outName = part.slice(0, eq).trim();
			let path = part.slice(eq + 1).trim();
			if (path.startsWith('.')) path = path.slice(1);
			const segs = path.split('.').filter(Boolean);
			return { outName, path: segs };
		});
}

// Walk path segments against an object/array. Returns undefined when missing.
function resolvePath(root: unknown, segs: string[]): unknown {
	let cur: unknown = root;
	for (const seg of segs) {
		if (cur === null || cur === undefined) return undefined;
		const obj = cur as Record<string, unknown> | unknown[];
		cur = /^\d+$/.test(seg) && Array.isArray(obj)
			? obj[Number(seg)]
			: (obj as Record<string, unknown>)[seg];
	}
	return cur;
}

// Project rows with an explicit col spec.
function rowsToTsvCols(rows: unknown[], cols: ColSpec[]): string {
	if (cols.length === 0) return '';
	const header = cols.map((c) => c.outName).join('\t');
	const body = rows
		.map((r) => {
			return cols
				.map((c) => {
					const v = resolvePath(r, c.path);
					if (v === undefined || v === null) return '';
					if (typeof v === 'object') return JSON.stringify(v).replace(/\t/g, ' ').replace(/[\r\n]+/g, ' ');
					return String(v).replace(/\t/g, ' ').replace(/[\r\n]+/g, ' ');
				})
				.join('\t');
		})
		.join('\n');
	return header + '\n' + body + (body.endsWith('\n') ? '' : '\n');
}
// Pick the largest array inside an object; if `parsed` is already an array,
// return it.  Lets `json2tsv` handle CVE-style documents whose top-level is
// an object containing multiple array fields (e.g. `new`, `updated`).
function asRowArray(parsed: unknown): unknown[] {
	if (Array.isArray(parsed)) return parsed;
	if (parsed && typeof parsed === 'object') {
		let best: unknown[] = [];
		for (const v of Object.values(parsed as Record<string, unknown>)) {
			if (Array.isArray(v) && v.length > best.length) best = v;
		}
		if (best.length > 0) return best;
	}
	throw new Error(
		'json input must be array, or object containing an array field',
	);
}

function jsonToTsv(input: string, cols?: ColSpec[]): string {
	const parsed = JSON.parse(input);
	const rows = asRowArray(parsed);
	if (cols && cols.length > 0) {
		return rowsToTsvCols(rows, cols);
	}
	return rowsToTsv(rows);
}

// Read `cols` spec from either repeated ?cols=A&cols=B style OR comma-separated.
function collectCols(u: URL): ColSpec[] {
	const all = u.searchParams.getAll('cols');
	const merged = all.join(',');
	if (!merged) return [];
	return parseColsSpec(merged);
}
function jsonlToTsv(input: string): string {
	const rows: unknown[] = [];
	for (const line of input.split('\n')) {
		const t = line.trim();
		if (!t) continue;
		rows.push(JSON.parse(t));
	}
	if (rows.length === 0) throw new Error('no valid JSONL rows');
	return rowsToTsv(rows);
}

// Same auto-pick behavior for NDJSON? No — NDJSON must be array-per-line.
// If a line parses to an object, keep it as a row regardless of array-ness.

// Transform a fetched body (text mode) by conv key.
async function transformText(conv: string, body: string, cols?: ColSpec[]): Promise<{ contentType: string; body: string }> {
	switch (conv) {
		case 'json2tsv':
			return {
				contentType: 'text/tab-separated-values; charset=utf-8',
				body: jsonToTsv(body, cols),
			};
		case 'jsonl2tsv': {
			const rows: unknown[] = [];
			for (const line of body.split('\n')) {
				const t = line.trim();
				if (!t) continue;
				rows.push(JSON.parse(t));
			}
			if (rows.length === 0) throw new Error('no valid JSONL rows');
			if (cols && cols.length > 0) {
				return {
					contentType: 'text/tab-separated-values; charset=utf-8',
					body: rowsToTsvCols(rows, cols),
				};
			}
			return {
				contentType: 'text/tab-separated-values; charset=utf-8',
				body: rowsToTsv(rows),
			};
		}
		default:
			throw new Error(`text conv '${conv}' not supported`);
	}
}

async function transformBytes(conv: string, body: Uint8Array): Promise<Uint8Array> {
	switch (conv) {
		case 'gzip':
			return gzip(body);
		case 'ungz':
			return ungzip(body);
		default:
			throw new Error(`bytes conv '${conv}' not supported (or use POST body)`);
	}
}

const TEXT_CONVS = new Set(['json2tsv', 'jsonl2tsv']);
const BYTES_CONVS = new Set(['gzip', 'ungz']);

const UA_FETCH_OPTS: RequestInit = {
	headers: { 'user-agent': UA },
	redirect: 'follow',
};

export const httpget: Service = {
	meta: {
		name: 'httpget',
		path: '/httpget',
		desc: {
			en: 'Smart download proxy + transform (?conv=gzip|ungz|json2tsv|jsonl2tsv). GET ?url=X or POST body.',
			cn: '下载代理 + 即时转换（?conv=gzip|ungz|json2tsv|jsonl2tsv）。GET ?url=X 或 POST 主体。',
		},
	},
	fetch: async (req, env, ctx) => {
		const u = new URL(req.url);

		// Resolve conv from either /conv/<op> path or ?conv=X query (path wins for clarity).
		let conv = '';
		const pathOp = u.pathname.match(/^\/conv\/([a-z0-9_-]+)$/i);
		if (pathOp) {
			conv = pathOp[1];
		} else if (u.pathname !== '/httpget' && u.pathname !== '/httpget/') {
			// Some other sub-path we don't recognize — reject
			return json(
				{
					error: `unknown sub-path '${u.pathname}'. Use /httpget or /conv/<op>.`,
					ops: ['gzip', 'ungz', 'json2tsv', 'jsonl2tsv'],
				},
				400,
			);
		} else {
			conv = u.searchParams.get('conv') ?? '';
		}

		// 1) determine input source
		let bytes: Uint8Array | null = null;
		let text: string | null = null;
		let finalUrl = '';
		let upstreamContentType: string | null = null;

		if (req.method === 'GET') {
			const targetUrl = u.searchParams.get('url');
			if (!targetUrl) return json({ error: 'GET requires ?url=X (or use POST body)' }, 400);
			if (!/^https?:\/\//.test(targetUrl)) return json({ error: 'url must start with http(s)://' }, 400);
			let upstream: Response;
			try {
				upstream = await fetch(targetUrl, UA_FETCH_OPTS);
			} catch (e) {
				return json({ error: `fetch failed: ${(e as Error).message}` }, 502);
			}
			if (!upstream.ok) return json({ error: `upstream HTTP ${upstream.status}` }, 502);
			finalUrl = upstream.url || targetUrl;
			upstreamContentType = upstream.headers.get('content-type');
			// Buffer input — for text convs decode as text; for bytes convs keep raw.
			const ab = await upstream.arrayBuffer();
			bytes = new Uint8Array(ab);
			if (TEXT_CONVS.has(conv)) {
				try {
					text = new TextDecoder('utf-8').decode(bytes);
				} catch {
					return json({ error: 'upstream not text-decodable (utf-8 failed)' }, 400);
				}
			}
		} else if (req.method === 'POST') {
			const ct = req.headers.get('content-type') ?? '';
			const ab = await req.arrayBuffer();
			bytes = new Uint8Array(ab);
			if (TEXT_CONVS.has(conv)) {
				text = new TextDecoder('utf-8').decode(bytes);
			}
		} else {
			return json({ error: 'GET or POST only' }, 405);
		}

		const colsSpec: ColSpec[] = []; // assigned inside the try below

		// 2) apply conv (if any)
		if (!conv) {
			// pass-through — return what we got
			if (bytes === null) return json({ error: 'no body' }, 400);
			const ct = upstreamContentType ?? 'application/octet-stream';
			return bytesOut(bytes, ct);
		}

		if (TEXT_CONVS.has(conv)) {
			if (text === null) return json({ error: `text conv '${conv}' needs text input` }, 400);
			try {
				colsSpec.length = 0; colsSpec.push(...collectCols(u));
				const out = await transformText(conv, text, colsSpec);
				return textOut(out.body, 200, {
					'content-type': out.contentType,
					'x-cfbox-final-url': finalUrl,
					'x-cfbox-conv': conv,
				});
			} catch (e) {
				return json({ error: `${conv} failed: ${(e as Error).message}` }, 400);
			}
		}

		if (BYTES_CONVS.has(conv)) {
			if (bytes === null) return json({ error: `bytes conv '${conv}' needs binary input` }, 400);
			try {
				const out = await transformBytes(conv, bytes);
				return bytesOut(out, 'application/octet-stream', {
					'x-cfbox-final-url': finalUrl,
					'x-cfbox-conv': conv,
				});
			} catch (e) {
				return json({ error: `${conv} failed: ${(e as Error).message}` }, 500);
			}
		}

		return json(
			{
				error: `unknown conv '${conv}'. Supported: ${[
					...TEXT_CONVS,
					...BYTES_CONVS,
				].join(', ')}`,
			},
			400,
		);
	},
};

// src/services/md.ts — HTML → Markdown converter.
// Sub-paths:
//   GET  /md?url=X          → fetch X, raw MD converter (chrome included)
//   GET  /md/article?url=X  → fetch X, article-mode (strip nav/header/footer first)
//   POST /md                body=html  → raw MD on supplied HTML
//   POST /md/article        body=html  → article-mode MD on supplied HTML
//
// v0.5: regex-based converter. Honest scope:
//   - Headings (h1–h6), bold/italic, code (inline + fenced), links, lists,
//     blockquote, images, tables (basic), horizontal rules
//   - Article mode strips `<script>`, `<style>`, `<nav>`, `<header>`, `<footer>`,
//     `<aside>`, `<form>` before converting
// Why not turndown/happy-dom: bundle VM-Context issues on CF Workers (see
// design.md §14). Pure regex keeps the bundle slim and matches v0.5 needs.

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

function text(body: string, status = 200): Response {
	return new Response(body, {
		status,
		headers: { 'content-type': 'text/plain; charset=utf-8' },
	});
}

const UA = 'cfbox-md/0.5 (+https://cfbox.ljh.sh)';

async function fetchHtml(url: string): Promise<{ html: string; finalUrl: string }> {
	const res = await fetch(url, { headers: { 'user-agent': UA } });
	if (!res.ok) throw new Error(`fetch HTTP ${res.status}`);
	return { html: await res.text(), finalUrl: res.url };
}

// Strip <script>, <style>, <nav>, <header>, <footer>, <aside>, <noscript>, <form> contents
// (Replace content with empty string rather than removing tag, to keep surrounding flow stable.)
const SKIP_CONTENT_BLOCK = /<(script|style|noscript|form)\b[^>]*>[\s\S]*?<\/\1>/gi;
const SKIP_CONTENT_INLINE = /<(script|style|noscript)\b[^>]*\/>/gi;

// Find the main article body. Returns inner HTML of <article> or <main>, or null.
// This is a CF-only heuristic — HTML5 semantic elements first, no DOM needed.
function extractArticleContent(html: string): string | null {
	const articleMatch = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i);
	if (articleMatch) return articleMatch[1];
	const mainMatch = html.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i);
	if (mainMatch) return mainMatch[1];
	return null;
}

function htmlToMd(html: string, opts: { article: boolean } = { article: false }): string {
	let s = html;

	// 1. Remove comments
	s = s.replace(/<!--[\s\S]*?-->/g, '');

	if (opts.article) {
		// 1a. Narrow down to <article> or <main> content if found (regex over raw HTML
		// is fine for this; HTMLRewriter streaming has too many restrictions).
		const narrowed = extractArticleContent(s);
		if (narrowed !== null) {
			s = narrowed;
		}
	}

	// 2. Drop script / style content (always)
	s = s.replace(SKIP_CONTENT_BLOCK, '');
	s = s.replace(SKIP_CONTENT_INLINE, '');

	if (opts.article) {
		// 2a. Drop nav/header/footer/aside (in case we did not find <article>)
		s = s.replace(/<(nav|header|footer|aside)\b[^>]*>[\s\S]*?<\/\1>/gi, '');
		s = s.replace(/<(nav|header|footer|aside)\b[^>]*\/>/gi, '');
	}

	// 3. Extract inline content first (preserve them)
	// Fenced code blocks ```...```
	s = s.replace(
		/<pre>\s*<code(?:\s+class=["'][^"']*language-([\w-]+)["'])?[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/gi,
		(_m, lang: string | undefined, code: string) => {
			const trimmed = code
				.replace(/<[^>]+>/g, '')
				.replace(/&lt;/g, '<')
				.replace(/&gt;/g, '>')
				.replace(/&amp;/g, '&')
				.replace(/&#10;/g, '\n')
				.replace(/&quot;/g, '"')
				.trim();
			return '\n```' + (lang || '') + '\n' + trimmed + '\n```\n';
		},
	);

	// Inline code `...`
	s = s.replace(/<code\b[^>]*>([^<]*)<\/code>/gi, (_m, code: string) => {
		const c = code
			.replace(/&lt;/g, '<')
			.replace(/&gt;/g, '>')
			.replace(/&amp;/g, '&');
		return '`' + c + '`';
	});

	// 4. Convert headings (greedy longest match)
	for (let level = 6; level >= 1; level--) {
		const re = new RegExp(
			`<h${level}\\b[^>]*>([\\s\\S]*?)<\\/h${level}>`,
			'gi',
		);
		s = s.replace(re, (_m, inner: string) => {
			const text = stripTags(inner).trim();
			return `\n\n${'#'.repeat(level)} ${text}\n\n`;
		});
	}

	// 5. Paragraphs: convert <p>...</p> to text + newlines
	s = s.replace(/<p\b[^>]*>([\s\S]*?)<\/p>/gi, (_m, inner: string) => {
		const text = inlineToMd(inner);
		return text.trim() ? `\n\n${text.trim()}\n\n` : '\n';
	});

	// 6. Line breaks
	s = s.replace(/<br\s*\/?>/gi, '  \n');

	// 7. Bold
	s = s.replace(
		/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1>/gi,
		(_m, _t, inner: string) => `**${inlineToMd(inner).trim()}**`,
	);

	// 8. Italic
	s = s.replace(
		/<(em|i)\b[^>]*>([\s\S]*?)<\/\1>/gi,
		(_m, _t, inner: string) => `*${inlineToMd(inner).trim()}*`,
	);

	// 9. Links
	s = s.replace(/<a\b[^>]*\bhref=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, (_m, href: string, text: string) => {
		const t = stripTags(text).trim();
		return t ? `[${t}](${href})` : '';
	});

	// 10. Images
	s = s.replace(
		/<img\b[^>]*\bsrc=["']([^"']+)["'][^>]*\balt=["']([^"']*)["'][^>]*\/?>/gi,
		(_m, src: string, alt: string) => `![${alt || ''}](${src})`,
	);
	s = s.replace(
		/<img\b[^>]*\bsrc=["']([^"']+)["'][^>]*\/?>/gi,
		(_m, src: string) => `![](${src})`,
	);

	// 11. Blockquote
	s = s.replace(
		/<blockquote\b[^>]*>([\s\S]*?)<\/blockquote>/gi,
		(_m, inner: string) => {
			const text = stripTags(inner).trim().replace(/^/gm, '> ');
			return `\n\n${text}\n\n`;
		},
	);

	// 12. Unordered list
	s = s.replace(/<ul\b[^>]*>([\s\S]*?)<\/ul>/gi, (_m, inner: string) => {
		const items = inner
			.match(/<li\b[^>]*>[\s\S]*?<\/li>/gi)
			?.map((li) => `- ${stripTags(li).trim()}`)
			.join('\n');
		return items ? `\n\n${items}\n\n` : '';
	});

	// 13. Ordered list
	s = s.replace(/<ol\b[^>]*>([\s\S]*?)<\/ol>/gi, (_m, inner: string) => {
		const items = inner
			.match(/<li\b[^>]*>[\s\S]*?<\/li>/gi)
			?.map((li, idx) => `${idx + 1}. ${stripTags(li).trim()}`)
			.join('\n');
		return items ? `\n\n${items}\n\n` : '';
	});

	// 14. Horizontal rule
	s = s.replace(/<hr\s*\/?>/gi, '\n\n---\n\n');

	// 15. Tables (basic — first <tr> as header, rest as body rows)
	s = s.replace(
		/<table\b[^>]*>([\s\S]*?)<\/table>/gi,
		(_m, inner: string) => {
			const rows = inner.match(/<tr\b[^>]*>[\s\S]*?<\/tr>/gi) ?? [];
			if (rows.length === 0) return '';
			const lines: string[] = [];
			for (let i = 0; i < rows.length; i++) {
				const cells = (rows[i].match(/<t[hd]\b[^>]*>([\s\S]*?)<\/t[hd]>/gi) ?? [])
					.map((c) => stripTags(c).trim().replace(/\|/g, '\\|'));
				if (cells.length) {
					lines.push(`| ${cells.join(' | ')} |`);
					if (i === 0 && rows.length > 1) {
						lines.push(`| ${cells.map(() => '---').join(' | ')} |`);
					}
				}
			}
			return lines.length ? `\n\n${lines.join('\n')}\n\n` : '';
		},
	);

	// 16. Strip remaining tags
	s = stripTags(s);

	// 17. Decode entities
	s = decodeEntities(s);

	// 18. Collapse whitespace
	s = s
		.replace(/\r\n/g, '\n')
		.replace(/[ \t]+\n/g, '\n')
		.replace(/\n{3,}/g, '\n\n')
		.trim();

	return s + '\n';
}

function stripTags(html: string): string {
	let s = html;
	// Drop remaining inline tags but keep their content
	s = s.replace(/<[^>]+>/g, '');
	return s;
}

function decodeEntities(s: string): string {
	return s
		.replace(/&lt;/g, '<')
		.replace(/&gt;/g, '>')
		.replace(/&quot;/g, '"')
		.replace(/&#39;/g, "'")
		.replace(/&apos;/g, "'")
		.replace(/&nbsp;/g, ' ')
		.replace(/&hellip;/g, '…')
		.replace(/&mdash;/g, '—')
		.replace(/&ndash;/g, '–')
		.replace(/&amp;/g, '&');
}

function inlineToMd(html: string): string {
	// Used inside <p>, <li>, <td> content — light cleanup of nested inline tags
	let s = html;
	// Bold / italic / code / link — handled by main flow when those regex run first.
	// But strip stray nested tags.
	s = s.replace(/<[^>]+>/g, '');
	return decodeEntities(s);
}

function mdResponse(
	body: string,
	mode: 'raw' | 'article',
	extra: Record<string, string> = {},
): Response {
	return new Response(body, {
		status: 200,
		headers: {
			'content-type': 'text/markdown; charset=utf-8',
			'cache-control': 'no-store',
			'x-cfbox-mode': mode,
			...extra,
		},
	});
}

export const md: Service = {
	meta: {
		name: 'md',
		path: '/md',
		desc: {
			en: 'HTML → Markdown (/md = raw; /md/article = strip chrome). GET ?url=X or POST body html.',
			cn: 'HTML→MD（/md 整页；/md/article 剥 nav/header/footer）。GET ?url=X 或 POST 主体 html',
		},
	},
	fetch: async (req, env, ctx) => {
		if (req.method !== 'GET' && req.method !== 'POST') {
			return json({ error: 'GET or POST only' }, 405);
		}

		const u = new URL(req.url);
		const path = u.pathname;
		const targetUrl = u.searchParams.get('url');

		let html: string;
		let finalUrl = '';
		if (req.method === 'GET' && targetUrl) {
			if (!/^https?:\/\//.test(targetUrl)) {
				return json({ error: 'url must start with http(s)://' }, 400);
			}
			try {
				const r = await fetchHtml(targetUrl);
				html = r.html;
				finalUrl = r.finalUrl;
			} catch (e) {
				return json({ error: `fetch failed: ${(e as Error).message}` }, 502);
			}
		} else if (req.method === 'POST') {
			const ct = req.headers.get('content-type') ?? '';
			if (ct.includes('application/json')) {
				let body: { html?: unknown };
				try {
					body = (await req.json()) as { html?: unknown };
				} catch {
					return json({ error: 'invalid JSON body; expected {"html":"..."}' }, 400);
				}
				if (typeof body.html !== 'string') {
					return json({ error: 'expected JSON {html:"..."}' }, 400);
				}
				html = body.html;
			} else {
				html = await req.text();
			}
			if (!html.trim()) {
				return json({ error: 'empty body; POST JSON {html:"..."} or raw HTML' }, 400);
			}
			finalUrl = targetUrl ?? '(POST)';
		} else {
			return json({ error: 'GET requires ?url=X; POST body has html' }, 400);
		}

		// /md → raw (chrome included)
		if (path === '/md' || path === '/md/') {
			try {
				const out = htmlToMd(html, false);
				return mdResponse(out, 'raw', { 'x-cfbox-final-url': finalUrl });
			} catch (e) {
				return json({ error: `md failed: ${(e as Error).message}` }, 500);
			}
		}

		// /md/article → strip nav/header/footer first
		if (path === '/md/article' || path === '/md/article/') {
			try {
				const out = htmlToMd(html, true);
				return mdResponse(out, 'article', { 'x-cfbox-final-url': finalUrl });
			} catch (e) {
				return json({ error: `md article failed: ${(e as Error).message}` }, 500);
			}
		}

		return text(
			'cfbox /md — /md (raw) or /md/article (strip chrome). GET ?url=X or POST body html.',
			405,
		);
	},
};

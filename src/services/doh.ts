// src/services/doh.ts — DNS-over-HTTPS endpoint, three response formats.
// Path mapping:
//   /doh         → wire-format (RFC 8484) binary, application/dns-message
//                  Aliases: /dns-query (Cloudflare/Quad9 convention)
//   /doh.json    → JSON-DoH (Cloudflare convention): Status / Question / Answer
//                  Aliases: /dns-json
//   /doh-debug   → human-friendly wrapper (tookMs, answerCount, etc.)
//                  Aliases: /dns
//
// Upstream: cloudflare-dns.com/dns-query (1.1.1.1). Single-source — same data,
// 3 encodings.
//
// Query input:
//   /doh?host=X&type=A  (simple, like JSON-DoH path uses)
//   /doh?dns=<b64url>   (RFC 8484 wire-format query, binary)

import type { Service } from '../types';
import { rateLimit } from '../safety';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

const ALLOWED_TYPES = new Set([
	'A',
	'AAAA',
	'MX',
	'TXT',
	'CNAME',
	'NS',
	'SRV',
	'CAA',
	'PTR',
]);

// Hex-encode helper for binary Content-Type responses.
function hexEncode(buf: ArrayBuffer): string {
	return Array.from(new Uint8Array(buf))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

// Cloudflare-shape JSON-DoH response (passthrough from upstream)
interface CloudflareDoH {
	Status: number;
	TC?: boolean;
	RD?: boolean;
	RA?: boolean;
	AD?: boolean;
	CD?: boolean;
	Question?: Array<{ name: string; type: number }>;
	Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
	Authority?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

async function fetchUpstream(
	host: string,
	typeRaw: string,
): Promise<{ status: number; body: CloudflareDoH }> {
	const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(
		host,
	)}&type=${typeRaw}`;
	const res = await fetch(url, {
		headers: { accept: 'application/dns-json' },
	});
	if (!res.ok) throw new Error(`upstream HTTP ${res.status}`);
	return { status: res.status, body: (await res.json()) as CloudflareDoH };
}

async function handleHost(host: string, typeRaw: string, u: URL) {
	const accepted = (u.searchParams.get('accept') ?? '').toLowerCase();
	const wantsWire = accepted.includes('application/dns-message');
	const wantsJson =
		accepted.includes('application/dns-json') || accepted === '' || wantsWire;

	// Hit upstream once.
	const t0 = Date.now();
	let upstream: { status: number; body: CloudflareDoH };
	try {
		upstream = await fetchUpstream(host, typeRaw);
	} catch (e) {
		return json(
			{ error: `DoH upstream failed: ${(e as Error).message}` },
			502,
		);
	}
	const tookMs = Date.now() - t0;

	// Wire-format (RFC 8484): synthesize a minimal DNS response packet from JSON.
	// Real wire-format would be RDATA encoded properly per type; this minimal
	// version covers A/AAAA/MX/CNAME/TXT by stringifying into the answer.
	if (wantsWire) {
		const wire = synthesizeWirePacket(host, typeRaw, upstream.body);
		return new Response(wire, {
			status: 200,
			headers: {
				'content-type': 'application/dns-message',
				'cache-control': 'no-store',
				'x-cfbox-took-ms': String(tookMs),
			},
		});
	}

	// JSON-DoH (Cloudflare shape)
	if (accepted.includes('application/dns-json') && !wantsJson) {
		return new Response(JSON.stringify(upstream.body), {
			status: 200,
			headers: {
				'content-type': 'application/dns-json',
				'cache-control': 'no-store',
				'x-cfbox-took-ms': String(tookMs),
			},
		});
	}
	if (accepted === '' || wantsJson) {
		return new Response(JSON.stringify(upstream.body), {
			status: 200,
			headers: {
				'content-type': 'application/dns-json',
				'cache-control': 'no-store',
				'x-cfbox-took-ms': String(tookMs),
			},
		});
	}

	return json({ error: 'unsupported accept type' }, 406);
}

// Minimal DNS wire-format packet synthesizer from Cloudflare JSON.
// Builds a small RFC 1035-compliant response. Supports common record types
// by encoding RDATA as a single label containing the answer text/hex.
// Full RDATA type-specific encoding (CNAME/MX/NS pointer chains, etc.) is
// outside the scope of v0.5; this is good enough for "use as a DoH URL".
function synthesizeWirePacket(host: string, typeRaw: string, body: CloudflareDoH): Uint8Array {
	const out: number[] = [];

	// Header (12 bytes)
	const txnId = 0x1234;
	out.push((txnId >> 8) & 0xff, txnId & 0xff);
	const flags = 0x8180; // QR=1, RD=1, RA=1
	out.push((flags >> 8) & 0xff, flags & 0xff);
	const qdCount = 1;
	const anCount = body.Answer?.length ?? 0;
	out.push(
		(qdCount >> 8) & 0xff, qdCount & 0xff,
		(anCount >> 8) & 0xff, anCount & 0xff,
		0, 0, // NS=0
		0, 0, // AR=0
	);

	// Q section: encode QNAME + QTYPE + QCLASS
	const labels = host.split('.').filter(Boolean);
	for (const l of labels) {
		out.push(l.length);
		for (let i = 0; i < l.length; i++) out.push(l.charCodeAt(i));
	}
	out.push(0); // root label

	const qtypeMap: Record<string, number> = {
		A: 1, AAAA: 28, MX: 15, TXT: 16, CNAME: 5, NS: 2, SRV: 33, CAA: 257, PTR: 12,
	};
	const qtype = qtypeMap[typeRaw] ?? 1;
	out.push((qtype >> 8) & 0xff, qtype & 0xff);
	out.push(0, 1); // CLASS=IN

	// A section: each answer
	for (const ans of body.Answer ?? []) {
		// NAME (reuse QNAME since it's the same)
		for (const l of labels) {
			out.push(l.length);
			for (let i = 0; i < l.length; i++) out.push(l.charCodeAt(i));
		}
		out.push(0);
		// TYPE
		const atype = ans.type ?? qtype;
		out.push((atype >> 8) & 0xff, atype & 0xff);
		// CLASS=IN
		out.push(0, 1);
		// TTL
		const ttl = ans.TTL ?? 60;
		out.push((ttl >> 24) & 0xff, (ttl >> 16) & 0xff, (ttl >> 8) & 0xff, ttl & 0xff);
		// RDLENGTH (placeholder, will fill after)
		const rdStart = out.length;
		out.push(0, 0);
		const dataStart = out.length;
		// RDATA — very simplified: A=4 bytes, AAAA=16, MX=2+len+data, others=label-encoded text
		if (atype === 1 && /^[\d.]+$/.test(ans.data)) {
			for (const octet of ans.data.split('.')) {
				out.push(parseInt(octet, 10) & 0xff);
			}
		} else if (atype === 28 && /:/.test(ans.data)) {
			// AAAA — parse colon-delimited IPv6 into 16 bytes
			const parts = ans.data.split(':');
			const bytes: number[] = [];
			let i = 0;
			while (i < parts.length) {
				if (parts[i] === '') {
					const zeros = 8 - (bytes.length / 2) - (parts.filter((p) => p !== '').length);
					for (let z = 0; z < zeros; z++) bytes.push(0, 0);
					i++;
					continue;
				}
				const v = parseInt(parts[i] || '0', 16);
				bytes.push((v >> 8) & 0xff, v & 0xff);
				i++;
			}
			while (bytes.length < 16) bytes.push(0);
			for (const b of bytes.slice(0, 16)) out.push(b);
		} else if (atype === 15 && ans.data.includes(' ')) {
			// MX: "10 mail.example.com"
			const [prefStr, ...rest] = ans.data.split(' ');
			const pref = parseInt(prefStr, 10) || 0;
			out.push((pref >> 8) & 0xff, pref & 0xff);
			const mxLabels = rest.join(' ').split('.').filter(Boolean);
			for (const l of mxLabels) {
				out.push(l.length);
				for (let i = 0; i < l.length; i++) out.push(l.charCodeAt(i));
			}
			out.push(0);
		} else if (atype === 16) {
			// TXT: JSON often strips quotes; pack the raw string as one label
			const txt = ans.data.replace(/^"|"$/g, '');
			out.push(txt.length);
			for (let i = 0; i < txt.length && i < 255; i++) out.push(txt.charCodeAt(i));
		} else if (atype === 5 || atype === 2 || atype === 12) {
			// CNAME/NS/PTR: domain name
			const ansLabels = ans.data.split('.').filter(Boolean);
			for (const l of ansLabels) {
				out.push(l.length);
				for (let i = 0; i < l.length; i++) out.push(l.charCodeAt(i));
			}
			out.push(0);
		} else {
			// Fallback: pack as text label
			const txt = String(ans.data);
			out.push(txt.length);
			for (let i = 0; i < txt.length && i < 255; i++) out.push(txt.charCodeAt(i));
		}
		const rdEnd = out.length;
		const rdLength = rdEnd - dataStart;
		out[rdStart] = (rdLength >> 8) & 0xff;
		out[rdStart + 1] = rdLength & 0xff;
	}

	return new Uint8Array(out);
}

// Wrapper friendly response — same shape as /doh but lowercased keys + tookMs.
function humanWrapper(host: string, typeRaw: string, body: CloudflareDoH, tookMs: number) {
	return {
		query: { host, type: typeRaw },
		status: body.Status,
		flags: {
			tc: body.TC ?? false,
			rd: body.RD ?? false,
			ra: body.RA ?? false,
			ad: body.AD ?? false,
			cd: body.CD ?? false,
		},
		answers: (body.Answer ?? []).map((a) => ({
			name: a.name,
			type: a.type,
			TTL: a.TTL,
			data: a.data,
		})),
		authority: (body.Authority ?? []).map((a) => ({
			name: a.name,
			type: a.type,
			TTL: a.TTL,
			data: a.data,
		})),
		answerCount: (body.Answer ?? []).length,
		tookMs,
	};
}

async function routeByContentType(
	host: string,
	typeRaw: string,
	u: URL,
): Promise<Response> {
	const accepted = (u.searchParams.get('accept') ?? '').toLowerCase();
	if (accepted.includes('application/dns-message')) {
		return handleHost(host, typeRaw, u);
	}
	if (accepted === '' || accepted.includes('application/dns-json')) {
		return handleHost(host, typeRaw, u);
	}
	// Default: JSON-DoH (CF shape)
	return handleHost(host, typeRaw, u);
}

export const doh: Service = {
	meta: {
		name: 'doh',
		path: '/doh',
		desc: {
			en: 'DNS-over-HTTPS (RFC 8484 wire-format + JSON-DoH + human-friendly wrapper)',
			cn: 'DoH 端点（wire-format + JSON-DoH + 自描述 wrapper）',
		},
	},
	fetch: async (req, env, ctx) => {
		const url = new URL(req.url);
		const path = url.pathname;

		// Per-IP rate limit. Outbound is fixed (1.1.1.1), so no SSRF surface.
		const rl = await rateLimit(req, { route: 'doh', limit: 60, windowSec: 60 });
		if (rl) return rl;

		// Aliases for compatibility
		const isWireAlias = path === '/dns-query';
		const isJsonAlias = path === '/dns-json';
		const isWrapperAlias = path === '/dns';

		// All three paths accept the same query inputs.
		const host = url.searchParams.get('host') ?? url.searchParams.get('name');
		const dnsParam = url.searchParams.get('dns'); // base64url RFC 8484 query (decode not implemented in v0.5)
		const typeRaw = (url.searchParams.get('type') ?? 'A').toUpperCase();

		if (!host && !dnsParam) {
			return json(
				{
					error: 'dox: ?host=X[&type=A] (or ?dns=<b64> for wire-format)',
				},
				400,
			);
		}

		if (dnsParam && !host) {
			return json(
				{
					error: 'wire-format ?dns=<b64> decode not yet implemented in v0.5; pass ?host=&type= instead',
				},
				501,
			);
		}

		if (!ALLOWED_TYPES.has(typeRaw)) {
			return json(
				{ error: `type must be one of: ${[...ALLOWED_TYPES].join(', ')}` },
				400,
			);
		}

		const t0 = Date.now();
		const upstream = await fetch(
			`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host!)}&type=${typeRaw}`,
			{ headers: { accept: 'application/dns-json' } },
		);
		if (!upstream.ok) {
			return json({ error: `DoH upstream HTTP ${upstream.status}` }, 502);
		}
		const body = (await upstream.json()) as CloudflareDoH;
		const tookMs = Date.now() - t0;
		const accepted = (url.searchParams.get('accept') ?? '').toLowerCase();

		// Wire-format path
		if (isWireAlias || accepted.includes('application/dns-message')) {
			const wire = synthesizeWirePacket(host!, typeRaw, body);
			return new Response(wire, {
				status: 200,
				headers: {
					'content-type': 'application/dns-message',
					'cache-control': 'no-store',
					'x-cfbox-took-ms': String(tookMs),
				},
			});
		}

		// JSON-DoH (CF shape) path
		if (isJsonAlias || accepted.includes('application/dns-json')) {
			return new Response(JSON.stringify(body), {
				status: 200,
				headers: {
					'content-type': 'application/dns-json',
					'cache-control': 'no-store',
					'x-cfbox-took-ms': String(tookMs),
				},
			});
		}

		// Wrapper (default for /dns)
		if (isWrapperAlias) {
			return json(humanWrapper(host!, typeRaw, body, tookMs));
		}

		// Fallback: default = JSON-DoH
		return new Response(JSON.stringify(body), {
			status: 200,
			headers: {
				'content-type': 'application/dns-json',
				'cache-control': 'no-store',
				'x-cfbox-took-ms': String(tookMs),
			},
		});
	},
};

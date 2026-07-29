// src/services/ipinfo.ts — PTR + ASN lookup for arbitrary IPs.
//   GET  /ipinfo?ip=A&ip=B&ip=C  →  multi-IP, returns array
//   POST /ipinfo  {ips: ["A", "B"]}  →  same
//
// Data sources:
//   - PTR  (IP → hostname)  : Cloudflare DoH (1.1.1.1) for "<reverse>.in-addr.arpa" / ".ip6.arpa"
//   - ASN  (network/border) : Team Cymru DNS for "<ip>.origin.asn.cymru.com" (TXT)
// Free; no key needed. No GeoIP (would need MaxMind license).
//
// Privacy: this service runs over plain HTTP — anyone hitting `/ipinfo?ip=...`
// is doing a public DoH query that any client could perform themselves.
// We add NO new privacy concern beyond the requester IP being logged at the
// edge.

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

const DOH = 'https://cloudflare-dns.com/dns-query';
// ip-api.com: free public IP geolocation. No key, HTTP/HTTPS, 45 req/min public.
// Docs: https://ip-api.com/docs — returns country/region/city/lat/lon/ISP/org.
const GEO_API = 'https://ip-api.com/json/';
const MAX_IPS = 50;

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
// Loose IPv6 check; sufficient for routing format
const IPV6_HAS_COLON = /^[\da-fA-F:]+$/;

function isIPv4(s: string): boolean {
	if (!IPV4_RE.test(s)) return false;
	const octets = s.split('.').map(Number);
	return octets.every((n) => n >= 0 && n <= 255);
}
function isIPv6(s: string): boolean {
	return IPV6_HAS_COLON.test(s) && s.includes('::') || (s.match(/:/g) || []).length >= 2;
}
function isValidIp(s: string): boolean {
	return typeof s === 'string' && (isIPv4(s) || isIPv6(s));
}

// PTR query name:
//   IPv4 "8.8.8.8"        → "8.8.8.8.in-addr.arpa"
//   IPv6 "2001:4860::8888" → expanded, nibble-reversed, "ip6.arpa"
function reverseName(ip: string): string {
	if (isIPv4(ip)) {
		return ip.split('.').reverse().join('.') + '.in-addr.arpa';
	}
	// IPv6: expand to 32 nibbles, reverse, dot-separate, suffix ip6.arpa
	const expanded = ip.replace(/::/g, ':').toLowerCase();
	// Strip leading/trailing colons, split on ":", pad each part to 4 nibbles
	const parts = expanded.split(':').filter((p) => p.length > 0);
	const nibbles = parts
		.map((p) => p.padEnd(4, '0'))
		.join('')
		.padEnd(32, '0');
	return nibbles.split('').reverse().join('.') + '.ip6.arpa';
}

// Team Cymru: "<ip>.origin.asn.cymru.com" → TXT "ASN | prefix | cc | registry | allocated"
function asnName(ip: string): string {
	return `${ip}.origin.asn.cymru.com`;
}

interface IpGeo {
	country: string;
	countryCode: string;
	region: string;
	regionName: string;
	city: string;
	lat: number;
	lon: number;
	timezone: string;
	isp: string;
	org: string;
}

interface IpResult {
	ip: string;
	ptr?: string | null;
	asn?: {
		asn: number;
		prefix: string;
		country: string;
		registry: string;
		allocated: string;
	} | null;
	geo?: IpGeo | null;
	geoError?: string;
	error?: string;
}

async function lookupOne(ip: string): Promise<IpResult> {
	if (!isValidIp(ip)) {
		return { ip, error: 'invalid ip format' };
	}
	try {
		const [ptrRes, asnRes, geoRes] = await Promise.all([
			// PTR
			fetch(
				`${DOH}?name=${encodeURIComponent(reverseName(ip))}&type=PTR`,
				{ headers: { accept: 'application/dns-json' } },
			),
			// ASN (Team Cymru TXT)
			fetch(
				`${DOH}?name=${encodeURIComponent(asnName(ip))}&type=TXT`,
				{ headers: { accept: 'application/dns-json' } },
			),
			// Geo (ip-api.com — IPv4 only, IPv6 falls back to CF req.cf)
			isIPv4(ip)
				? fetch(`${GEO_API}${encodeURIComponent(ip)}`)
				: Promise.resolve(null),
		]);

		// PTR
		let ptr: string | null = null;
		if (ptrRes.ok) {
			try {
				const data = (await ptrRes.json()) as { Answer?: Array<{ data: string }> };
				ptr = data.Answer?.[0]?.data ?? null;
			} catch {
				/* ignore */
			}
		}

		// ASN
		let asn: IpResult['asn'] = null;
		if (asnRes.ok) {
			try {
				const data = (await asnRes.json()) as { Answer?: Array<{ data: string }> };
				const raw = data.Answer?.[0]?.data ?? '';
				const cleaned = raw.replace(/^"|"$/g, '');
				const parts = cleaned.split(' | ').map((s) => s.trim());
				if (parts.length >= 5) {
					const asnNum = parseInt(parts[0].replace(/[^0-9]/g, ''), 10);
					if (!isNaN(asnNum)) {
						asn = {
							asn: asnNum,
							prefix: parts[1],
							country: parts[2],
							registry: parts[3],
							allocated: parts[4],
						};
					}
				}
			} catch {
				/* ignore */
			}
		}

		// Geo (ip-api.com)
		let geo: IpGeo | null = null;
		let geoError: string | undefined;
		if (geoRes) {
			try {
				if (geoRes.ok) {
					const data = (await geoRes.json()) as {
						status?: string;
						country?: string;
						countryCode?: string;
						region?: string;
						regionName?: string;
						city?: string;
						lat?: number;
						lon?: number;
						timezone?: string;
						isp?: string;
						org?: string;
					};
					if (data.status === 'success') {
						geo = {
							country: data.country ?? '',
							countryCode: data.countryCode ?? '',
							region: data.region ?? '',
							regionName: data.regionName ?? '',
							city: data.city ?? '',
							lat: data.lat ?? 0,
							lon: data.lon ?? 0,
							timezone: data.timezone ?? '',
							isp: data.isp ?? '',
							org: data.org ?? '',
						};
					} else {
						geoError = 'geo lookup returned no data';
					}
				} else {
					geoError = `http ${geoRes.status}`;
				}
			} catch (e) {
				geoError = (e as Error).message;
			}
		} else {
			// IPv6 — use CF req.cf as a minimal fallback (only the requester's own IP)
			// Skip for arbitrary query targets
			geoError = 'geo unavailable for IPv6 (free tier limit)';
		}

		const r: IpResult = { ip, ptr, asn, geo };
		if (geoError) r.geoError = geoError;
		return r;
	} catch (e) {
		return { ip, error: `lookup failed: ${(e as Error).message}` };
	}
}

export const ipinfo: Service = {
	meta: {
		name: 'ipinfo',
		path: '/ipinfo',
		desc: {
			en: 'PTR + ASN lookup for arbitrary IPs (multi-IP, DoH-based)',
			cn: 'PTR + ASN 查询（多 IP，DoH）',
		},
	},
	fetch: async (req, env, ctx) => {
		let ips: string[] = [];

		if (req.method === 'POST') {
			const ct = req.headers.get('content-type') ?? '';
			let body: { ips?: unknown } | null = null;
			try {
				body = ct.includes('application/json')
					? ((await req.json()) as { ips?: unknown })
					: ((await req.formData()).get('ips')
							? { ips: ((await req.formData()).get('ips') as string).split(',') }
							: null);
			} catch {
				return json({ error: 'invalid request body' }, 400);
			}
			if (!Array.isArray(body?.ips)) {
				return json(
					{ error: 'POST body must be JSON {"ips": ["A","B"]} or form ips=A,B' },
					400,
				);
			}
			ips = (body!.ips as unknown[]).map((x) => String(x)).filter(Boolean);
		} else if (req.method === 'GET') {
			const u = new URL(req.url);
			ips = u.searchParams.getAll('ip');
		} else {
			return json({ error: 'GET or POST only' }, 405);
		}

		if (ips.length === 0) {
			return json(
				{ error: 'no ip provided. GET ?ip=X&ip=Y or POST {"ips":["X","Y"]}' },
				400,
			);
		}
		if (ips.length > MAX_IPS) {
			return json(
				{ error: `max ${MAX_IPS} ips per request (got ${ips.length})` },
				400,
			);
		}

		// Parallel lookup
		const results = await Promise.all(ips.map(lookupOne));
		return json({ count: results.length, results });
	},
};

import type { Service, ServiceMeta } from './types';
import { myip } from './services/myip';
import { short } from './services/short';
import { sendmail } from './services/sendmail';
import { httpinfo } from './services/httpinfo';
import { unshorten } from './services/unshorten';
import { hash } from './services/hash';
import { headers } from './services/headers';
import { ua } from './services/ua';
import { jwt } from './services/jwt';
import { paste } from './services/paste';
import { cron } from './services/cron';
import { cf } from './services/cf';
import { doh } from './services/doh';
import { services } from './services/services';
import { md } from './services/md';
import { ipinfo } from './services/ipinfo';
import { httpget } from './services/httpget';

export const registry: Record<string, Service> = {
	myip,
	short,
	sendmail,
	httpinfo,
	unshorten,
	hash,
	headers,
	ua,
	jwt,
	paste,
	cron,
	cf,
	// DNS-over-HTTPS: all 4 paths route to the same handler, which internally
	// dispatches by pathname to the right response format.
	doh, // /doh (RFC 8484 wire-format via Accept header)
	'doh.json': doh, // /doh.json (JSON-DoH CF shape)
	'dns-query': doh, // /dns-query (RFC 8484 wire-format)
	'dns-json': doh, // /dns-json (JSON-DoH CF shape)
	dns: doh, // /dns (legacy wrapper, kept for backward compat)
	// /services — service catalog for hub integration (introspect)
	services,
	// /md — HTML → Markdown (regex-based)
	md,
	// /ipinfo — PTR + ASN for arbitrary IPs (multi-IP)
	ipinfo,
	// /httpget — Smart download proxy + transform (?conv=gzip|ungz|json2tsv|jsonl2tsv)
	httpget,
	// /conv — alias namespace for /httpget ops (e.g. /conv/gzip, /conv/json2tsv).
	// Same handler; dispatcher uses pathname-vs-query to pick the op.
	conv: httpget,
};

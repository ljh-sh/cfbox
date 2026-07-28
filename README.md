# cfbox

Single Cloudflare Worker, many small utility endpoints at `cfbox.<your-domain>/<service>`.

Designed for fork-to-deploy: clone, edit `wrangler.jsonc`, deploy, done. JSON-only output, designed to wrap behind [`x-cmd`](https://www.x-cmd.com/) or call directly via `curl`.

Current state: **v0.5** — 18 service paths live.

---

## Services

All paths under `cfbox.<your-domain>/`.

### Public info / debug

| Path | Method | Description |
|---|---|---|
| `/myip` | GET | Client IP + `req.cf`-populated geo (`country`, `city`, `region`, `continent`, `lat`, `lon`, `asn`, `asOrganization`, `colo`) |
| `/httpinfo` | GET | IP + geo + TLS + all request headers + parsed User-Agent |
| `/headers` | GET | All received HTTP headers (debug) |
| `/ua` | GET | Parse User-Agent string → `{browser, os, device, bot}`. Defaults to your own UA; pass `?ua=...` to parse arbitrary |

### DNS (4 response formats, same data)

| Path | Format |
|---|---|
| `/doh` | wire-format (RFC 8484) `application/dns-message` — for OS / `curl --doh-url` |
| `/doh.json` / `/dns-json` | JSON-DoH (Cloudflare shape `{Status, Question, Answer}`) |
| `/dns-query` | wire-format alias (`/dns-query?dns=<b64>` for full RFC 8484; `?host=&type=` for simple) |
| `/dns` | Friendly wrapper with `tookMs` + DNS flags (`tc/rd/ra/ad/cd`) |

OS DoH URL: `https://cfbox.ljh.sh/dns-query`.

### Computations

| Path | Description |
|---|---|
| `/hash?text=...&algo=sha-256\|sha-1\|sha-384\|sha-512` | Text hash (hex) |
| `/jwt?token=...` | Decode JWT header + payload (no signature verification — debug only) |
| `/cron?expr="*/15 * * * *"` | Parse cron into human-readable parts |
| `/diff?a=...&b=...` | (TBD) |
| `/unit?value=1&from=ft&to=m` | (TBD) |

### URL utilities

| Path | Description |
|---|---|
| `/unshorten?url=...` | Follow redirect chain → reveal final URL. SSRF-guarded (no internal IPs) |

### Storage (admin-gated via `?pass=123`)

| Path | Description |
|---|---|
| `/short` POST `{url, code?}` | URL shortener. Custom codes 2-32 chars `[A-Za-z0-9_-]`, optional. Returns `{code, url, short, createdAt}` |
| `/short?url=X&code=Y` GET | Browser-friendly: create + `302` to new `/r/<code>` |
| `/r/<code>` GET | Resolve short link → `302` + fire-and-forget click counter |
| `/paste` POST `{text, ttl?}` | Pastebin with optional TTL (KV-backed) |
| `/paste/<code>` GET | Read paste |

### Cloudflare edge debug toolkit (`/cf/*`)

| Path | Description |
|---|---|
| `/cf` / `/cf/inspect` | Full dump: IP, geo, TLS, all headers, timestamp |
| `/cf/pop` | Which CF POP served you (`colo`, `country`, `city`, etc.) |
| `/cf/tls` | TLS handshake info (`tlsVersion`, `tlsCipher`, `httpProtocol`) |
| `/cf/clock` | CF edge wallclock (useful for clock skew detection) |
| `/cf/debug` | All `CF-*` headers (`cf-ray`, `cf-ipcountry`, `cf-cache-status`, …) |
| `/cf/fetch?url=...&pass=...` | Fetch URL from CF edge IP (admin-gated, SSRF-guarded) |

### Scaffolded (not active)

| Path | Status |
|---|---|
| `/sendmail` POST `{to, subject, text, pass}` | Code in place; current sending provider (MailChannels) requires API key. Tier-3 deployments skip this entirely. |

---

## Hardcoded admin pass

All write/storage endpoints above (`/short`, `/paste`, `/sendmail`, `/cf/fetch`, etc.) check `pass`:

- POST body field: `{"pass":"<value>"}`
- GET query: `?pass=<value>`

Current value is `const ADMIN_PASS = '123'` in each `src/services/*.ts`. Single-user personal toolbox; harden before sharing publicly.

---

## Quick start

```bash
git clone https://github.com/ljh-sh/cfbox.git
cd cfbox
npm install   # optional — wrangler bundles its own worker-types
```

### Dev (no deploy needed)

```bash
npx wrangler dev --port 8788
# → http://localhost:8788/myip
```

### Deploy to your domain

1. **Create KV namespace** (one-time, for `/short`, `/paste`):
   ```bash
   wrangler kv namespace create SHORT_KV
   ```
   Copy the returned `id` into `wrangler.jsonc` → `kv_namespaces[0].id`.

2. **Edit `wrangler.jsonc`** — uncomment + fill in `routes`:
   ```jsonc
   "routes": [
     { "pattern": "cfbox.YOUR-DOMAIN.com/*", "zone_name": "YOUR-DOMAIN.com" }
   ]
   ```

3. **DNS**: in CF dashboard or via API, add a `proxied` A record:
   ```
   cfbox.YOUR-DOMAIN.com  A  192.0.2.1  (proxied)
   ```

4. **Deploy**:
   ```bash
   npx wrangler deploy
   ```

5. Hit `https://cfbox.YOUR-DOMAIN.com/myip` — JSON response.

---

## Adding a new service

Three mechanical edits in `src/`:

1. Create `src/services/<name>.ts` exporting a `Service`:
   ```typescript
   import type { Service } from '../types';
   export const foo: Service = {
     meta: { name: 'foo', path: '/foo', desc: { en: '...', cn: '...' } },
     fetch: async (req, env, ctx) => { /* ... */ },
   };
   ```

2. Add to `src/registry.ts`:
   ```typescript
   import { foo } from './services/foo';
   export const registry: Record<string, Service> = {
     // ...
     foo,
   };
   ```

3. `npx wrangler dev` → test → `npx wrangler deploy`.

⚠️ **Signature gotcha**: the `Service.fetch` is `(req, env, ctx)` — second param is the binding object, NOT a URL. Construct URL from `req.url` inside the function:
```typescript
fetch: async (req, env, ctx) => {
  const u = new URL(req.url);  // ← required, every time
  // use u.searchParams, env.<binding>, ctx.waitUntil
}
```
Writing `(req, u) =>` binding `u` to env silently fails with `error code: 1101` ("cannot read properties of undefined").

---

## Architecture (locked decisions)

- **Single Worker** + static service registry (Pattern A). No multi-Worker split until quota pain.
- **Free tier**: 100,000 req/day per CF account, 10ms CPU/invocation, 3 MB bundle size.
- **Single catch-all DNS route**: `cfbox.<domain>/*` → one Worker. No N-route fan-out.
- **Migration to multi-Worker** later = change `src/registry.ts` only. Call site unchanged.

See [`mneme/cfbox-design/design.md`](https://github.com/ljh-sh/mneme/tree/main/cfbox-design/design.md) for trade-offs.

---

## Deployment paths (three trust tiers)

Same code; pick by what you want to keep private:

| Path | Auth | Trust boundary | Cost |
|---|---|---|---|
| **Hub relay** (x-cmd) | Pubkey at hub; hub relays | Hub sees metadata live; audit logs are post-hoc | Free |
| **Self-host + email 2FA** | Pubkey + email OTP | Email provider sees logins | Email service cost |
| **Self-host + password/key** | Symmetric pass or Ed25519 sig, fully local | **No third party**; no email needed | Just CF account |

Hub-relay audit logging is *after the fact* — doesn't prevent key theft mid-flight. For sensitive data, self-host.

---

## License

MIT. See `LICENSE`.

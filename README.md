# worker_doh

A zero-dependency [Cloudflare Workers](https://workers.cloudflare.com) DNS-over-HTTPS relay (RFC 8484) with edge caching, automatic fastest-upstream selection, and AdGuard-Home-style domain filtering. All user configuration travels **in the request URL** — the worker stores nothing on the server.

## Features

- **RFC 8484 wire format** — `GET /dns-query?dns=<base64url>` and `POST` with `application/dns-message`; EDNS and message compression handled by a small built-in DNS codec.
- **JSON debug API** — RFC 8427-style `GET /?name=example.com&type=A` for quick inspection from a browser.
- **Edge caching** — responses cached in `caches.default`; cache keys are partitioned per configuration set, so filtered and unfiltered queries never cross-contaminate.
- **Fastest upstream wins** — upstream DoH endpoints are raced; the fastest responder stays sticky until it degrades.
- **AdGuard-Home-style filtering** — block, allow-list exceptions, fixed-IP overrides, and remote filter subscriptions, in env vars or per request.
- **Stateless config model** — a config page generates a DoH URL carrying every option as query params; paste it into your client and you're done.
- **SSRF-hardened** — user-supplied `up`/`list` URLs must be https public hosts; embedded query strings, IP literals, localhost and private TLDs are rejected.

## Quick start

```sh
npm install
npm run dev            # wrangler dev on http://localhost:8787
```

```sh
# JSON debug API
curl "http://localhost:8787/?name=example.com&type=A"

# RFC 8484 wire format
curl -H 'accept: application/dns-message' --output query.dns \
  "http://localhost:8787/dns-query?dns=AAEBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
```

Deploy with `npx wrangler deploy` (requires a Cloudflare account; see [Wrangler docs](https://developers.cloudflare.com/workers/wrangler/)).

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Config page — builds your personal DoH URL, no server-side state |
| `GET/POST /dns-query` | DoH wire format (RFC 8484) |
| `GET /?name=&type=` | JSON debug API |
| `GET/POST /p/<base64url>` | Config encoded in the path (no plaintext domains in the URL) |

## Configuration

### Deploy-time (`wrangler.jsonc` vars)

| Var | Default | Meaning |
|---|---|---|
| `UPSTREAM_DOH` | CF / Google / AliDNS | Comma-separated upstream DoH endpoints (raced) |
| `UPSTREAM_REGIONS` | — | Region-specific upstreams: `CODE=url[,url];CODE=url…` (see below) |
| `BLOCK_DOMAINS` | — | Comma/space-separated blocked domains (suffix match) |
| `ALLOW_DOMAINS` | — | Exception domains that override blocks |
| `BLOCKLIST_URL` | — | Comma-separated remote filter URLs, refreshed every 6 h |
| `UPSTREAM_TIMEOUT_MS` | `5000` | Per-attempt upstream race timeout |
| `STICKY_TTL_MS` | `300000` | How long the fastest upstream stays selected |

**Region-based selection**: `UPSTREAM_REGIONS` maps Cloudflare's client-IP geolocation (`cf.country` / `cf.continent`) to upstream lists, e.g. `JP=https://public.dns.iij.jp/dns-query;AS=https://dns.alidns.com/dns-query`. Match order: per-request `up=` > country code > continent code (`AF/AS/EU/NA/OC/SA`) > global `UPSTREAM_DOH`. Two-letter codes are tried as a country first, so `NA=` serves both Namibia and North America. Each matched region bucket gets its own sticky winner and its own edge-cache partition, so region choices never cross-contaminate.

### Per-request URL params

| Param | Meaning |
|---|---|
| `block=a.com,b.net` | Blocked domains, union with env |
| `allow=b.net` | Allow-list exceptions |
| `host=router.home/192.168.1.1` | Fixed A answers (also newline-separated in the page) |
| `up=https://…` | Per-request upstream list (≤ 8), replaces the default |
| `list=https://…` | Remote filter subscriptions (≤ 4), cached 10 min |

Request params and env vars merge as a **union** — requests without params behave exactly like a plain deployment.

**Precedence:** `allow` > fixed `host` > `block` > upstream resolution. An exception at any parent level (`@@||example.com^`) lets through everything below it, including fixed-IP overrides.

### Filter rule syntax

Remote subscriptions (`BLOCKLIST_URL`, `list=`) accept a domain-level subset of the AdGuard / hosts / dnsmasq syntax:

```text
||ads.example.com^         # block (suffix match: sub.ads.example.com too)
*.wild.example.com         # block (wildcard)
@@||cdn.example.com^       # allow exception — beats block and fixed IP
0.0.0.0 tracker.com        # block (hosts file)
192.168.1.9 nas.home       # answer A 192.168.1.9 (hosts file)
address=/fix.example/5.6.7.8   # answer A (dnsmasq)
```

> [!NOTE]
> Full-regex rules (`~…`), ABP `$`-modifier filters, and cosmetic (`##`) rules are skipped — filtering happens at the DNS layer only.

## Privacy & security

> [!WARNING]
> Configuration travels as **plaintext URL params** and the endpoint has **no authentication**. Anyone who sees the URL can see and reuse your blocked domains, pinned hosts, and subscriptions. Use the `/p/<base64url>` form to keep domains out of logs (it encodes, it does not encrypt), or keep private domains in deploy-time env vars.

Upstream forwarding carries only the DNS question itself (`name`, `type`, DNSSEC `do`) — config params are never leaked to third-party upstreams. Client identity inside the query is scrubbed before it leaves the edge (always on, zero config):

- **EDNS Client Subnet is coarsened** to the client's `/8` (IPv4) or `/32` (IPv6) region block — upstreams still geo-point to the right region, but can no longer locate the client's `/24`.
- **Tracking options are stripped**: EDNS Client/Server Cookie, Padding (size fingerprinting) and Client Tag never reach upstreams.
- **Query IDs are randomized** toward upstreams and restamped to the client's original ID on the way back (this also fixes cached replies being served with a foreign ID).

## Development

| Command | What |
|---|---|
| `npm run dev` | Local worker on `:8787` with hot reload |
| `npm test` | Unit tests (DNS codec, rule parser, opts validation) |
| `npm run typecheck` | `tsc --noEmit` |

```text
src/
  index.ts     routing, edge cache, JSON & wire handlers
  dnsmsg.ts    DNS message encode/decode (labels, pointers, EDNS)
  opts.ts      per-request params: parse, validate, canonical hash
  rules.ts     rule parser (adblock/hosts/dnsmasq), matching, caches
  upstream.ts  upstream racing, sticky selection, inflight dedupe
  page.ts      inline config page (no build step)
```

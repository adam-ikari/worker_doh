import { buildReply, minAnswerTtl, parseQuestion, RCODE_NXDOMAIN, isStandardQuery, typeName } from "./dnsmsg";
import { getRules, isBlocked, lookupHost } from "./rules";
import { resolveJson, resolveWire, UpstreamError } from "./upstream";
import type { Env } from "./types";

const CT_WIRE = "application/dns-message";
const CT_JSON = "application/dns-json";
const MAX_QUERY_BYTES = 32768 + 12; // wire query cap
const BLOCK_TTL = 60; // edge-cache TTL for rule-generated replies
const HOSTS_TTL = 300; // TTL served for hosts-file A answers
const URL_TTL_CEILING = 86400;

const CORS = {
	"access-control-allow-origin": "*",
	"access-control-allow-methods": "GET, POST, OPTIONS",
	"access-control-allow-headers": "content-type",
};

export default {
	async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (req.method === "OPTIONS") {
			return new Response(null, { status: 204, headers: CORS });
		}
		if (req.method !== "GET" && req.method !== "POST") {
			return text("method not allowed", 405);
		}

		const url = new URL(req.url);
		const cache = (caches as unknown as { default: Cache }).default;

		try {
			// JSON API (debug/CORS): GET /?name=example.com&type=A
			if (req.method === "GET" && !url.searchParams.has("dns") && url.searchParams.has("name")) {
				return await handleJson(env, url);
			}
			if (req.method === "GET" && !url.searchParams.has("dns") && (url.pathname === "/" || url.pathname === "")) {
				return landing(url);
			}

			const query = await readQuery(req, url);
			if (!query) {
				return text(
					"expected a DNS question: GET ?dns=<base64url> or POST application/dns-message",
					400,
				);
			}
			if (!isStandardQuery(query)) {
				return text("not a standard DNS query", 400);
			}
			const q = parseQuestion(query);
			if (!q || query.byteLength > MAX_QUERY_BYTES) {
				return text("unsupported DNS query", 400);
			}
			const cacheKey = new Request(
				`https://${url.host}/_doh_cache/${q.name}/t${q.type}`,
				{ method: "GET" },
			);

			// ---- custom rules (always authoritative, but edge-cacheable briefly) ----
			const rules = await getRules(env);
			if (isBlocked(rules, q.name)) {
				return wireReply(ctx, cacheKey, buildReply(query, { rcode: RCODE_NXDOMAIN }), BLOCK_TTL);
			}
			if (q.type === 1) {
				const ip = lookupHost(rules, q.name);
				if (ip) {
					return wireReply(ctx, cacheKey, buildReply(query, { a: [{ ip }], ttl: HOSTS_TTL }), HOSTS_TTL);
				}
			}

			// ---- edge cache per RFC 8484 §5.1 (HTTP cache informed by DNS TTL) ----
			const cached = await cache.match(cacheKey);
			if (cached) return cached;

			const out = await resolveWire(env, query, `${q.name}/${q.type}`);
			const minTtl = minAnswerTtl(new Uint8Array(out.body));
			const ttl = minTtl === null ? 0 : Math.min(minTtl, URL_TTL_CEILING);

			return wireReply(ctx, cacheKey, new Uint8Array(out.body), ttl);
		} catch (err) {
			if (err instanceof UpstreamError) {
				return text("upstream DNS servers unavailable", 502);
			}
			console.error(`doh error: ${err}`);
			return text("internal error", 500);
		}
	},
} satisfies ExportedHandler<Env>;

async function readQuery(req: Request, url: URL): Promise<Uint8Array | null> {
	if (req.method === "POST") {
		const ct = req.headers.get("content-type") ?? "";
		if (!ct.includes(CT_WIRE)) return null;
		const buf = await req.arrayBuffer();
		if (buf.byteLength === 0 || buf.byteLength > MAX_QUERY_BYTES) return null;
		return new Uint8Array(buf);
	}
	const dnsParam = url.searchParams.get("dns");
	if (dnsParam === null) return null;
	return b64urlDecode(dnsParam);
}

function b64urlDecode(s: string): Uint8Array | null {
	try {
		let b = s.replace(/-/g, "+").replace(/_/g, "/");
		while (b.length % 4) b += "=";
		const bin = atob(b);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	} catch {
		return null;
	}
}

/** Serve a wire-format reply and let the edge cache serve it for `ttl` seconds. */
function wireReply(
	ctx: ExecutionContext,
	cacheKey: Request,
	msg: Uint8Array,
	ttl: number,
): Response {
	const res = new Response(msg as unknown as BodyInit, {
		status: 200,
		headers: new Headers({
			"content-type": CT_WIRE,
			"cache-control": ttl > 0 ? `max-age=${ttl}` : "no-store",
			...CORS,
		}),
	});
	if (ttl > 0) {
		// put a clone: a Response body can only be consumed once
		ctx.waitUntil(cachePut(cacheKey, res.clone()));
	}
	return res;
}

async function cachePut(key: Request, res: Response): Promise<void> {
	try {
		const cache = (caches as unknown as { default: Cache }).default;
		await cache.put(key, res);
	} catch (err) {
		console.warn(`cache.put failed: ${err}`);
	}
}

async function handleJson(env: Env, url: URL): Promise<Response> {
	const name = (url.searchParams.get("name") ?? "").toLowerCase().replace(/\.+$/, "");
	if (!/^[a-z0-9._-]+$/.test(name)) return text("bad name", 400);
	const params = new URLSearchParams(url.searchParams);
	params.set("name", name);
	const typeStr = typeNameOf(params);

	const rules = await getRules(env);
	if (isBlocked(rules, name)) {
		return jsonResponse({ Status: RCODE_NXDOMAIN, Question: [{ name, type: typeStr }] });
	}
	if (typeStr === "A") {
		const ip = lookupHost(rules, name);
		if (ip) {
			return jsonResponse({
				Status: 0,
				Question: [{ name, type: 1 }],
				Answer: [{ name, type: 1, TTL: 300, data: ip }],
			});
		}
	}

	const out = await resolveJson(env, params);
	let body: Record<string, unknown>;
	try {
		body = JSON.parse(new TextDecoder().decode(out.body)) as Record<string, unknown>;
	} catch {
		return text("bad upstream JSON", 502);
	}

	const json = body as { Status?: number; Answer?: Array<{ TTL?: number }> };
	const ttl = json.Answer?.reduce((m, a) => Math.min(m, a.TTL ?? 0), Infinity);
	const maxAge = Number.isFinite(ttl) ? Math.min(ttl as number, 86400) : 0;

	const res = new Response(JSON.stringify(json), {
		status: 200,
		headers: new Headers({
			"content-type": CT_JSON,
			"cache-control": maxAge > 0 ? `max-age=${maxAge}` : "no-store",
			...CORS,
		}),
	});
	return res;
}

function typeNameOf(params: URLSearchParams): string {
	const t = params.get("type");
	if (!t || t === "") return "A";
	if (/^\d+$/.test(t)) return typeName(Number(t));
	return t.toUpperCase();
}

function jsonResponse(obj: Record<string, unknown>): Response {
	return new Response(JSON.stringify(obj), {
		status: 200,
		headers: new Headers({
			"content-type": CT_JSON,
			"cache-control": "no-store",
			...CORS,
		}),
	});
}

function landing(url: URL): Response {
	const host = url.host;
	const html = `<!doctype html><meta charset=utf-8><title>DoH relay</title>
<body style="font-family:system-ui;max-width:46rem;margin:3rem auto;line-height:1.6">
<h1>DNS-over-HTTPS relay</h1>
<p>RFC 8484 DoH endpoint with edge caching, fastest-upstream auto selection and custom block/hosts rules.</p>
<ul>
<li><b>Wire format:</b> <code>GET https://${host}/dns-query?dns=&lt;base64url&gt;</code> or
<code>POST https://${host}/dns-query</code> (Content-Type: application/dns-message)</li>
<li><b>JSON (debug):</b> <code>GET https://${host}/?name=example.com&amp;type=A</code></li>
</ul>
<p>Point clients at <code>https://${host}/dns-query</code> — e.g. browser secure DNS, or
<code>dig @${host}</code> with <code>+https</code> via <code>--doh-url</code>.</p>
</body>`;
	return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8", ...CORS } });
}

function text(msg: string, status: number): Response {
	return new Response(msg, { status, headers: { "content-type": "text/plain;charset=UTF-8", ...CORS } });
}

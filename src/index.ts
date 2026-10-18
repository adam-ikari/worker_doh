import { buildReply, minAnswerTtl, parseQuestion, RCODE_NXDOMAIN, isStandardQuery, typeName } from "./dnsmsg";
import { getRules, getRulesFor, isBlocked, lookupHost } from "./rules";
import { resolveJson, resolveWire, UpstreamError } from "./upstream";
import { hasOpts, optsHash, parseOpts, type RequestOpts } from "./opts";
import { configPage } from "./page";
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

		// /p/<b64url> carries "?block=..." (and optionally the wire query) in the path
		const path = decodePath(url.pathname);
		const sp = path ? path.sp : url.searchParams;
		const parsed = parseOpts(sp);
		if (!parsed.ok) {
			return text(`bad config parameter — ${parsed.error}`, 400);
		}
		const opts: RequestOpts = parsed.opts;

		try {
			// JSON API (debug/CORS): GET /?name=example.com&type=A
			if (req.method === "GET" && sp.has("name")) {
				return await handleJson(env, url, sp, opts);
			}
			if (req.method === "GET" && !sp.has("dns") && (url.pathname === "/" || url.pathname === "")) {
				return configPage(url);
			}

			const query = await readQuery(req, url, path);
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
			const hash = hasOpts(opts) ? `/${await optsHash(opts)}` : "";
			const cacheKey = new Request(
				`https://${url.host}/_doh_cache/${q.name}/t${q.type}${hash}`,
				{ method: "GET" },
			);

			// ---- custom rules (always authoritative, but edge-cacheable briefly) ----
			const rules = hasOpts(opts)
				? await getRulesFor(env, opts)
				: await getRules(env);
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

			// dedupe key carries the config hash: a plain query must never share
			// an in-flight filtered result (or vice versa)
			const out = await resolveWire(
				env,
				query,
				`${q.name}/${q.type}${hash}`,
				hasOpts(opts) ? opts : undefined,
			);
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

interface PathInfo {
	/** config query params carried in the path ("" → empty) */
	sp: URLSearchParams;
	/** wire query bytes carried in the path, if any */
	query: Uint8Array | null;
}

/**
 * Decode `/p/<b64url>`. The payload is either "?<config>" (config only; query
 * comes from ?dns= or the POST body), or "<b64wire>|<config>" with the wire
 * DNS query first ("|" separator — "?" and "&" are eaten by the URL layer).
 */
function decodePath(pathname: string): PathInfo | null {
	if (!pathname.startsWith("/p/")) return null;
	const rest = decodeURIComponent(pathname.slice(3));
	const seg = b64urlDecode(rest);
	if (!seg) return null;
	const text = new TextDecoder().decode(seg);
	const bar = text.indexOf("|");
	if (bar > 0) {
		const wire = b64urlDecode(text.slice(0, bar));
		let cfg = text.slice(bar + 1);
		if (cfg.startsWith("?")) cfg = cfg.slice(1);
		return { sp: new URLSearchParams(cfg), query: wire };
	}
	return { sp: new URLSearchParams(text.startsWith("?") ? text.slice(1) : text), query: null };
}

async function readQuery(
	req: Request,
	url: URL,
	path: PathInfo | null,
): Promise<Uint8Array | null> {
	if (path?.query) return path.query;
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

async function handleJson(env: Env, url: URL, sp: URLSearchParams, opts: RequestOpts): Promise<Response> {
	const name = (sp.get("name") ?? "").toLowerCase().replace(/\.+$/, "");
	if (!/^[a-z0-9._-]+$/.test(name)) return text("bad name", 400);
	// forward only the DNS question — block/host/up/list are private config and
	// must not leak to third-party upstreams
	const params = new URLSearchParams();
	for (const k of ["type", "do", "edns_client_subnet"]) {
		const v = sp.get(k);
		if (v !== null) params.set(k, v);
	}
	params.set("name", name);
	const typeStr = typeNameOf(params);

	const rules = hasOpts(opts) ? await getRulesFor(env, opts) : await getRules(env);
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

	const out = await resolveJson(env, params, hasOpts(opts) ? opts : undefined);
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

function text(msg: string, status: number): Response {
	return new Response(msg, { status, headers: { "content-type": "text/plain;charset=UTF-8", ...CORS } });
}

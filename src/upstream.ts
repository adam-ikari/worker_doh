/**
 * Upstream DoH selection: forwards each query to the configured upstreams and
 * automatically keeps using the one that answers fastest.
 *
 * Strategy:
 *  - cache miss -> race all upstreams concurrently, first valid response wins
 *  - the winner is remembered ("sticky") per region bucket for STICKY_TTL_MS
 *    and tried alone first on subsequent queries from that bucket, with a
 *    short timeout — falls back to a full race on timeout/failure. This keeps
 *    answers from flapping between resolvers' different CDN viewpoints while
 *    still recovering quickly.
 *  - identical in-flight queries are deduped per isolate.
 */

import type { Env } from "./types";
import type { RequestOpts } from "./opts";

export interface UpstreamResult {
	status: number;
	contentType: string;
	body: ArrayBuffer;
	upstream: string;
}

export class UpstreamError extends Error {}

const DEFAULT_UPSTREAMS = [
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
	"https://dns.alidns.com/dns-query",
];

/**
 * Region-based upstream selection (deploy-time env only):
 * `UPSTREAM_REGIONS="JP=https://a/dns-query,https://b/dns-query;AS=https://c/dns-query"`
 * Match order: per-request `up=` > client country (cf.country) > client
 * continent (cf.continent) > global UPSTREAM_DOH > built-in defaults.
 * Two-letter codes are looked up as a country first, so e.g. "NA" serves both
 * Namibia (country) and North America (continent fallback).
 */
export interface ClientRegion {
	country?: string;
	continent?: string;
}

export interface RegionSel {
	list: string[];
	/** cache/sticky partition tag: "" (feature off / custom up), "cXX", "kXX", "g" */
	bucket: string;
}

function globalList(env: Env): string[] {
	const list = (env.UPSTREAM_DOH ?? "")
		.split(/[\s,]+/)
		.map((s) => s.trim())
		.filter(Boolean);
	if (list.length === 0) list.push(...DEFAULT_UPSTREAMS);
	return list;
}

let regionsMemo: { raw: string; map: Map<string, string[]> } | null = null;

function parseRegions(raw: string): Map<string, string[]> {
	if (regionsMemo && regionsMemo.raw === raw) return regionsMemo.map;
	const map = new Map<string, string[]>();
	for (const group of raw.split(";")) {
		const eq = group.indexOf("=");
		if (eq <= 0) continue;
		const code = group.slice(0, eq).trim().toUpperCase();
		const urls = group
			.slice(eq + 1)
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
		if (/^[A-Z]{2}$/.test(code) && urls.length > 0) map.set(code, urls);
	}
	regionsMemo = { raw, map };
	return map;
}

export function regionFor(env: Env, opts?: RequestOpts, cf?: ClientRegion): RegionSel {
	if (opts && opts.up.length > 0) return { list: opts.up, bucket: "" };
	const raw = (env.UPSTREAM_REGIONS ?? "").trim();
	if (raw) {
		const map = parseRegions(raw);
		const country = (cf?.country ?? "").toUpperCase();
		const continent = (cf?.continent ?? "").toUpperCase();
		if (country && map.has(country)) return { list: map.get(country)!, bucket: "c" + country };
		if (continent && map.has(continent)) return { list: map.get(continent)!, bucket: "k" + continent };
		return { list: globalList(env), bucket: "g" };
	}
	return { list: globalList(env), bucket: "" };
}

function timeout(ms: number): { signal: AbortSignal; clear: () => void } {
	const ac = new AbortController();
	const t = setTimeout(() => ac.abort(), ms);
	return { signal: ac.signal, clear: () => clearTimeout(t) };
}

function numEnv(v: string | undefined, dflt: number): number {
	const n = Number(v);
	return Number.isFinite(n) && n > 0 ? n : dflt;
}

const STICKY_TTL_MS_DEFAULT = 5 * 60 * 1000;
const FULL_TIMEOUT_MS_DEFAULT = 5000;
const STICKY_TIMEOUT_MS = 1500;

interface Sticky {
	url: string;
	until: number;
}
/** one sticky winner per region bucket — a CN winner must not serve JP clients */
const sticky = new Map<string, Sticky>();

const inflight = new Map<string, Promise<UpstreamResult>>();

interface WireOpts {
	method: "POST" | "GET";
}

async function fetchWire(
	url: string,
	query: Uint8Array,
	timeoutMs: number,
	opts: WireOpts,
): Promise<UpstreamResult | null> {
	const { signal, clear } = timeout(timeoutMs);
	try {
		let res: Response;
		if (opts.method === "POST") {
			res = await fetch(url, {
				method: "POST",
				headers: { accept: "application/dns-message", "content-type": "application/dns-message" },
				body: query as unknown as BodyInit,
				signal,
			});
		} else {
			const u = new URL(url);
			u.searchParams.set("dns", b64url(query));
			res = await fetch(u, {
				headers: { accept: "application/dns-message" },
				signal,
			});
		}
		if (!res.ok) return null;
		const body = await res.arrayBuffer();
		// must look like a DNS response echoing the query id
		if (body.byteLength < 12) return null;
		const u8 = new Uint8Array(body);
		if (u8[0] !== query[0] || u8[1] !== query[1]) return null;
		if ((u8[2] & 0x80) === 0) return null; // not a response
		return { status: res.status, contentType: "application/dns-message", body, upstream: url };
	} catch {
		return null;
	} finally {
		clear();
	}
}

function b64url(bytes: Uint8Array): string {
	let bin = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
	}
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function raceWire(
	env: Env,
	query: Uint8Array,
	sel: RegionSel,
	customUp: boolean,
): Promise<UpstreamResult> {
	const totalMs = numEnv(env.UPSTREAM_TIMEOUT_MS, FULL_TIMEOUT_MS_DEFAULT);
	const attempts = sel.list.map(async (url) => {
		const viaPost = await fetchWire(url, query, totalMs, { method: "POST" });
		if (viaPost) return viaPost;
		// some RFC 8484 servers are GET-only in practice
		return fetchWire(url, query, totalMs, { method: "GET" });
	});
	const results = await Promise.allSettled(attempts);
	for (const r of results) {
		if (r.status === "fulfilled" && r.value) {
			if (!customUp) {
				sticky.set(sel.bucket, {
					url: r.value.upstream,
					until: Date.now() + numEnv(env.STICKY_TTL_MS, STICKY_TTL_MS_DEFAULT),
				});
			}
			return r.value;
		}
	}
	throw new UpstreamError("all upstream DoH servers failed");
}

/**
 * Resolve a wire-format query upstream. `key` is "<qname>/<qtype>/<region+opts
 * tags>" and used to dedupe identical concurrent queries from this isolate.
 */
export async function resolveWire(
	env: Env,
	query: Uint8Array,
	key: string,
	opts: RequestOpts | undefined,
	sel: RegionSel,
): Promise<UpstreamResult> {
	const customUp = !!opts && opts.up.length > 0;
	const pending = inflight.get(key);
	if (pending) return pending;

	const p = (async (): Promise<UpstreamResult> => {
		// a caller-supplied upstream list is used as-is, never via the sticky pick
		const fast = sticky.get(sel.bucket);
		if (!customUp && fast && Date.now() < fast.until) {
			const viaFast = await fetchWire(fast.url, query, STICKY_TIMEOUT_MS, { method: "POST" });
			if (viaFast) return viaFast;
			sticky.delete(sel.bucket); // current winner is slow down -> re-race
		}
		return raceWire(env, query, sel, customUp);
	})().finally(() => inflight.delete(key));

	inflight.set(key, p);
	return p;
}

/**
 * Forward a DNS-JSON (RFC 8427 style) request: `params` carries name/type.
 * No sticky track here — JSON is a debugging/CORS path.
 */
export async function resolveJson(
	env: Env,
	params: URLSearchParams,
	sel: RegionSel,
): Promise<UpstreamResult> {
	const totalMs = numEnv(env.UPSTREAM_TIMEOUT_MS, FULL_TIMEOUT_MS_DEFAULT);
	const attempts = sel.list.map(async (base) => {
		// Google-style servers expose the JSON API at /resolve, not /dns-query
		const u = new URL(base);
		if (/\/dns-query\/?$/.test(u.pathname)) u.pathname = "/resolve";
		u.search = "";
		for (const [k, v] of params) u.searchParams.append(k, v);
		const url = u.toString();
		const { signal, clear } = timeout(totalMs);
		try {
			const res = await fetch(url, {
				headers: { accept: "application/dns-json" },
				signal,
			});
			const ct = res.headers.get("content-type") ?? "";
			if (!res.ok || !ct.includes("json")) return null;
			const body = await res.arrayBuffer();
			return { status: res.status, contentType: ct, body, upstream: url };
		} catch {
			return null;
		} finally {
			clear();
		}
	});
	const results = await Promise.allSettled(attempts);
	for (const r of results) {
		if (r.status === "fulfilled" && r.value) return r.value;
	}
	throw new UpstreamError("all upstream DoH servers failed");
}

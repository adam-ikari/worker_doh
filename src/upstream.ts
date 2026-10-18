/**
 * Upstream DoH selection: forwards each query to the configured upstreams and
 * automatically keeps using the one that answers fastest.
 *
 * Strategy:
 *  - cache miss -> race all upstreams concurrently, first valid response wins
 *  - the winner is remembered ("sticky") for STICKY_TTL_MS and tried alone
 *    first on subsequent queries, with a short timeout — falls back to a full
 *    race on timeout/failure. This keeps answers from flapping between
 *    resolvers' different CDN viewpoints while still recovering quickly.
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

function upstreamList(env: Env, opts?: RequestOpts): string[] {
	if (opts && opts.up.length > 0) return opts.up; // validated by parseOpts
	const list = (env.UPSTREAM_DOH ?? "")
		.split(/[\s,]+/)
		.map((s) => s.trim())
		.filter(Boolean);
	if (list.length === 0) list.push(...DEFAULT_UPSTREAMS);
	return list;
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
let sticky: Sticky | null = null;

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
	opts?: RequestOpts,
): Promise<UpstreamResult> {
	const totalMs = numEnv(env.UPSTREAM_TIMEOUT_MS, FULL_TIMEOUT_MS_DEFAULT);
	const stickyAllowed = !opts || opts.up.length === 0;
	const attempts = upstreamList(env, opts).map(async (url) => {
		const viaPost = await fetchWire(url, query, totalMs, { method: "POST" });
		if (viaPost) return viaPost;
		// some RFC 8484 servers are GET-only in practice
		return fetchWire(url, query, totalMs, { method: "GET" });
	});
	const results = await Promise.allSettled(attempts);
	for (const r of results) {
		if (r.status === "fulfilled" && r.value) {
			if (stickyAllowed) {
				sticky = { url: r.value.upstream, until: Date.now() + numEnv(env.STICKY_TTL_MS, STICKY_TTL_MS_DEFAULT) };
			}
			return r.value;
		}
	}
	throw new UpstreamError("all upstream DoH servers failed");
}

/**
 * Resolve a wire-format query upstream. `key` is "<qname>/<qtype>" and used
 * to dedupe identical concurrent queries from this isolate.
 */
export async function resolveWire(
	env: Env,
	query: Uint8Array,
	key: string,
	opts?: RequestOpts,
): Promise<UpstreamResult> {
	const customUp = !!opts && opts.up.length > 0;
	const pending = inflight.get(key);
	if (pending) return pending;

	const p = (async (): Promise<UpstreamResult> => {
		// a caller-supplied upstream list is used as-is, never via the sticky pick
		if (!customUp && sticky && Date.now() < sticky.until) {
			const fast = await fetchWire(sticky.url, query, STICKY_TIMEOUT_MS, { method: "POST" });
			if (fast) return fast;
			sticky = null; // current winner is slow down -> re-race
		}
		return raceWire(env, query, opts);
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
	opts?: RequestOpts,
): Promise<UpstreamResult> {
	const totalMs = numEnv(env.UPSTREAM_TIMEOUT_MS, FULL_TIMEOUT_MS_DEFAULT);
	const attempts = upstreamList(env, opts).map(async (base) => {
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

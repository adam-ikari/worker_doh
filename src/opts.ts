/**
 * Per-request configuration carried in the DoH URL's query string.
 *
 * The whole config model here is stateless: a client's rules live in the URL
 * it points its resolver at. Params (parsed by `parseOpts`, encoded by
 * `optsToParams` — one codec for both sides):
 *
 *   block=ads.x,tracker.y          domains answered NXDOMAIN (suffix match)
 *   host=home.lan/192.168.1.5,...  fixed A answers
 *   up=https://dns.google/dns-query,...  upstream override (else env/default)
 *   list=https://.../hosts         extra blocklist URL (adblock/hosts/dnsmasq)
 *
 * There is no authentication, so anything that makes the worker fetch a
 * URL is validated hard: https only, no IP literals, no localhost/private
 * names, entry caps. This limits (not eliminates) the SSRF/amplification
 * surface — see the decision page in the brain.
 */

export interface RequestOpts {
	block: string[];
	hosts: Map<string, string>;
	up: string[];
	list: string[];
}

export type OptsResult = { ok: true; opts: RequestOpts } | { ok: false; error: string };

const DOMAIN_RE = /^[a-z0-9._-]+$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const MAX_UP = 8;
const MAX_LIST = 4;
const MAX_BLOCK = 200;
const MAX_HOSTS = 100;
/** Hostnames the worker must never be told to contact. */
const BAD_TLDS = new Set(["local", "internal", "localhost", "home", "lan", "localdomain", "test", "intranet"]);

function normDomain(s: string): string | null {
	const d = s.trim().toLowerCase().replace(/\.+$/, "");
	if (!d || !DOMAIN_RE.test(d) || d.startsWith(".") || d.startsWith("-")) return null;
	return d;
}

function checkUrl(s: string, what: string): string | null {
	let u: URL;
	try {
		u = new URL(s);
	} catch {
		return `${what}: not a URL: ${s}`;
	}
	if (u.protocol !== "https:") return `${what}: https only: ${s}`;
	const h = u.hostname.toLowerCase().replace(/\.+$/, "");
	if (IPV4_RE.test(h) || u.hostname.includes("[")) return `${what}: IP literals not allowed: ${s}`;
	if (h === "localhost" || BAD_TLDS.has(h.split(".").pop() ?? "")) {
		return `${what}: private/localhost name not allowed: ${s}`;
	}
	// our own query params get appended with &/? — a URL that already carries
	// a query would let the caller redirect the request to an arbitrary path
	if (u.search || u.hash) return `${what}: URL must not carry query/hash: ${s}`;
	return null;
}

export function parseOpts(sp: URLSearchParams): OptsResult {
	const opts: RequestOpts = { block: [], hosts: new Map(), up: [], list: [] };

	for (const raw of splitList(sp.get("block"))) {
		const d = normDomain(raw);
		if (!d) return err(`block: bad domain: ${raw}`);
		opts.block.push(d);
	}

	for (const raw of splitList(sp.get("host"))) {
		const slash = raw.lastIndexOf("/");
		if (slash <= 0) return err(`host: expected domain/ip: ${raw}`);
		const d = normDomain(raw.slice(0, slash));
		const ip = raw.slice(slash + 1).trim();
		if (!d) return err(`host: bad domain: ${raw}`);
		if (!IPV4_RE.test(ip) || !ip.split(".").every((p) => Number(p) <= 255)) {
			return err(`host: bad IPv4: ${ip}`);
		}
		opts.hosts.set(d, ip);
	}

	const ups = splitList(sp.get("up"));
	for (const s of ups) {
		const e = checkUrl(s, "up");
		if (e) return err(e);
		opts.up.push(s);
	}
	const lists = splitList(sp.get("list"));
	for (const s of lists) {
		const e = checkUrl(s, "list");
		if (e) return err(e);
		opts.list.push(s);
	}

	if (ups.length > MAX_UP) return err(`up: too many entries (max ${MAX_UP})`);
	if (lists.length > MAX_LIST) return err(`list: too many entries (max ${MAX_LIST})`);
	if (opts.block.length > MAX_BLOCK) return err(`block: too many entries (max ${MAX_BLOCK})`);
	if (opts.hosts.size > MAX_HOSTS) return err(`host: too many entries (max ${MAX_HOSTS})`);

	return { ok: true, opts };
}

function splitList(v: string | null): string[] {
	if (!v) return [];
	return v.split(",").map((s) => s.trim()).filter(Boolean);
}

function err(error: string): OptsResult {
	return { ok: false, error };
}

export function hasOpts(o: RequestOpts): boolean {
	return o.block.length > 0 || o.hosts.size > 0 || o.up.length > 0 || o.list.length > 0;
}

/** Stable, order-insensitive encoding — same config always yields same string. */
export function canonicalOpts(o: RequestOpts): string {
	const parts: string[] = [];
	if (o.block.length) parts.push(`b=${[...new Set(o.block)].sort().join(",")}`);
	if (o.hosts.size) parts.push(`h=${[...o.hosts.entries()].sort().map(([d, i]) => `${d}/${i}`).join(",")}`);
	if (o.up.length) parts.push(`u=${[...new Set(o.up)].sort().join(",")}`);
	if (o.list.length) parts.push(`l=${[...new Set(o.list)].sort().join(",")}`);
	return parts.join("&");
}

/** 8-hex digest of the canonical opts, for cache-key partitioning. Async for portability. */
export async function optsHash(o: RequestOpts): Promise<string> {
	const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalOpts(o)));
	return [...new Uint8Array(buf).slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function optsToParams(o: RequestOpts): URLSearchParams {
	const sp = new URLSearchParams();
	if (o.block.length) sp.set("block", [...o.block].sort().join(","));
	if (o.hosts.size) sp.set("host", [...o.hosts.entries()].sort().map(([d, i]) => `${d}/${i}`).join(","));
	if (o.up.length) sp.set("up", [...o.up].sort().join(","));
	if (o.list.length) sp.set("list", [...o.list].sort().join(","));
	return sp;
}

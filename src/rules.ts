/**
 * Custom rules: block domains and/or override them with fixed IPs.
 *
 * Sources (merged):
 *  - BLOCK_DOMAINS env var: comma/space separated domains to block
 *  - BLOCKLIST_URL env var: remote file, refreshed periodically, parsed as a
 *    mix of adblock-style, hosts-style and dnsmasq address-style rules:
 *
 *      example.com            -> block
 *      ||ads.example.com^     -> block
 *      0.0.0.0 ads.com        -> block (hosts file)
 *      1.2.3.4 my.home        -> serve A 1.2.3.4 (hosts file)
 *      address=/x.com/1.2.3.4 -> serve A (dnsmasq)
 *
 * Everything else (comments, wildcards, ABP filters) is ignored.
 */

import type { Env } from "./types";
import type { RequestOpts } from "./opts";

export interface Rules {
	blocked: Set<string>;
	/** domain -> IPv4 */
	hosts: Map<string, string>;
	updatedAt: number;
}

const RULES_TTL_MS = 6 * 60 * 60 * 1000; // refetch blocklist every 6h
const FETCH_TIMEOUT_MS = 15_000;

function emptyRules(): Rules {
	return { blocked: new Set(), hosts: new Map(), updatedAt: 0 };
}

function isIpv4(s: string): boolean {
	const p = s.split(".");
	if (p.length !== 4) return false;
	return p.every((x) => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
}

export function parseRuleSource(text: string, rules: Rules): void {
	for (const raw of text.split(/\r?\n|\f/)) {
		const line = raw.trim();
		if (!line || /^[#;!\/]/.test(line)) continue;

		// hosts: "ip domain [domain...]"
		const first = line.split(/\s+/)[0];
		if (isIpv4(first)) {
			for (const dom of line.split(/\s+/).slice(1)) {
				const d = dom.toLowerCase().replace(/\.+$/, "");
				if (!d) continue;
				if (first === "0.0.0.0") rules.blocked.add(d);
				else rules.hosts.set(d, first);
			}
			continue;
		}

		// dnsmasq: address=/domain/ip | address=/domain/# | address=/domain (block)
		const addr = line.match(/^address=\/([^/]+)(?:\/([^/]*))?/);
		if (addr) {
			for (const dom of addr[1].split("/")) {
				const d = dom.toLowerCase().replace(/\.+$/, "");
				if (!d || d.startsWith("*")) continue;
				if (addr[2] && addr[2] !== "#" && isIpv4(addr[2])) {
					rules.hosts.set(d, addr[2]);
				} else {
					rules.blocked.add(d);
				}
			}
			continue;
		}

		// adblock: ||domain^ (whitelisting @@ and unsupported filters are skipped)
		const abp = line.match(/^\|\|([a-z0-9._-]+?)\^/i);
		if (abp) {
			rules.blocked.add(abp[1].toLowerCase().replace(/\.+$/, ""));
			continue;
		}

		// plain domain line
		const d = line.toLowerCase().replace(/\.+$/, "").split(/\s+/)[0];
		if (/^[a-z0-9._-]+$/.test(d)) rules.blocked.add(d);
	}
}

let rulesState: { rules: Rules; at: number } | null = null;
let rulesPending: Promise<Rules> | null = null;

async function loadRules(env: Env): Promise<Rules> {
	const rules = emptyRules();
	if (env.BLOCK_DOMAINS) {
		for (const d of env.BLOCK_DOMAINS.split(/[\s,]+/)) {
			const dom = d.trim().toLowerCase().replace(/\.+$/, "");
			if (dom) rules.blocked.add(dom);
		}
	}
	if (env.BLOCKLIST_URL) {
		const { signal, clear } = timeout(FETCH_TIMEOUT_MS);
		try {
			const res = await fetch(env.BLOCKLIST_URL, { signal, redirect: "follow" });
			if (!res.ok) {
				console.error(`blocklist ${env.BLOCKLIST_URL}: HTTP ${res.status}`);
			} else {
				parseRuleSource(await res.text(), rules);
			}
		} catch (err) {
			console.error(`blocklist fetch failed: ${err}`);
		} finally {
			clear();
		}
	}
	rules.updatedAt = Date.now();
	return rules;
}

function timeout(ms: number): { signal: AbortSignal; clear: () => void } {
	const ac = new AbortController();
	const t = setTimeout(() => ac.abort(), ms);
	return { signal: ac.signal, clear: () => clearTimeout(t) };
}

/** Get (and lazily refresh) the active rules. Cached per isolate. */
export async function getRules(env: Env): Promise<Rules> {
	if (rulesState && Date.now() - rulesState.at < RULES_TTL_MS) return rulesState.rules;
	if (!rulesState || Date.now() - rulesState.at >= RULES_TTL_MS) {
		if (!rulesPending) {
			rulesPending = loadRules(env)
				.then((rules) => {
					rulesState = { rules, at: Date.now() };
					return rules;
				})
				.catch((err) => {
					console.error(`rules load error: ${err}`);
					return rulesState ? rulesState.rules : emptyRules();
				})
				.finally(() => {
					rulesPending = null;
				});
		}
	}
	return rulesPending ?? rulesState?.rules ?? emptyRules();
}

/**
 * Env rules plus the per-request opts (union; env rules always stay as the
 * floor). `opts.list` blocklists are fetched and cached in isolate memory
 * (never the edge cache — list content is third-party).
 */
export async function getRulesFor(env: Env, opts: RequestOpts): Promise<Rules> {
	const base = await getRules(env);
	if (opts.block.length === 0 && opts.hosts.size === 0 && opts.list.length === 0) return base;

	const rules: Rules = {
		blocked: new Set(base.blocked),
		hosts: new Map(base.hosts),
		updatedAt: Date.now(),
	};
	for (const url of opts.list) {
		for (const d of await fetchListRules(url)) rules.blocked.add(d);
	}
	for (const d of opts.block) rules.blocked.add(d);
	for (const [d, ip] of opts.hosts) rules.hosts.set(d, ip);
	return rules;
}

const LIST_TTL_MS = 10 * 60 * 1000;
const listCache = new Map<string, { until: number; blocked: string[] }>();
const listPending = new Map<string, Promise<string[]>>();

async function fetchListRules(url: string): Promise<string[]> {
	const hit = listCache.get(url);
	if (hit && Date.now() < hit.until) return hit.blocked;
	let p = listPending.get(url);
	if (!p) {
		p = (async (): Promise<string[]> => {
			const { signal, clear } = timeout(FETCH_TIMEOUT_MS);
			try {
				const res = await fetch(url, { signal, redirect: "follow" });
				if (!res.ok) {
					console.error(`list ${url}: HTTP ${res.status}`);
					return [];
				}
				// blocklists are huge by design; cap the text we ever parse
				const text = (await res.text()).slice(0, 2_000_000);
				const rules = emptyRules();
				parseRuleSource(text, rules);
				return [...rules.blocked];
			} catch (err) {
				console.error(`list fetch failed: ${err}`);
				return [];
			} finally {
				clear();
			}
		})().finally(() => listPending.delete(url));
		listPending.set(url, p);
	}
	const blocked = await p.catch(() => [] as string[]);
	listCache.set(url, { until: Date.now() + LIST_TTL_MS, blocked });
	return blocked;
}

/** Suffix match with label boundaries: "ads.x.com" hits "x.com" too. */
export function isBlocked(rules: Rules, name: string): boolean {
	if (rules.blocked.size === 0) return false;
	let label = name.toLowerCase().replace(/\.+$/, "");
	for (;;) {
		if (rules.blocked.has(label)) return true;
		const dot = label.indexOf(".");
		if (dot === -1) return false;
		label = label.slice(dot + 1);
	}
}

export function lookupHost(rules: Rules, name: string): string | null {
	let label = name.toLowerCase().replace(/\.+$/, "");
	for (;;) {
		const ip = rules.hosts.get(label);
		if (ip) return ip;
		const dot = label.indexOf(".");
		if (dot === -1) return null;
		label = label.slice(dot + 1);
	}
}

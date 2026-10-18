/**
 * Filtering rules in the AdGuard-Home "DNS filters" sense, at the DNS layer:
 * block domains, allow exceptions, override with fixed IPs.
 *
 * Sources (merged):
 *  - BLOCK_DOMAINS / ALLOW_DOMAINS env vars: comma/space separated lists
 *  - BLOCKLIST_URL env var: comma-separated remote filter URLs, each
 *    refreshed every 6h, parsed as a domain-level subset of the rule syntax
 *    commonly found in adblock/hosts/dnsmasq subscriptions:
 *
 *      example.com            -> block
 *      ||ads.example.com^     -> block  (AGH wildcard behaviour: suffix match)
 *      *.wild.example.com     -> block  (leading "*." stripped)
 *      @@||ok.example.com^    -> allow (exception; beats block and hosts)
 *      0.0.0.0 ads.com        -> block (hosts file)
 *      1.2.3.4 my.home        -> serve A 1.2.3.4 (hosts file)
 *      address=/x.com/1.2.3.4 -> serve A (dnsmasq)
 *
 * Unsupported lines are skipped: full-regex rules (~...), $-modifier ABP
 * filters, cosmetic/elemhide (##) rules, comments.
 *
 * Precedence: allowed > hosts override > blocked > upstream resolution.
 */

import type { Env } from "./types";
import type { RequestOpts } from "./opts";

export interface Rules {
	blocked: Set<string>;
	/** exception domains: a name at or under one of these is never filtered */
	allowed: Set<string>;
	/** domain -> IPv4 */
	hosts: Map<string, string>;
	updatedAt: number;
}

const RULES_TTL_MS = 6 * 60 * 60 * 1000; // refetch blocklist every 6h
const FETCH_TIMEOUT_MS = 15_000;

function emptyRules(): Rules {
	return { blocked: new Set(), allowed: new Set(), hosts: new Map(), updatedAt: 0 };
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
		// cosmetic / regex / element-hidden rules: no DNS-layer meaning
		if (/^(##|#@#|~)/.test(line)) continue;

		// exception rule: @@||domain^[$modifiers] — whitelist, beats everything
		if (line.startsWith("@@")) {
			const d = normRuleDomain(line.slice(2).split("$")[0]);
			if (d) rules.allowed.add(d);
			continue;
		}

		// hosts: "ip domain [domain...] [# inline comment]"
		const first = line.split(/\s+/)[0];
		if (isIpv4(first)) {
			for (const dom of line.split(/\s+/).slice(1)) {
				if (dom.startsWith("#")) break; // inline comment: rest of line
				const d = dom.toLowerCase().replace(/\.+$/, "");
				if (!/^[a-z0-9._-]+$/.test(d)) continue;
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

		// adblock: ||domain^ (with optional $modifiers); *.domain wildcard form
		const abp = line.match(/^\|\|([a-z0-9._-]+?)\^/i);
		if (abp) {
			rules.blocked.add(abp[1].toLowerCase().replace(/\.+$/, ""));
			continue;
		}

		// plain domain line (or *.domain — same suffix semantics as AGH wildcards)
		const d = normRuleDomain(line.split(/\s+/)[0]);
		if (d) rules.blocked.add(d);
	}
}

/** "*.dom" / "dom." / "||dom^" → "dom"; null when not a plain domain rule. */
function normRuleDomain(s: string): string | null {
	const d = s.replace(/^\*\./, "").replace(/^\|\|/, "").replace(/\^.*$/, "").toLowerCase().replace(/\.+$/, "");
	if (!d || !/^[a-z0-9._-]+$/.test(d)) return null;
	return d;
}

let rulesState: { rules: Rules; at: number } | null = null;
let rulesPending: Promise<Rules> | null = null;

async function loadRules(env: Env): Promise<Rules> {
	const rules = emptyRules();
	addDomains(rules.blocked, env.BLOCK_DOMAINS);
	addDomains(rules.allowed, env.ALLOW_DOMAINS);
	const urls = (env.BLOCKLIST_URL ?? "").split(/[\s,]+/).filter(Boolean);
	for (const list of await Promise.all(urls.map(fetchListRules))) {
		for (const d of list.blocked) rules.blocked.add(d);
		for (const d of list.allowed) rules.allowed.add(d);
		for (const [d, ip] of list.hosts) rules.hosts.set(d, ip);
	}
	rules.updatedAt = Date.now();
	return rules;
}

function addDomains(set: Set<string>, v: string | undefined): void {
	if (!v) return;
	for (const d of v.split(/[\s,]+/)) {
		const dom = d.trim().toLowerCase().replace(/\.+$/, "");
		if (dom) set.add(dom);
	}
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
 * floor). `opts.list` filter URLs are fetched and cached in isolate memory
 * (never the edge cache — list content is third-party).
 */
export async function getRulesFor(env: Env, opts: RequestOpts): Promise<Rules> {
	const base = await getRules(env);
	if (!hasFilter(opts)) return base;

	const rules: Rules = {
		blocked: new Set(base.blocked),
		allowed: new Set(base.allowed),
		hosts: new Map(base.hosts),
		updatedAt: Date.now(),
	};
	for (const list of opts.list) {
		const r = await fetchListRules(list);
		for (const d of r.blocked) rules.blocked.add(d);
		for (const d of r.allowed) rules.allowed.add(d);
		for (const [d, ip] of r.hosts) rules.hosts.set(d, ip);
	}
	for (const d of opts.block) rules.blocked.add(d);
	for (const d of opts.allow) rules.allowed.add(d);
	for (const [d, ip] of opts.hosts) rules.hosts.set(d, ip);
	return rules;
}

function hasFilter(o: RequestOpts): boolean {
	return o.block.length > 0 || o.allow.length > 0 || o.hosts.size > 0 || o.list.length > 0;
}

const LIST_TTL_MS = 10 * 60 * 1000;
const listCache = new Map<string, { until: number; rules: Rules }>();
const listPending = new Map<string, Promise<Rules>>();

async function fetchListRules(url: string): Promise<Rules> {
	const hit = listCache.get(url);
	if (hit && Date.now() < hit.until) return hit.rules;
	let p = listPending.get(url);
	if (!p) {
		p = (async (): Promise<Rules> => {
			const { signal, clear } = timeout(FETCH_TIMEOUT_MS);
			try {
				const res = await fetch(url, { signal, redirect: "follow" });
				if (!res.ok) {
					console.error(`list ${url}: HTTP ${res.status}`);
					return emptyRules();
				}
				// blocklists are huge by design; cap the text we ever parse
				const rules = emptyRules();
				parseRuleSource((await res.text()).slice(0, 2_000_000), rules);
				return rules;
			} catch (err) {
				console.error(`list fetch failed: ${err}`);
				return emptyRules();
			} finally {
				clear();
			}
		})().finally(() => listPending.delete(url));
		listPending.set(url, p);
	}
	let rules: Rules;
	try {
		rules = await p;
	} catch {
		rules = emptyRules();
	}
	listCache.set(url, { until: Date.now() + LIST_TTL_MS, rules });
	return rules;
}

/**
 * Suffix match with label boundaries: "ads.x.com" hits "x.com" too.
 * An allowlist hit at any level of the name overrides every block rule.
 */
export function isBlocked(rules: Rules, name: string): boolean {
	if (rules.blocked.size === 0) return false;
	let label = name.toLowerCase().replace(/\.+$/, "");
	for (;;) {
		if (rules.allowed.has(label)) return false;
		if (rules.blocked.has(label)) return true;
		const dot = label.indexOf(".");
		if (dot === -1) return false;
		label = label.slice(dot + 1);
	}
}

export function lookupHost(rules: Rules, name: string): string | null {
	let label = name.toLowerCase().replace(/\.+$/, "");
	// an exception anywhere up the tree disables the fixed answer for the name
	for (;;) {
		if (rules.allowed.has(label)) return null;
		const dot = label.indexOf(".");
		if (dot === -1) break;
		label = label.slice(dot + 1);
	}
	label = name.toLowerCase().replace(/\.+$/, "");
	for (;;) {
		const ip = rules.hosts.get(label);
		if (ip) return ip;
		const dot = label.indexOf(".");
		if (dot === -1) return null;
		label = label.slice(dot + 1);
	}
}

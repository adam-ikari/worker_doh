/**
 * Filtering rules in the AdGuard-Home "DNS filters" sense, at the DNS layer:
 * block domains, allow exceptions, override with fixed IPs / CNAME aliases.
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
 *      /^ads?\..*$/           -> block by regex (subscriptions only)
 *      @@/^ok\./              -> allow by regex
 *      0.0.0.0 ads.com        -> block (hosts file)
 *      1.2.3.4 my.home        -> serve A 1.2.3.4 (hosts file)
 *      ::1 my6.home           -> serve AAAA ::1 (hosts file)
 *      address=/x.com/1.2.3.4 -> serve A (dnsmasq)
 *      address=/x.com/2001:db8::1 -> serve AAAA
 *      address=/x.com/target.lan  -> serve CNAME
 *
 * Unsupported lines are skipped: full-regex rules (~...), $-modifier ABP
 * filters, cosmetic/elemhide (##) rules, comments.
 *
 * Precedence: allowed > fixed answer > blocked > upstream resolution.
 */

import { parseIpv4, parseIpv6, type FixedAnswer } from "./dnsmsg";
import type { Env } from "./types";
import type { RequestOpts } from "./opts";

export interface Rules {
	blocked: Set<string>;
	/** exception domains: a name at or under one of these is never filtered */
	allowed: Set<string>;
	/** domain -> IPv4 */
	hosts: Map<string, string>;
	/** domain -> IPv6 */
	aaaa: Map<string, string>;
	/** domain -> target domain */
	cnames: Map<string, string>;
	/** subscription regex rules (/pattern/, case-insensitive) */
	blockRx: RegExp[];
	allowRx: RegExp[];
	updatedAt: number;
}

const RULES_TTL_MS = 6 * 60 * 60 * 1000; // refetch blocklist every 6h
const FETCH_TIMEOUT_MS = 15_000;
const MAX_NAME = 253;
const MAX_RX_LEN = 128;

function emptyRules(): Rules {
	return {
		blocked: new Set(),
		allowed: new Set(),
		hosts: new Map(),
		aaaa: new Map(),
		cnames: new Map(),
		blockRx: [],
		allowRx: [],
		updatedAt: 0,
	};
}

function isIpv4(s: string): boolean {
	const p = s.split(".");
	if (p.length !== 4) return false;
	return p.every((x) => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
}

function isIpv6(s: string): boolean {
	return s.includes(":") && parseIpv6(s) !== null;
}

/** All-zero IPv6 (::) is the hosts-file "block" convention, not a real answer. */
function isBlockIp(s: string): boolean {
	if (s === "0.0.0.0") return true;
	const b = isIpv6(s) ? parseIpv6(s) : null;
	return b !== null && b.every((x) => x === 0);
}

/** "/pattern/" -> RegExp (case-insensitive); null when not a usable regex line. */
function parseRegexLine(s: string): RegExp | null {
	if (s.length < 3 || s[0] !== "/" || s[s.length - 1] !== "/") return null;
	const pattern = s.slice(1, -1);
	if (!pattern || pattern.length > MAX_RX_LEN) return null;
	try {
		return new RegExp(pattern, "i");
	} catch {
		return null;
	}
}

function normTarget(s: string): string | null {
	const d = s.toLowerCase().replace(/\.+$/, "");
	if (!d || !/^[a-z0-9._-]+$/.test(d) || d.startsWith(".") || d.startsWith("-")) return null;
	return d;
}

export function parseRuleSource(text: string, rules: Rules): void {
	for (const raw of text.split(/\r?\n|\f/)) {
		const line = raw.trim();
		if (!line || /^[#;!]/.test(line)) continue;
		// cosmetic / regex / element-hidden rules: no DNS-layer meaning
		if (/^(##|#@#|~)/.test(line)) continue;

		// exception rule: @@/regex/ first, then @@||domain^[$modifiers]
		if (line.startsWith("@@")) {
			const rest = line.slice(2);
			if (rest.startsWith("/")) {
				const rx = parseRegexLine(rest);
				if (rx) rules.allowRx.push(rx);
				continue;
			}
			const d = normRuleDomain(rest.split("$")[0]);
			if (d) rules.allowed.add(d);
			continue;
		}

		// regex rule: /pattern/
		if (line.startsWith("/")) {
			const rx = parseRegexLine(line);
			if (rx) rules.blockRx.push(rx);
			continue;
		}

		// hosts: "ip domain [domain...] [# inline comment]"
		const first = line.split(/\s+/)[0];
		const v4 = isIpv4(first);
		const v6 = !v4 && isIpv6(first);
		if (v4 || v6) {
			const block = isBlockIp(first);
			for (const dom of line.split(/\s+/).slice(1)) {
				if (dom.startsWith("#")) break; // inline comment: rest of line
				const d = dom.toLowerCase().replace(/\.+$/, "");
				if (!/^[a-z0-9._-]+$/.test(d)) continue;
				if (block) rules.blocked.add(d);
				else if (v4) rules.hosts.set(d, first);
				else rules.aaaa.set(d, first);
			}
			continue;
		}

		// dnsmasq: address=/domain/ip | address=/domain/# | address=/domain (block)
		const addr = line.match(/^address=\/([^/]+)(?:\/([^/]*))?/);
		if (addr) {
			const rhs = addr[2];
			const ip4 = rhs !== undefined && isIpv4(rhs);
			const ip6 = !ip4 && rhs !== undefined && isIpv6(rhs);
			// digits-and-dots that fails IPv4 is a typo, never a CNAME target
			const cname = !ip4 && !ip6 && rhs !== undefined && !/^[0-9.]+$/.test(rhs) ? normTarget(rhs) : null;
			for (const dom of addr[1].split("/")) {
				const d = dom.toLowerCase().replace(/\.+$/, "");
				if (!d || d.startsWith("*")) continue;
				if (ip4) rules.hosts.set(d, rhs);
				else if (ip6) rules.aaaa.set(d, rhs);
				else if (cname) rules.cnames.set(d, cname);
				else rules.blocked.add(d);
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

function mergeRules(into: Rules, from: Rules): void {
	for (const d of from.blocked) into.blocked.add(d);
	for (const d of from.allowed) into.allowed.add(d);
	for (const [d, ip] of from.hosts) into.hosts.set(d, ip);
	for (const [d, ip] of from.aaaa) into.aaaa.set(d, ip);
	for (const [d, t] of from.cnames) into.cnames.set(d, t);
	into.blockRx.push(...from.blockRx);
	into.allowRx.push(...from.allowRx);
}

/** Route a fixed-answer target by its literal type: v4, v6, or CNAME domain. */
function addFixed(rules: Rules, domain: string, rhs: string): void {
	if (isIpv4(rhs)) rules.hosts.set(domain, rhs);
	else if (isIpv6(rhs)) rules.aaaa.set(domain, rhs);
	else rules.cnames.set(domain, rhs);
}

async function loadRules(env: Env): Promise<Rules> {
	const rules = emptyRules();
	addDomains(rules.blocked, env.BLOCK_DOMAINS);
	addDomains(rules.allowed, env.ALLOW_DOMAINS);
	const urls = (env.BLOCKLIST_URL ?? "").split(/[\s,]+/).filter(Boolean);
	for (const list of await Promise.all(urls.map(fetchListRules))) {
		mergeRules(rules, list);
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
		aaaa: new Map(base.aaaa),
		cnames: new Map(base.cnames),
		blockRx: base.blockRx.slice(),
		allowRx: base.allowRx.slice(),
		updatedAt: Date.now(),
	};
	for (const list of opts.list) {
		mergeRules(rules, await fetchListRules(list));
	}
	for (const d of opts.block) rules.blocked.add(d);
	for (const d of opts.allow) rules.allowed.add(d);
	for (const [d, rhs] of opts.hosts) addFixed(rules, d, rhs);
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
 * Regex rules only apply after the suffix walk found neither side.
 */
export function isBlocked(rules: Rules, name: string): boolean {
	if (rules.blocked.size === 0 && rules.blockRx.length === 0) return false;
	const n = name.toLowerCase().replace(/\.+$/, "");
	let label = n;
	for (;;) {
		if (rules.allowed.has(label)) return false;
		if (rules.blocked.has(label)) return true;
		const dot = label.indexOf(".");
		if (dot === -1) break;
		label = label.slice(dot + 1);
	}
	if (n.length > MAX_NAME) return false;
	if (rules.allowRx.some((rx) => rx.test(n))) return false;
	return rules.blockRx.some((rx) => rx.test(n));
}

/**
 * Fixed answer for a name: CNAME beats A/AAAA, most-specific suffix first.
 * A domain allowlist hit (suffix or regex) disables every fixed answer.
 */
export function lookupFixed(rules: Rules, name: string, qtype: number): FixedAnswer | null {
	const n = name.toLowerCase().replace(/\.+$/, "");
	let label = n;
	for (;;) {
		if (rules.allowed.has(label)) return null;
		const dot = label.indexOf(".");
		if (dot === -1) break;
		label = label.slice(dot + 1);
	}
	if (n.length > MAX_NAME) return null;
	if (rules.allowRx.some((rx) => rx.test(n))) return null;

	label = n;
	for (;;) {
		const cname = rules.cnames.get(label);
		if (cname) return { type: 5, data: cname };
		if (qtype === 1) {
			const ip = rules.hosts.get(label);
			if (ip) return { type: 1, data: ip };
		} else if (qtype === 28) {
			const ip = rules.aaaa.get(label);
			if (ip) return { type: 28, data: ip };
		}
		const dot = label.indexOf(".");
		if (dot === -1) return null;
		label = label.slice(dot + 1);
	}
}

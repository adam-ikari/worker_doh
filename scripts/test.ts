/**
 * Local sanity tests for the pure modules (dnsmsg / rules).
 * Run: npm test  (works in plain Node, no Worker runtime needed)
 */
import assert from "node:assert/strict";
import {
	buildReply,
	encodeName,
	isStandardQuery,
	minAnswerTtl,
	parseQuestion,
	RCODE_NXDOMAIN,
	RCODE_REFUSED,
	scrubQuery,
	randomId,
	setMsgId,
	coarseEcsParam,
} from "../src/dnsmsg";
import { isBlocked, lookupFixed, parseRuleSource } from "../src/rules";
import type { Rules } from "../src/rules";
import { canonicalOpts, hasOpts, optsHash, optsToParams, parseOpts } from "../src/opts";
import { regionFor } from "../src/upstream";
import { configPage } from "../src/page";

function mkRules(): Rules {
	return {
		blocked: new Set<string>(),
		allowed: new Set<string>(),
		hosts: new Map<string, string>(),
		aaaa: new Map<string, string>(),
		cnames: new Map<string, string>(),
		blockRx: [],
		allowRx: [],
		updatedAt: 0,
	};
}

let passed = 0;
async function ok(name: string, fn: () => void | Promise<void>): Promise<void> {
	await fn();
	passed++;
	console.log(`  ok - ${name}`);
}

function queryWire(name: string, type = 1, id = 0x1234): Uint8Array {
	const labels = name ? name.split(".") : [];
	const size = 12 + labels.reduce((n, l) => n + 1 + l.length, 1) + 4;
	const buf = new Uint8Array(size);
	const dv = new DataView(buf.buffer);
	dv.setUint16(0, id);
	dv.setUint16(2, 0x0100); // RD
	dv.setUint16(4, 1); // QDCOUNT
	let off = 12;
	for (const l of labels) {
		buf[off++] = l.length;
		for (const c of l) buf[off++] = c.charCodeAt(0);
	}
	buf[off++] = 0;
	dv.setUint16(off, type);
	dv.setUint16(off + 2, 1);
	return buf;
}

await ok("parseQuestion walks labels and returns correct end offset", () => {
	const q = parseQuestion(queryWire("example.com"))!;
	assert.ok(q);
	assert.equal(q.name, "example.com");
	assert.equal(q.type, 1);
	assert.equal(q.class, 1);
	assert.equal(q.end, 29);
});

await ok("parseQuestion handles root query", () => {
	const q = parseQuestion(queryWire("", 1))!;
	assert.ok(q);
	assert.equal(q.name, "");
	assert.equal(q.end, 17);
});

await ok("isStandardQuery rejects responses and non-zero opcodes", () => {
	assert.ok(isStandardQuery(queryWire("a.com")));
	const resp = queryWire("a.com");
	resp[2] |= 0x80;
	assert.ok(!isStandardQuery(resp));
});

await ok("buildReply NXDOMAIN keeps question and clears answer count", () => {
	const query = queryWire("ads.example.com");
	const reply = buildReply(query, { rcode: RCODE_NXDOMAIN });
	assert.equal(reply.length, 33);
	assert.equal((reply[2] & 0x80) !== 0, true); // QR
	assert.equal(reply[3] & 0x0f, 3); // rcode
	assert.equal((reply[6] << 8) | reply[7], 0); // ANCOUNT
	assert.equal(
		reply.subarray(12, 33).every((b, i) => b === query[i + 12]),
		true,
	);
	const refused = buildReply(query, { rcode: RCODE_REFUSED });
	assert.equal(refused[3] & 0x0f, 5); // REFUSED
	assert.equal((refused[2] & 0x80) !== 0, true);
});

await ok("buildReply A answer emits pointer + A record and keeps EDNS", () => {
	const query = queryWire("my.home"); // q.end = 25
	// fabricate an OPT record in the additional section: root name, type 41
	const withOpt = new Uint8Array(query.length);
	withOpt.set(query);
	const dv = new DataView(withOpt.buffer);
	dv.setUint16(10, 1); // ARCOUNT = 1
	const opt = new Uint8Array([0, 41, 0x25, 0x00, 0, 0, 0, 0, 0, 0, 0, 4]);
	const full = new Uint8Array(withOpt.length + opt.length);
	full.set(withOpt);
	full.set(opt, withOpt.length);

	const reply = buildReply(full, { answers: [{ type: 1, data: "1.2.3.4" }] });
	const dv2 = new DataView(reply.buffer);
	assert.equal(dv2.getUint16(6), 1); // ANCOUNT
	assert.equal(dv2.getUint16(10), 1); // ARCOUNT preserved
	// answer record starts at q.end = 25
	const rec = reply.subarray(25, 41);
	assert.deepEqual(Array.from(rec.subarray(0, 2)), [0xc0, 0x0c]);
	assert.deepEqual(Array.from(rec.subarray(12, 16)), [1, 2, 3, 4]);
	// OPT echoed at the end, bytes copied verbatim
	assert.deepEqual(Array.from(reply.subarray(41)), Array.from(opt));
});

await ok("minAnswerTtl scans answers with compressed names", () => {
	// build a fake response: header + question + A answer (compressed name) + TTL 60
	const query = queryWire("example.com");
	const msg = new Uint8Array(query.length + 16);
	msg.set(query);
	const dv = new DataView(msg.buffer);
	dv.setUint8(2, 0x80); // QR
	dv.setUint16(6, 1); // ANCOUNT
	const rec = msg.subarray(query.length);
	rec.set([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
	assert.equal(minAnswerTtl(msg), 60);
	assert.equal(minAnswerTtl(query), null); // a query has no answers
});

await ok("rules parse adblock/hosts/dnsmasq formats", () => {
	const rules = mkRules();
	parseRuleSource(
		[
			"# comment",
			"||ads.example.com^",
			"tracker.net",
			"0.0.0.0 black.io",
			"1.2.3.4 my.home",
			"address=/x.com/9.9.9.9",
			"address=/wrapped.info",
			"9.9.9.9 gw.home # gateway",
		].join("\n"),
		rules,
	);
	assert.ok(isBlocked(rules, "sub.ads.example.com"));
	assert.ok(isBlocked(rules, "tracker.net"));
	assert.ok(isBlocked(rules, "deep.sub.black.io"));
	assert.equal(isBlocked(rules, "notblack.io"), false);
	assert.deepEqual(lookupFixed(rules, "my.home", 1), { type: 1, data: "1.2.3.4" });
	assert.deepEqual(lookupFixed(rules, "x.com", 1), { type: 1, data: "9.9.9.9" });
	assert.equal(isBlocked(rules, "wrapped.info"), true);
	assert.deepEqual(lookupFixed(rules, "gw.home", 1), { type: 1, data: "9.9.9.9" });
	assert.equal(rules.hosts.has("#"), false); // inline comment not parsed as a domain
	assert.equal(rules.hosts.has("gateway"), false);
});

await ok("rules: AGH-style exceptions, wildcards, skipped syntax", () => {
	const rules = mkRules();
	parseRuleSource(
		[
			"||ads.a^",
			"*.wild.b^",
			"@@||ok.a^",
			"@@plain.c",
			"x.com$important", // modifier on a plain domain: not a recognizable rule
			"##.banner", // cosmetic
			"~/regex\\.rule", // full regex
			"address=/fix.c/5.6.7.8",
			"||hosts-block.d^",
		].join("\n"),
		rules,
	);
	assert.ok(isBlocked(rules, "sub.ads.a"));
	assert.ok(isBlocked(rules, "x.y.wild.b")); // *.wild.b^ wildcard
	assert.equal(isBlocked(rules, "ads.ok.a"), false); // allowed parent covers the whole subtree
	assert.ok(isBlocked(rules, "ads.a")); // unrelated block rule still applies
	assert.equal(isBlocked(rules, "ok.a"), false);
	assert.equal(isBlocked(rules, "www.plain.c"), false);
	assert.equal(isBlocked(rules, "x.com"), false); // $important line not parsed as a rule
	assert.equal(isBlocked(rules, "regex.rule"), false);
	assert.deepEqual(lookupFixed(rules, "fix.c", 1), { type: 1, data: "5.6.7.8" });
	// exception beats a hosts override too
	rules.hosts.set("mail.ok.a", "9.9.9.9");
	assert.equal(lookupFixed(rules, "mail.ok.a", 1), null);
});

await ok("rules: IPv6 and CNAME fixed answers, family matching", () => {
	const rules = mkRules();
	parseRuleSource(
		[
			"address=/v6.example/2001:db8::1",
			"address=/alias.example/server.lan",
			"2001:db8::7 nas6.home",
			"::1 loop.home",
			"address=/v6-blocked.example/#",
			":: blocked6.home",
		].join("\n"),
		rules,
	);
	assert.equal(rules.aaaa.get("v6.example"), "2001:db8::1");
	assert.deepEqual(lookupFixed(rules, "v6.example", 28), { type: 28, data: "2001:db8::1" });
	assert.equal(lookupFixed(rules, "v6.example", 1), null); // A query goes upstream
	assert.equal(rules.cnames.get("alias.example"), "server.lan");
	assert.deepEqual(lookupFixed(rules, "alias.example", 1), { type: 5, data: "server.lan" });
	assert.deepEqual(lookupFixed(rules, "alias.example", 28), { type: 5, data: "server.lan" });
	assert.equal(rules.aaaa.get("nas6.home"), "2001:db8::7");
	assert.equal(rules.aaaa.get("loop.home"), "::1");
	assert.ok(isBlocked(rules, "v6-blocked.example"));
	assert.ok(isBlocked(rules, "blocked6.home"));
});

await ok("rules: subscription regex block/allow, suffix allow beats regex", () => {
	const rules = mkRules();
	parseRuleSource(
		[
			"/^ads?\\..*$/",
			"@@/^ok\\./",
			"/\\.rx\\.test$/",
			"@@||safe.rx.test^",
			"/this is not (a regex/",
			"/" + "a".repeat(129) + "/",
		].join("\n"),
		rules,
	);
	assert.equal(rules.blockRx.length, 2); // invalid and >128 chars skipped
	assert.equal(rules.allowRx.length, 1);
	assert.ok(isBlocked(rules, "ads.x.com"));
	assert.ok(isBlocked(rules, "ad.x.com"));
	assert.equal(isBlocked(rules, "ok.anything"), false);
	assert.ok(isBlocked(rules, "a.rx.test"));
	assert.equal(isBlocked(rules, "x.safe.rx.test"), false); // domain allowlist wins
	assert.equal(isBlocked(rules, "example.com"), false);

	// regex allow also disables fixed answers
	const rules2 = mkRules();
	parseRuleSource("@@/^pin\\./\naddress=/pin.ok/1.2.3.4\naddress=/fixed.home/9.9.9.9", rules2);
	assert.equal(lookupFixed(rules2, "pin.ok", 1), null);
	assert.deepEqual(lookupFixed(rules2, "fixed.home", 1), { type: 1, data: "9.9.9.9" });
});

await ok("buildReply AAAA and CNAME record layouts", () => {
	const q6 = queryWire("v6.example", 28);
	const r6 = buildReply(q6, { answers: [{ type: 28, data: "2001:db8::1" }] });
	const dv6 = new DataView(r6.buffer);
	assert.equal(dv6.getUint16(6), 1); // ANCOUNT
	assert.equal(dv6.getUint16(q6.length + 2), 28); // TYPE AAAA
	assert.equal(dv6.getUint16(q6.length + 4), 1); // CLASS IN
	assert.equal(dv6.getUint16(q6.length + 10), 16); // RDLENGTH
	assert.deepEqual(Array.from(r6.subarray(q6.length + 12, q6.length + 28)), [
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	]);

	const qc = queryWire("alias.example", 1);
	const rc = buildReply(qc, { answers: [{ type: 5, data: "server.lan" }] });
	const dvc = new DataView(rc.buffer);
	assert.equal(dvc.getUint16(qc.length + 2), 5); // TYPE CNAME
	assert.equal(dvc.getUint16(qc.length + 10), 12); // RDLENGTH
	assert.deepEqual(Array.from(rc.subarray(qc.length + 12)), Array.from(encodeName("server.lan")));
});

await ok("opts: allow round-trips and partitions the cache hash", async () => {
	const a = parseOpts(new URLSearchParams("block=x.com&allow=y.com"));
	assert.ok(a.ok);
	assert.deepEqual(a.opts.allow, ["y.com"]);
	assert.ok(hasOpts(a.opts));
	const b = parseOpts(optsToParams(a.opts));
	assert.ok(b.ok);
	assert.equal(canonicalOpts(b.opts), canonicalOpts(a.opts));
	const c = parseOpts(new URLSearchParams("block=x.com"));
	assert.ok(c.ok);
	assert.notEqual(await optsHash(a.opts), await optsHash(c.opts));
	assert.ok(!parseOpts(new URLSearchParams("allow=bad domain")).ok);
});

await ok("opts parse, validate, and reject SSRF-ish urls", () => {
	const r = parseOpts(
		new URLSearchParams("block=Ads.Example.com,tracker.net&host=my.home/1.2.3.4&up=https://dns.google/dns-query"),
	);
	assert.ok(r.ok);
	assert.deepEqual(r.opts.block, ["ads.example.com", "tracker.net"]);
	assert.equal(r.opts.hosts.get("my.home"), "1.2.3.4");
	assert.deepEqual(r.opts.up, ["https://dns.google/dns-query"]);
	assert.equal(r.opts.blockMode, "");

	// fixed-answer targets: IPv4 / IPv6 / CNAME domain, all in host=
	const v = parseOpts(new URLSearchParams("host=nas6.home/2001:DB8::9,blog.home/server.lan&bm=REFUSED"));
	assert.ok(v.ok);
	assert.equal(v.opts.hosts.get("nas6.home"), "2001:db8::9");
	assert.equal(v.opts.hosts.get("blog.home"), "server.lan");
	assert.equal(v.opts.blockMode, "refused");
	assert.ok(hasOpts(v.opts));

	// block modes: names and both IP families
	for (const bm of ["nxdomain", "refused", "noaddr", "0.0.0.0", "2001:db8::1", "::"]) {
		assert.ok(parseOpts(new URLSearchParams(`bm=${bm}`)).ok, `bm=${bm} should parse`);
	}

	// rejects: non-https, IP literal, localhost/private TLD, query injection, bad host entry
	for (const qs of [
		"up=http://dns.google/dns-query",
		"up=https://1.1.1.1/dns-query",
		"up=https://localhost/dns-query",
		"up=https://box.internal/dns-query",
		"up=https://evil.com/x?a=",
		"list=https://169.254.169.254/latest/meta-data",
		"host=my.home",
		"host=my.home/999.1.1.1",
		"host=x/y/z",
		"host=my.home/not a domain",
		"block=bad domain",
		"bm=wat",
		"bm=1.2.3.999",
	]) {
		assert.ok(!parseOpts(new URLSearchParams(qs)).ok, `should reject: ${qs}`);
	}
});

await ok("opts canonical form and hash are order-insensitive", async () => {
	const a = parseOpts(new URLSearchParams("block=x.com,y.com&host=b.lan/2.2.2.2,a.lan/1.1.1.1"));
	const b = parseOpts(new URLSearchParams("block=y.com,x.com&host=a.lan/1.1.1.1,b.lan/2.2.2.2"));
	assert.ok(a.ok && b.ok);
	assert.equal(canonicalOpts(a.opts), canonicalOpts(b.opts));
	assert.equal(await optsHash(a.opts), await optsHash(b.opts));
	const c = parseOpts(new URLSearchParams("block=x.com,y.com.z"));
	assert.ok(c.ok);
	assert.notEqual(await optsHash(c.opts), await optsHash(a.opts));

	const back = optsToParams(a.opts);
	const r = parseOpts(back);
	assert.ok(r.ok);
	assert.equal(canonicalOpts(r.opts), canonicalOpts(a.opts));

	// bm joins the hash only when set; round-trips through optsToParams
	const withBm = parseOpts(new URLSearchParams("block=x.com&bm=refused"));
	const plain = parseOpts(new URLSearchParams("block=x.com"));
	assert.ok(withBm.ok && plain.ok);
	assert.equal(canonicalOpts(plain.opts).includes("m="), false);
	assert.equal(canonicalOpts(withBm.opts).includes("m=refused"), true);
	assert.notEqual(await optsHash(withBm.opts), await optsHash(plain.opts));
	const bmBack = parseOpts(optsToParams(withBm.opts));
	assert.ok(bmBack.ok);
	assert.equal(bmBack.opts.blockMode, "refused");
	assert.equal(canonicalOpts(bmBack.opts), canonicalOpts(withBm.opts));
});

await ok("region: country > continent > global, up= wins, malformed skipped", () => {
	const env = {
		UPSTREAM_DOH: "https://global.example/dns-query",
		UPSTREAM_REGIONS: "jp=https://jp1.example/dns-query,https://jp2.example/dns-query; AS = https://as1.example/dns-query ; malformed; X=",
	};
	const jp = regionFor(env, undefined, { country: "jp", continent: "AS" });
	assert.deepEqual(jp.list, ["https://jp1.example/dns-query", "https://jp2.example/dns-query"]);
	assert.equal(jp.bucket, "cJP");
	// KR is not configured; its continent AS is
	const as = regionFor(env, undefined, { country: "kr", continent: "AS" });
	assert.deepEqual(as.list, ["https://as1.example/dns-query"]);
	assert.equal(as.bucket, "kAS");
	const miss = regionFor(env, undefined, { country: "de", continent: "EU" });
	assert.deepEqual(miss.list, ["https://global.example/dns-query"]);
	assert.equal(miss.bucket, "g");
	assert.equal(regionFor(env, undefined, undefined).bucket, "g");
	// feature off -> empty bucket, cacheKey stays as it was before regions
	const off = regionFor({ UPSTREAM_DOH: "https://global.example/dns-query" }, undefined, { country: "JP" });
	assert.equal(off.bucket, "");
	assert.deepEqual(off.list, ["https://global.example/dns-query"]);
	// up= param beats every region rule
	const up = parseOpts(new URLSearchParams("up=https://dns.google/dns-query"));
	assert.ok(up.ok);
	const forced = regionFor(env, up.opts, { country: "jp" });
	assert.deepEqual(forced.list, ["https://dns.google/dns-query"]);
	assert.equal(forced.bucket, "");
});

await ok("page: dual theme + rules editor anchors, inline JS parses", async () => {
	const page = configPage(new URL("https://doh.example.com/dns-query"));
	const html = await page.text();
	assert.ok(html.includes("@media (prefers-color-scheme: dark)"));
	assert.ok(html.includes('id="rules"'));
	assert.ok(html.includes('id="bm"'));
	assert.ok(html.includes("doh-ui-theme"));
	const m = html.match(/<script>([\s\S]*)<\/script>/);
	assert.ok(m && m[1].length > 1000);
	new Function(m[1]); // throws SyntaxError on broken inline JS
	assert.ok(m[1].includes("isIpv6"));
	assert.ok(html.includes("doh.example.com"));
});

function optWith(options: number[][]): number[] {
	// root name, type 41, class=udp size, ext-ver + flags(CD), RDLENGTH, options
	const rdlen = options.reduce((n, o) => n + o.length, 0);
	const rr = [0, 0, 41, 0x25, 0x00, 0, 0x80, 0, 0, rdlen >> 8, rdlen & 0xff];
	for (const o of options) rr.push(...o);
	return rr;
}

function queryWithOpt(options: number[][], name = "example.com"): Uint8Array {
	const q = queryWire(name);
	const rr = optWith(options);
	const msg = new Uint8Array(q.length + rr.length);
	msg.set(q);
	msg.set(rr, q.length);
	new DataView(msg.buffer).setUint16(10, 1); // ARCOUNT
	return msg;
}

function walkOptions(opt: Uint8Array): Array<{ code: number; data: Uint8Array }> {
	const out: Array<{ code: number; data: Uint8Array }> = [];
	let o = 11; // past OPT fixed part (name+type+class+ttl+rdlength)
	while (o + 4 <= opt.length) {
		const code = (opt[o] << 8) | opt[o + 1];
		const len = (opt[o + 2] << 8) | opt[o + 3];
		out.push({ code, data: opt.subarray(o + 4, o + 4 + len) });
		o += 4 + len;
	}
	return out;
}

await ok("scrubQuery coarsens ECS and drops cookies/padding, keeps other options", () => {
	const qLen = queryWire("example.com").length;
	const ecsData = [0, 1, 24, 0, 1, 2, 3, 4]; // v4 1.2.3.4/24
	const msg = queryWithOpt([
		[0, 10, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd], // CLIENT_COOKIE — dropped
		[0, 8, 0, ecsData.length, ...ecsData], // ECS
		[0, 12, 0, 2, 0, 0], // PADDING — dropped
		[0, 99, 0, 1, 0x7f], // unknown — kept
	]);
	const scrubbed = scrubQuery(msg);
	const rr = scrubbed.subarray(qLen);
	const opts = walkOptions(rr);
	assert.deepEqual(opts.map((o) => o.code), [8, 99]);
	const e = opts[0].data;
	assert.equal(e[1], 1); // family v4
	assert.equal(e[2], 8); // prefix truncated to /8
	assert.deepEqual(Array.from(e.subarray(4)), [1]); // /8 → 1 address byte, region kept
	assert.deepEqual(Array.from(opts[1].data), [0x7f]);
	assert.equal(new DataView(scrubbed.buffer).getUint16(10), 1); // ARCOUNT unchanged
	assert.equal(rr[6] & 0x80, 0x80); // CD flag preserved
	// question section untouched, ID untouched
	assert.deepEqual(Array.from(scrubbed.subarray(0, qLen)), Array.from(msg.subarray(0, qLen)));
});

await ok("scrubQuery: coarse ECS kept, v6 truncated, no-OPT and malformed-OPT cases", () => {
	const already = queryWithOpt([[0, 8, 0, 5, 0, 1, 8, 0, 9]]); // 9.0.0.0/8 (data: fam,src=/8,scope=0,addr 9)
	assert.equal(scrubQuery(already), already); // nothing to change → same reference
	const v6 = queryWithOpt([[0, 8, 0, 12, 0, 2, 64, 0, 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0]]); // 2001:db8:1234::/64
	const s6 = scrubQuery(v6);
	const o6 = walkOptions(s6.subarray(queryWire("example.com").length))[0];
	assert.equal(o6.data[1], 2);
	assert.equal(o6.data[2], 32);
	assert.deepEqual(Array.from(o6.data.subarray(4)), [0x20, 0x01, 0x0d, 0xb8]);
	const plain = queryWire("a.com");
	assert.equal(scrubQuery(plain), plain);
	// truncated option (len runs past RDATA) → whole OPT dropped
	const broken = queryWithOpt([[0, 8, 0, 20, 0, 1]]);
	const out = scrubQuery(broken);
	assert.equal(out.length, queryWire("example.com").length);
	assert.equal(new DataView(out.buffer).getUint16(10), 0);
});

await ok("randomId + setMsgId round-trip", () => {
	const q = queryWire("a.com", 1, 0xbeef);
	const r = randomId(q);
	assert.equal(r.id, 0xbeef);
	const rid = (r.msg[0] << 8) | r.msg[1];
	assert.notEqual(rid, 0xbeef); // overwhelmingly likely
	const back = setMsgId(r.msg, r.id);
	assert.equal((back[0] << 8) | back[1], 0xbeef);
	assert.equal((q[0] << 8) | q[1], 0xbeef); // inputs not mutated
});

await ok("coarseEcsParam truncates to region prefixes", () => {
	assert.equal(coarseEcsParam("1.2.3.4"), "1.0.0.0/8");
	assert.equal(coarseEcsParam("1.2.3.4/24"), "1.0.0.0/8");
	assert.equal(coarseEcsParam("1.2.3.4/4"), "1.0.0.0/4"); // already coarser → kept
	assert.equal(coarseEcsParam("2001:db8:1234::/48"), "2001:db8:0:0:0:0:0:0/32");
	assert.equal(coarseEcsParam("2001:db8::/32"), "2001:db8:0:0:0:0:0:0/32");
	assert.equal(coarseEcsParam("not-an-ip"), null);
	assert.equal(coarseEcsParam("1.2.3.4/99"), null);
});

console.log(`\n${passed} tests passed`);

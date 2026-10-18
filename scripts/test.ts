/**
 * Local sanity tests for the pure modules (dnsmsg / rules).
 * Run: npm test  (works in plain Node, no Worker runtime needed)
 */
import assert from "node:assert/strict";
import {
	buildReply,
	isStandardQuery,
	minAnswerTtl,
	parseQuestion,
	RCODE_NXDOMAIN,
} from "../src/dnsmsg";
import { isBlocked, lookupHost, parseRuleSource } from "../src/rules";
import { canonicalOpts, hasOpts, optsHash, optsToParams, parseOpts } from "../src/opts";

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

	const reply = buildReply(full, { a: [{ ip: "1.2.3.4" }] });
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
	const rules = { blocked: new Set<string>(), allowed: new Set<string>(), hosts: new Map<string, string>(), updatedAt: 0 };
	parseRuleSource(
		[
			"# comment",
			"||ads.example.com^",
			"tracker.net",
			"0.0.0.0 black.io",
			"1.2.3.4 my.home",
			"address=/x.com/9.9.9.9",
			"address=/wrapped.info",
		].join("\n"),
		rules,
	);
	assert.ok(isBlocked(rules, "sub.ads.example.com"));
	assert.ok(isBlocked(rules, "tracker.net"));
	assert.ok(isBlocked(rules, "deep.sub.black.io"));
	assert.equal(isBlocked(rules, "notblack.io"), false);
	assert.equal(lookupHost(rules, "my.home"), "1.2.3.4");
	assert.equal(lookupHost(rules, "x.com"), "9.9.9.9");
	assert.equal(isBlocked(rules, "wrapped.info"), true);
});

await ok("rules: AGH-style exceptions, wildcards, skipped syntax", () => {
	const rules = { blocked: new Set<string>(), allowed: new Set<string>(), hosts: new Map<string, string>(), updatedAt: 0 };
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
	assert.equal(lookupHost(rules, "fix.c"), "5.6.7.8");
	// exception beats a hosts override too
	rules.hosts.set("mail.ok.a", "9.9.9.9");
	assert.equal(lookupHost(rules, "mail.ok.a"), null);
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
		"block=bad domain",
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
});

console.log(`\n${passed} tests passed`);

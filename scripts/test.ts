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

let passed = 0;
function ok(name: string, fn: () => void): void {
	fn();
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

ok("parseQuestion walks labels and returns correct end offset", () => {
	const q = parseQuestion(queryWire("example.com"))!;
	assert.ok(q);
	assert.equal(q.name, "example.com");
	assert.equal(q.type, 1);
	assert.equal(q.class, 1);
	assert.equal(q.end, 29);
});

ok("parseQuestion handles root query", () => {
	const q = parseQuestion(queryWire("", 1))!;
	assert.ok(q);
	assert.equal(q.name, "");
	assert.equal(q.end, 17);
});

ok("isStandardQuery rejects responses and non-zero opcodes", () => {
	assert.ok(isStandardQuery(queryWire("a.com")));
	const resp = queryWire("a.com");
	resp[2] |= 0x80;
	assert.ok(!isStandardQuery(resp));
});

ok("buildReply NXDOMAIN keeps question and clears answer count", () => {
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

ok("buildReply A answer emits pointer + A record and keeps EDNS", () => {
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

ok("minAnswerTtl scans answers with compressed names", () => {
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

ok("rules parse adblock/hosts/dnsmasq formats", () => {
	const rules = { blocked: new Set<string>(), hosts: new Map<string, string>(), updatedAt: 0 };
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

console.log(`\n${passed} tests passed`);

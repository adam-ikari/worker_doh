/**
 * Minimal DNS wire-format helpers (RFC 1035 / RFC 8484).
 *
 * Only what the relay actually needs: standard-query validation, question
 * parsing, answer-TTL scanning and building small replies (NXDOMAIN / A).
 */

export const RCODE_NOERROR = 0;
export const RCODE_NXDOMAIN = 3;

export interface Question {
	/** lowercase name, trailing dot stripped */
	name: string;
	type: number;
	class: number;
	/** offset just past the question section (i.e. start of the answer section) */
	end: number;
}

const TYPE_NAMES: Record<number, string> = {
	1: "A",
	2: "NS",
	5: "CNAME",
	6: "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	33: "SRV",
	64: "SVCB",
	65: "HTTPS",
};

export function typeName(type: number): string {
	return TYPE_NAMES[type] ?? `TYPE${type}`;
}

/**
 * True when the message is a standard (opcode 0) DNS query — the only kind an
 * RFC 8484 server should answer. Anything else is rejected upstream.
 */
export function isStandardQuery(msg: Uint8Array): boolean {
	if (msg.length < 12) return false;
	const isResponse = (msg[2] & 0x80) !== 0;
	const opcode = (msg[2] >> 3) & 0x0f;
	return !isResponse && opcode === 0;
}

/**
 * Parse the question section. Supports the root name (single 0 byte) and
 * reject anything using compression pointers inside the question, which
 * cannot happen in a well-formed query.
 */
export function parseQuestion(msg: Uint8Array): Question | null {
	if (!isStandardQuery(msg)) return null;
	const qdcount = (msg[4] << 8) | msg[5];
	if (qdcount !== 1) return null;

	const labels: string[] = [];
	let off = 12;
	for (;;) {
		if (off >= msg.length) return null;
		const len = msg[off];
		if ((len & 0xc0) !== 0) return null; // no pointers in a query
		if (len === 0) {
			off += 1;
			break;
		}
		if (off + 1 + len >= msg.length) return null;
		let ok = true;
		for (let i = 1; i <= len; i++) {
			const c = msg[off + i];
			// accept only visible ASCII, no escaped nonsense
			if (c < 0x21 || c > 0x7e) ok = false;
		}
		if (!ok) return null;
		labels.push(String.fromCharCode(...msg.subarray(off + 1, off + 1 + len)));
		off += 1 + len;
	}
	if (off + 4 > msg.length) return null;
	const name = labels.join(".");
	return {
		name,
		type: (msg[off] << 8) | msg[off + 1],
		class: (msg[off + 2] << 8) | msg[off + 3],
		end: off + 4,
	};
}

/**
 * Minimum TTL across the answer section (RFC 8484 §5.1 cache-control hint).
 * Returns null when there is nothing worth caching (empty/failed answers or a
 * message we could not parse).
 */
export function minAnswerTtl(msg: Uint8Array): number | null {
	if (msg.length < 12) return null;
	const rcode = msg[3] & 0x0f;
	const ancount = (msg[6] << 8) | msg[7];
	if (rcode !== RCODE_NOERROR || ancount === 0) return null;

	const skipQuestion = (): number | null => {
		let off = 12;
		for (;;) {
			if (off >= msg.length) return null;
			const len = msg[off];
			if ((len & 0xc0) !== 0) return null;
			if (len === 0) return off + 1;
			off += 1 + len;
		}
	};
	let off = skipQuestion();
	if (off === null) return null;
	off += 4; // skip QTYPE + QCLASS

	let minTtl = Infinity;
	for (let i = 0; i < ancount && off + 10 <= msg.length; i++) {
		// skip the (possibly compressed) owner name
		for (;;) {
			if (off >= msg.length) return null;
			const len = msg[off];
			if ((len & 0xc0) === 0xc0) {
				off += 2;
				break;
			}
			if (len === 0) {
				off += 1;
				break;
			}
			off += 1 + len;
		}
		const ttl =
			msg[off + 4] * 0x1000000 +
			((msg[off + 5] << 16) | (msg[off + 6] << 8) | msg[off + 7]);
		const rdlength = (msg[off + 8] << 8) | msg[off + 9];
		minTtl = Math.min(minTtl, ttl);
		off += 10 + rdlength;
	}
	return Number.isFinite(minTtl) ? minTtl : null;
}

/**
 * Build a reply from the original query: header patched to a response, the
 * question echoed back verbatim, plus optional A answers. When the query
 * carried records in the additional section (typically an EDNS OPT), those
 * bytes are copied through untouched so OPT round-trips.
 */
export function buildReply(
	query: Uint8Array,
	opts: { rcode?: number; a?: Array<{ ip: string }>; ttl?: number } = {},
): Uint8Array {
	const q = parseQuestion(query);
	if (!q) throw new Error("invalid query");

	// Walk the answer + additional sections of the query to find where the
	// additional section starts, so EDNS OPT can be echoed.
	const arcount = (query[10] << 8) | query[11];
	let extras: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
	if (arcount > 0) {
		const scanned = scanSections(query, q.end);
		if (scanned && scanned.extraStart !== null) {
			extras = query.subarray(scanned.extraStart);
		}
	}

	const answers = opts.a ?? [];
	const out = new Uint8Array(q.end + answers.length * 16 + extras.length);
	out.set(query.subarray(0, q.end), 0);
	out.set(extras, q.end + answers.length * 16);

	const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
	// QR=1, AA=1; keep opcode
	dv.setUint8(2, (dv.getUint8(2) & 0x7f) | 0x84);
	// RA=1, replace rcode
	dv.setUint8(3, (dv.getUint8(3) & 0xf0) | 0x80 | (opts.rcode ?? RCODE_NOERROR));
	// ANCOUNT / NSCOUNT / ARCOUNT
	dv.setUint16(6, answers.length);
	dv.setUint16(8, 0);
	dv.setUint16(10, arcount);

	let off = q.end;
	for (const ans of answers) {
		dv.setUint16(off, 0xc00c); // NAME: pointer to the question name
		dv.setUint16(off + 2, 1); // TYPE A
		dv.setUint16(off + 4, 1); // CLASS IN
		dv.setUint32(off + 6, opts.ttl ?? 300);
		dv.setUint16(off + 10, 4); // RDLENGTH
		const ip = ans.ip.split(".");
		out[off + 12] = Number(ip[0]);
		out[off + 13] = Number(ip[1]);
		out[off + 14] = Number(ip[2]);
		out[off + 15] = Number(ip[3]);
		off += 16;
	}
	return out;
}

/**
 * Walk the answer + authority sections of a query to locate where the
 * additional section starts (used only by buildReply, to echo EDNS OPT).
 */
function scanSections(
	msg: Uint8Array,
	start: number,
): { extraStart: number | null } | null {
	const ancount = (msg[6] << 8) | msg[7];
	const nscount = (msg[8] << 8) | msg[9];
	const arcount = (msg[10] << 8) | msg[11];
	if (ancount + nscount + arcount === 0) return { extraStart: null };
	let off = start;
	const walk = (count: number): boolean => {
		for (let i = 0; i < count; i++) {
			if (msg.length - off < 11) return false;
			// skip owner name (labels or compression pointer)
			for (;;) {
				if (off >= msg.length) return false;
				const len = msg[off];
				if ((len & 0xc0) === 0xc0) {
					off += 2;
					break;
				}
				if (len === 0) {
					off += 1;
					break;
				}
				off += 1 + len;
			}
			const rdlength = (msg[off + 8] << 8) | msg[off + 9];
			off += 10 + rdlength;
			if (off > msg.length) return false;
		}
		return true;
	};
	if (!walk(ancount) || !walk(nscount)) return null;
	const extraStart = off;
	if (!walk(arcount)) return null;
	return { extraStart };
}

// ---- client-identity scrubbing for outbound queries ----

const ECS_CAP_V4 = 8; // keep the client's /8 (region), drop everything finer
const ECS_CAP_V6 = 32;
/** EDNS options that carry client identity or enable tracking/fingerprinting */
const DROP_OPTIONS = new Set([10, 11, 12, 15]); // CLIENT/SERVER_COOKIE, PADDING, CLIENT-TAG

/** Coarsen one ECS option's data (RFC 7871): truncate prefix, zero low bits. */
function coarseEcsData(data: Uint8Array): Uint8Array | null {
	if (data.length < 4) return null;
	const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
	const family = dv.getUint16(0);
	const prefix = data[2];
	const addr = data.subarray(4);
	const cap = family === 1 ? ECS_CAP_V4 : family === 2 ? ECS_CAP_V6 : -1;
	if (cap < 0 || prefix > (family === 1 ? 32 : 128)) return null;
	if (prefix <= cap) return data.slice(); // already coarse enough
	const newPrefix = cap;
	const keepBytes = Math.ceil(newPrefix / 8);
	const out = new Uint8Array(4 + keepBytes);
	out[0] = data[0];
	out[1] = data[1];
	out[2] = newPrefix;
	// out[3] stays 0 (family-independent prefix in RFC 7871 layout: octets covered by full bytes are kept, remainder zeroed)
	out.set(addr.subarray(0, Math.min(keepBytes, addr.length)), 4);
	return out;
}

/**
 * Strip client-identifying EDNS options from a query before forwarding:
 * ECS (option 8) is coarsened to the client's /8 (v4) or /32 (v6) region,
 * cookies/padding/client-tag are removed, remaining options and the OPT
 * flags (DNSSEC CD bit) survive. A malformed OPT is dropped whole
 * (fail-closed). The question section is never touched, so answer-section
 * compression pointers into it stay valid.
 */
export function scrubQuery(msg: Uint8Array): Uint8Array {
	const q = parseQuestion(msg);
	if (!q) return msg;
	const arcount = (msg[10] << 8) | msg[11];
	if (arcount === 0) return msg;
	const scanned = scanSections(msg, q.end);
	// unparseable sections beyond the question: drop everything after it
	if (!scanned) return dropAllOpt(msg, q, q.end);
	if (scanned.extraStart === null) return msg;
	const extraStart = scanned.extraStart;

	const out: number[] = [];
	let off = extraStart;
	let droppedRrs = 0;
	for (let i = 0; i < arcount; i++) {
		const rrStart = off;
		// owner name
		for (;;) {
			if (off >= msg.length) return dropAllOpt(msg, q, extraStart);
			const len = msg[off];
			if ((len & 0xc0) === 0xc0) {
				off += 2;
				break;
			}
			if (len === 0) {
				off += 1;
				break;
			}
			off += 1 + len;
		}
		if (msg.length - off < 10) return dropAllOpt(msg, q, extraStart);
		const type = (msg[off] << 8) | msg[off + 1];
		const rdlength = (msg[off + 8] << 8) | msg[off + 9];
		const rdataStart = off + 10;
		const rrEnd = rdataStart + rdlength;
		if (rrEnd > msg.length) return dropAllOpt(msg, q, extraStart);
		if (type !== 41) {
			out.push(...msg.subarray(rrStart, rrEnd));
			off = rrEnd;
			continue;
		}
		// OPT: rebuild the option list from RDATA
		const fixed = Array.from(msg.subarray(rrStart, rdataStart)); // name+type+class+ttl
		const opts = msg.subarray(rdataStart, rrEnd);
		const rebuilt: number[] = [];
		let o = 0;
		let bad = false;
		while (o < opts.length) {
			if (opts.length - o < 4) {
				bad = true;
				break;
			}
			const code = (opts[o] << 8) | opts[o + 1];
			const olen = (opts[o + 2] << 8) | opts[o + 3];
			const dataStart = o + 4;
			if (dataStart + olen > opts.length) {
				bad = true;
				break;
			}
			const data = opts.subarray(dataStart, dataStart + olen);
			if (code === 8) {
				const c = coarseEcsData(data);
				if (c === null) {
					bad = true;
					break;
				}
				rebuilt.push(0, 8, c.length >> 8, c.length & 0xff, ...c);
			} else if (!DROP_OPTIONS.has(code)) {
				rebuilt.push(opts[o], opts[o + 1], opts[o + 2], opts[o + 3], ...data);
			}
			o = dataStart + olen;
		}
		if (bad) {
			droppedRrs++;
		} else {
			fixed[fixed.length - 2] = rebuilt.length >> 8;
			fixed[fixed.length - 1] = rebuilt.length & 0xff;
			out.push(...fixed, ...rebuilt);
		}
		off = rrEnd;
	}
	if (droppedRrs === 0 && out.length === msg.length - extraStart) return msg;
	const res = new Uint8Array(extraStart + out.length);
	res.set(msg.subarray(0, extraStart), 0);
	res.set(out, extraStart);
	const rdv = new DataView(res.buffer, res.byteOffset, res.byteLength);
	rdv.setUint16(10, arcount - droppedRrs);
	return res;
}

/** Malformed OPT encountered: remove every ADDITIONAL RR (fail-closed). */
function dropAllOpt(msg: Uint8Array, q: Question, extraStart: number): Uint8Array {
	const res = msg.slice(0, extraStart);
	new DataView(res.buffer, res.byteOffset, res.byteLength).setUint16(10, 0);
	return res;
}

/** Replace the query ID with a random one; returns the client's original ID. */
export function randomId(msg: Uint8Array): { msg: Uint8Array; id: number } {
	const out = msg.slice();
	const id = (out[0] << 8) | out[1];
	const r = new Uint8Array(2);
	crypto.getRandomValues(r);
	out[0] = r[0];
	out[1] = r[1];
	return { msg: out, id };
}

/** Stamp the client's original ID back into an upstream response. */
export function setMsgId(msg: Uint8Array, id: number): Uint8Array {
	const out = msg.slice();
	out[0] = id >> 8;
	out[1] = id & 0xff;
	return out;
}

/**
 * Coarsen a JSON-API `edns_client_subnet` value ("ip[/len]") the same way as
 * wire ECS. Returns null when the value is not a parseable address.
 */
export function coarseEcsParam(v: string): string | null {
	const [ipPart, lenPart] = v.split("/");
	const isV6 = ipPart.includes(":");
	const bytes = isV6 ? parseIpv6(ipPart) : parseIpv4(ipPart);
	if (bytes === null) return null;
	const cap = isV6 ? ECS_CAP_V6 : ECS_CAP_V4;
	const full = isV6 ? 128 : 32;
	let prefix = lenPart !== undefined ? Number(lenPart) : full;
	if (!Number.isInteger(prefix) || prefix < 0 || prefix > full) return null;
	if (prefix > cap) prefix = cap;
	const keep = Math.ceil(prefix / 8);
	for (let i = keep; i < bytes.length; i++) bytes[i] = 0;
	const addr = isV6 ? fmtIpv6(bytes) : bytes.join(".");
	return `${addr}/${prefix}`;
}

function parseIpv4(s: string): Uint8Array | null {
	const p = s.split(".");
	if (p.length !== 4) return null;
	const b = new Uint8Array(4);
	for (let i = 0; i < 4; i++) {
		if (!/^\d{1,3}$/.test(p[i]) || +p[i] > 255) return null;
		b[i] = +p[i];
	}
	return b;
}

function parseIpv6(s: string): Uint8Array | null {
	const parts = s.split("::");
	if (parts.length > 2) return null;
	const groups = (str: string): number[] | null => {
		if (str === "") return [];
		const g = str.split(":");
		const out: number[] = [];
		for (const x of g) {
			if (!/^[0-9a-fA-F]{1,4}$/.test(x)) return null;
			out.push(parseInt(x, 16));
		}
		return out;
	};
	const head = groups(parts[0]);
	if (head === null) return null;
	let gs = head;
	if (parts.length === 2) {
		const tail = groups(parts[1]);
		if (tail === null) return null;
		if (head.length + tail.length > 8) return null;
		gs = [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
	}
	if (gs.length !== 8) return null;
	const b = new Uint8Array(16);
	const dv = new DataView(b.buffer);
	for (let i = 0; i < 8; i++) dv.setUint16(i * 2, gs[i]);
	return b;
}

function fmtIpv6(b: Uint8Array): string {
	const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
	const g: string[] = [];
	for (let i = 0; i < 8; i++) g.push(dv.getUint16(i * 2).toString(16));
	return g.join(":");
}

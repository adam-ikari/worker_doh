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

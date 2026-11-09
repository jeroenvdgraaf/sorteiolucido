// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
// OpenTimestamps: montagem do arquivo .ots, leitura, junção de árvores e atualização (upgrade).
// Formato: https://github.com/opentimestamps/python-opentimestamps (core/serialize.py, timestamp.py, op.py)

export const MAGIC = Uint8Array.of(0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94);
export const TAG_PENDING = "83dfe30d2ef90c8e";
export const TAG_BITCOIN = "0588960d73d71901";
const OP = { sha1: 0x02, ripemd160: 0x03, sha256: 0x08, keccak256: 0x67, append: 0xf0, prepend: 0xf1, reverse: 0xf2, hexlify: 0xf3 };
const BINARY = new Set([OP.append, OP.prepend]);
const KNOWN = new Set(Object.values(OP));
const MAX_DEPTH = 256;

const hex = (u) => Array.from(u, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const concat = (...p) => { const o = new Uint8Array(p.reduce((s, x) => s + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

class Reader {
  constructor(b) { this.b = b; this.p = 0; }
  byte() { if (this.p >= this.b.length) throw new Error("ots: truncated"); return this.b[this.p++]; }
  bytes(n) { if (this.p + n > this.b.length) throw new Error("ots: truncated"); const r = this.b.subarray(this.p, this.p + n); this.p += n; return r; }
  varuint() { let v = 0, shift = 0, b; do { b = this.byte(); v += (b & 0x7f) * 2 ** shift; shift += 7; if (shift > 56) throw new Error("ots: varuint too long"); } while (b & 0x80); return v; }
  varbytes(max = 8192) { const n = this.varuint(); if (n > max) throw new Error("ots: varbytes too long"); return this.bytes(n); }
}
function varuint(n) { const out = []; do { let b = n % 128; n = Math.floor(n / 128); if (n) b |= 0x80; out.push(b); } while (n); return Uint8Array.from(out); }
const varbytes = (b) => concat(varuint(b.length), b);

// Nó: { attestations: [{ tag: hex, payload: Uint8Array }], ops: [{ op, arg: Uint8Array|null, child: Node }] }
export function parseTimestamp(r, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error("ots: too deep");
  const node = { attestations: [], ops: [] };
  const item = (tag) => {
    if (tag === 0x00) {
      const t = hex(r.bytes(8));
      node.attestations.push({ tag: t, payload: Uint8Array.from(r.varbytes()) });
    } else {
      if (!KNOWN.has(tag)) throw new Error("ots: unknown op 0x" + tag.toString(16));
      const arg = BINARY.has(tag) ? Uint8Array.from(r.varbytes(4096)) : null;
      node.ops.push({ op: tag, arg, child: parseTimestamp(r, depth + 1) });
    }
  };
  let tag = r.byte();
  while (tag === 0xff) { item(r.byte()); tag = r.byte(); }
  item(tag);
  return node;
}
export function serializeTimestamp(node) {
  const items = [];
  for (const a of node.attestations) items.push(concat(Uint8Array.of(0x00), fromHex(a.tag), varbytes(a.payload)));
  for (const o of node.ops) items.push(concat(Uint8Array.of(o.op), o.arg ? varbytes(o.arg) : new Uint8Array(0), serializeTimestamp(o.child)));
  if (!items.length) throw new Error("ots: empty timestamp");
  return concat(...items.map((it, i) => (i < items.length - 1 ? concat(Uint8Array.of(0xff), it) : it)));
}
export function mergeInto(dst, src) {
  for (const a of src.attestations) if (!dst.attestations.some((x) => x.tag === a.tag && eq(x.payload, a.payload))) dst.attestations.push(a);
  for (const o of src.ops) {
    const same = dst.ops.find((x) => x.op === o.op && ((!x.arg && !o.arg) || (x.arg && o.arg && eq(x.arg, o.arg))));
    if (same) mergeInto(same.child, o.child); else dst.ops.push(o);
  }
  return dst;
}

export function parseOtsFile(bytes) {
  if (bytes.length < MAGIC.length + 34 || !eq(bytes.subarray(0, MAGIC.length), MAGIC)) throw new Error("ots: bad magic");
  const r = new Reader(bytes); r.bytes(MAGIC.length);
  if (r.varuint() !== 1) throw new Error("ots: unsupported version");
  if (r.byte() !== OP.sha256) throw new Error("ots: only sha256 file hashes are supported");
  const digest = Uint8Array.from(r.bytes(32));
  const root = parseTimestamp(r);
  if (r.p !== bytes.length) throw new Error("ots: trailing bytes");
  return { digest, root };
}
export const serializeOtsFile = ({ digest, root }) => concat(MAGIC, varuint(1), Uint8Array.of(OP.sha256), digest, serializeTimestamp(root));

async function sha(alg, b) { return new Uint8Array(await crypto.subtle.digest(alg, b)); }
// Aplica uma operação; null se não suportada aqui (ripemd160/keccak256 não existem em crypto.subtle).
export async function applyOp(op, arg, msg) {
  switch (op) {
    case OP.append: return concat(msg, arg);
    case OP.prepend: return concat(arg, msg);
    case OP.sha256: return sha("SHA-256", msg);
    case OP.sha1: return sha("SHA-1", msg);
    case OP.reverse: return Uint8Array.from(msg).reverse();
    case OP.hexlify: return new TextEncoder().encode(hex(msg));
    default: return null;
  }
}
export function pendingUri(att) { const r = new Reader(att.payload); return new TextDecoder().decode(r.varbytes(1000)); }
export function pendingAttestation(uri) { return { tag: TAG_PENDING, payload: varbytes(new TextEncoder().encode(uri)) }; }
export function hasBitcoin(node) { return node.attestations.some((a) => a.tag === TAG_BITCOIN) || node.ops.some((o) => hasBitcoin(o.child)); }

// Envia o hash às agendas. Como o cliente oficial, acrescenta um nonce aleatório antes de enviar.
export async function stamp(digest, calendars, fetchFn, nonce = crypto.getRandomValues(new Uint8Array(16))) {
  const inner = await sha("SHA-256", concat(digest, nonce));
  const merged = { attestations: [], ops: [] }, errors = [];
  await Promise.all(calendars.map(async (cal) => {
    try {
      const r = await fetchFn(cal.replace(/\/+$/, "") + "/digest", { method: "POST", body: inner, headers: { accept: "application/vnd.opentimestamps.v1", "content-type": "application/x-www-form-urlencoded" } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const body = new Uint8Array(await r.arrayBuffer());
      if (body.length > 10000) throw new Error("response too large");
      const reader = new Reader(body), node = parseTimestamp(reader);
      if (reader.p !== body.length) throw new Error("trailing bytes");
      mergeInto(merged, node);
    } catch (e) { errors.push(cal + ": " + e.message); }
  }));
  if (!merged.attestations.length && !merged.ops.length) return { ots: null, errors };
  const root = { attestations: [], ops: [{ op: OP.append, arg: nonce, child: { attestations: [], ops: [{ op: OP.sha256, arg: null, child: merged }] } }] };
  return { ots: serializeOtsFile({ digest, root }), errors };
}

// Atualiza atestados pendentes consultando só as agendas permitidas (evita SSRF).
export async function upgrade(bytes, allowedCalendars, fetchFn) {
  const file = parseOtsFile(bytes), allowed = allowedCalendars.map((c) => c.replace(/\/+$/, ""));
  const errors = [];
  let changed = false;
  async function walk(node, msg, depth) {
    if (depth > MAX_DEPTH) return;
    for (const att of [...node.attestations]) {
      if (att.tag !== TAG_PENDING) continue;
      let uri; try { uri = pendingUri(att).replace(/\/+$/, ""); } catch { continue; }
      if (!allowed.includes(uri)) { errors.push("calendar not allowed: " + uri); continue; }
      try {
        const r = await fetchFn(uri + "/timestamp/" + hex(msg), { headers: { accept: "application/vnd.opentimestamps.v1" } });
        if (r.status === 404) continue; // ainda pendente
        if (!r.ok) throw new Error("HTTP " + r.status);
        const body = new Uint8Array(await r.arrayBuffer()), reader = new Reader(body), up = parseTimestamp(reader);
        if (reader.p !== body.length) throw new Error("trailing bytes");
        mergeInto(node, up); changed = true;
        if (hasBitcoin(up)) node.attestations = node.attestations.filter((a) => a !== att);
      } catch (e) { errors.push(uri + ": " + e.message); }
    }
    for (const o of node.ops) {
      const next = await applyOp(o.op, o.arg, msg);
      if (next) await walk(o.child, next, depth + 1);
    }
  }
  await walk(file.root, file.digest, 0);
  return { ots: changed ? serializeOtsFile(file) : bytes, complete: hasBitcoin(file.root), errors };
}

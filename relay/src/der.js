// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
// DER mínimo: monta o TimeStampReq (RFC 3161) e lê o suficiente do TimeStampResp.

const OID_SHA256 = Uint8Array.of(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01);

function len(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const out = [];
  while (n) { out.unshift(n & 0xff); n >>>= 8; }
  return Uint8Array.of(0x80 | out.length, ...out);
}
export function tlv(tag, ...parts) {
  const body = concat(...parts);
  return concat(Uint8Array.of(tag), len(body.length), body);
}
export function concat(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0), out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// TimeStampReq { version 1, messageImprint { sha256, hash }, nonce, certReq TRUE }
export function timeStampRequest(hashBytes, nonceBytes) {
  if (hashBytes.length !== 32) throw new Error("hash must be 32 bytes");
  const nonce = Uint8Array.from(nonceBytes);
  nonce[0] = (nonce[0] & 0x7f) | 0x01; // positivo e sem zero à esquerda: codificação DER mínima
  return tlv(0x30,
    Uint8Array.of(0x02, 0x01, 0x01),
    tlv(0x30, tlv(0x30, OID_SHA256, Uint8Array.of(0x05, 0x00)), tlv(0x04, hashBytes)),
    tlv(0x02, nonce),
    Uint8Array.of(0x01, 0x01, 0xff));
}

function read(b, pos) {
  if (pos + 2 > b.length) throw new Error("DER truncated");
  const tag = b[pos];
  let l = b[pos + 1]; pos += 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    if (n === 0 || n > 4 || pos + n > b.length) throw new Error("bad DER length");
    l = 0; for (let i = 0; i < n; i++) l = l * 256 + b[pos + i];
    pos += n;
  }
  if (pos + l > b.length) throw new Error("DER truncated");
  return { tag, start: pos, end: pos + l };
}
function children(b, s, e) {
  const out = []; let p = s;
  while (p < e) { const t = read(b, p); out.push(t); p = t.end; }
  if (p !== e) throw new Error("malformed DER");
  return out;
}
const hex = (u) => Array.from(u, (x) => x.toString(16).padStart(2, "0")).join("");

// Confere status concedido e o hash carimbado (o relay não confia cegamente na TSA).
export function inspectTimeStampResp(der) {
  const top = read(der, 0);
  if (top.tag !== 0x30 || top.end !== der.length) throw new Error("not a TimeStampResp");
  const kids = children(der, top.start, top.end);
  const st = children(der, kids[0].start, kids[0].end);
  const status = der[st[0].start];
  if (st[0].end - st[0].start !== 1 || (status !== 0 && status !== 1)) throw new Error("TSA refused (status " + status + ")");
  if (kids.length < 2) throw new Error("no token");
  const ci = children(der, kids[1].start, kids[1].end);
  const sdSeq = read(der, ci[1].start), sd = children(der, sdSeq.start, sdSeq.end);
  const eci = children(der, sd[2].start, sd[2].end);
  const os = read(der, eci[1].start), tstSeq = read(der, os.start);
  const tst = children(der, tstSeq.start, tstSeq.end);
  const mi = children(der, tst[2].start, tst[2].end);
  const genTime = new TextDecoder().decode(der.subarray(tst[4].start, tst[4].end));
  return { status, imprint: hex(der.subarray(mi[1].start, mi[1].end)), genTime };
}

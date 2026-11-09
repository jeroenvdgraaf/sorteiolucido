// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
// "Primeiro bloco após o lacre" (SPEC 4.1, 10) contra uma cadeia simulada:
// slots perdidos, cabeça atrasada, lacre no início, meio e fim de um slot, reorganização, retomada tardia.
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadCore } from "./core_loader.mjs";

const C = await loadCore();
const G = C.ETH.genesis, SLOT = 12;
const slotTime = (s) => G + s * SLOT;
const BASE_SLOT = 15619600; // ~ novembro de 2026

// Cadeia simulada. Cada bloco aparece `delay` s depois do início do slot; a RPC pode atrasar `lag` blocos.
function makeChain({ missed = [], delay = 4, lag = 0, slots = 400, firstNumber = 23700000 } = {}) {
  const blocks = [];
  let n = firstNumber;
  for (let s = BASE_SLOT; s < BASE_SLOT + slots; s++) {
    if (missed.includes(s)) continue;
    blocks.push({ number: n, hash: "h" + n + "-a", timestamp: slotTime(s), visibleAt: slotTime(s) + delay });
    n++;
  }
  const chain = {
    now: slotTime(BASE_SLOT + 10), calls: 0, blocks,
    visible() { return blocks.filter((b) => b.visibleAt <= chain.now); },
    rpc: {
      head: async () => { chain.calls++; const v = chain.visible(); return v[v.length - 1 - lag].number; },
      block: async (num) => {
        chain.calls++;
        const v = chain.visible(), top = v[v.length - 1 - lag].number;
        if (num > top) return null;
        const b = blocks.find((x) => x.number === num);
        return b ? { number: b.number, hash: b.hash, timestamp: b.timestamp } : null;
      },
    },
    sleep: async (ms) => { chain.now += ms / 1000; },
  };
  return chain;
}
const nbOf = (sealMs) => Math.floor(sealMs / 1000);
function expectedTarget(chain, nb) {
  const i = chain.blocks.findIndex((b) => b.timestamp > nb);
  return { block: chain.blocks[i], parent: chain.blocks[i - 1] };
}
async function runDraw(chain, sealMs) {
  chain.now = sealMs / 1000;
  const src = { notBefore: nbOf(sealMs), confirmations: 1 };
  const ev = await C.waitEthTarget(chain.rpc, src, { sleep: chain.sleep, interval: 2000, maxTries: 500 });
  const exp = expectedTarget(chain, src.notBefore);
  assert.equal(ev.number, exp.block.number, "alvo");
  assert.ok(ev.timestamp > src.notBefore, "timestamp do alvo depois do lacre");
  assert.ok(ev.parentTimestamp <= src.notBefore, "antecessor não depois do lacre");
  assert.ok(ev.confirmations >= 1);
  // Aceito só depois que o bloco seguinte ficou visível.
  const next = chain.blocks.find((b) => b.number === ev.number + 1);
  assert.ok(chain.now >= next.visibleAt, "esperou a confirmação");
  return ev;
}

const S = BASE_SLOT + 20;
test("seal exactly at a slot start targets the NEXT slot (timestamp must be strictly after)", async () => {
  const chain = makeChain();
  const ev = await runDraw(chain, slotTime(S) * 1000);
  assert.equal(ev.timestamp, slotTime(S + 1));
});
test("seal in the middle of a slot: the current slot's block appears after the seal but is not used", async () => {
  const chain = makeChain({ delay: 9 }); // o bloco do slot S surge 3 s depois do lacre (armadilha do "head + 1")
  const ev = await runDraw(chain, (slotTime(S) + 6) * 1000 + 500);
  assert.equal(ev.timestamp, slotTime(S + 1));
});
test("seal at the end of a slot (last millisecond)", async () => {
  const chain = makeChain();
  const ev = await runDraw(chain, (slotTime(S) + 11) * 1000 + 999);
  assert.equal(ev.timestamp, slotTime(S + 1));
});
test("missed slot right after the seal: target is the next produced block, parent before the seal", async () => {
  const chain = makeChain({ missed: [S + 1, S + 2] });
  const ev = await runDraw(chain, (slotTime(S) + 3) * 1000);
  assert.equal(ev.timestamp, slotTime(S + 3));
  assert.equal(ev.parentTimestamp, slotTime(S));
});
test("missed slot at the seal slot itself", async () => {
  const chain = makeChain({ missed: [S] });
  const ev = await runDraw(chain, (slotTime(S) + 5) * 1000);
  assert.equal(ev.timestamp, slotTime(S + 1));
  assert.equal(ev.parentTimestamp, slotTime(S - 1));
});
test("lagging head: the RPC reports an old head; the finder waits instead of picking an earlier block", async () => {
  const chain = makeChain({ lag: 3 });
  const ev = await runDraw(chain, (slotTime(S) + 1) * 1000);
  assert.equal(ev.timestamp, slotTime(S + 1));
});
test("resume long after the seal: binary search, few RPC calls", async () => {
  const chain = makeChain({ missed: [S + 1] });
  const sealMs = (slotTime(S) + 7) * 1000;
  chain.now = slotTime(S + 300); chain.calls = 0;
  const src = { notBefore: nbOf(sealMs), confirmations: 1 };
  const ev = await C.waitEthTarget(chain.rpc, src, { sleep: chain.sleep });
  assert.equal(ev.timestamp, slotTime(S + 2));
  assert.ok(chain.calls < 40, "chamadas: " + chain.calls);
});
test("reorg during confirmation: the target is re-read and only the canonical block is accepted", async () => {
  const chain = makeChain();
  const sealMs = (slotTime(S) + 2) * 1000;
  chain.now = sealMs / 1000;
  const target = chain.blocks.find((b) => b.timestamp === slotTime(S + 1));
  let flipped = false;
  const statuses = [];
  const rpc = { ...chain.rpc, block: async (n) => {
    const b = await chain.rpc.block(n);
    // O bloco é visto uma vez já confirmado; logo depois a cadeia se reorganiza na mesma altura.
    if (b && n === target.number && !flipped && chain.visible().some((x) => x.number === target.number + 1)) { flipped = true; target.hash = "h" + n + "-reorg"; }
    return b;
  } };
  const ev = await C.waitEthTarget(rpc, { notBefore: nbOf(sealMs), confirmations: 1 }, { sleep: chain.sleep, onStatus: (s) => statuses.push(s.state) });
  assert.ok(statuses.includes("reorg"));
  assert.equal(ev.number, target.number);
  assert.equal(ev.hash, "h" + target.number + "-reorg");
});
test("never accepts a block whose timestamp is not after notBefore, even from a misbehaving RPC", async () => {
  const chain = makeChain();
  const sealMs = slotTime(S + 50) * 1000;
  chain.now = slotTime(S + 10); // a RPC nunca chega ao lacre
  const statuses = [];
  await assert.rejects(C.waitEthTarget(chain.rpc, { notBefore: nbOf(sealMs), confirmations: 1 }, { sleep: async () => {}, maxTries: 5, onStatus: (s) => statuses.push(s.state) }));
  assert.ok(statuses.every((s) => s === "pending"));
});
test("findEthTarget on an exact boundary and with two confirmations", async () => {
  const chain = makeChain();
  chain.now = slotTime(S + 5);
  const t = await C.findEthTarget(chain.rpc, slotTime(S));
  assert.equal(t.block.timestamp, slotTime(S + 1));
  assert.equal(t.parent.timestamp, slotTime(S));
  chain.now = (slotTime(S) + 1);
  const ev = await C.waitEthTarget(chain.rpc, { notBefore: slotTime(S), confirmations: 2 }, { sleep: chain.sleep });
  assert.ok(ev.confirmations >= 2);
  assert.ok(chain.now >= slotTime(S + 3) + 4);
});
test("makeEthRpc falls back to the next endpoint", async () => {
  const calls = [];
  const fetchJson = async (url, opts) => {
    calls.push(url);
    if (url === "https://a.example") throw new Error("down");
    const { method } = JSON.parse(opts.body);
    return method === "eth_blockNumber" ? { result: "0x10" } : { result: { number: "0xf", hash: "0xABC", timestamp: "0x64" } };
  };
  const rpc = C.makeEthRpc(() => ["https://a.example", "https://b.example"], fetchJson);
  assert.equal(await rpc.head(), 16);
  assert.deepEqual(await rpc.block(15), { number: 15, hash: "abc", timestamp: 100 });
  assert.deepEqual(calls.slice(0, 2), ["https://a.example", "https://b.example"]);
  const dead = C.makeEthRpc(() => ["https://a.example"], fetchJson);
  await assert.rejects(dead.head(), /Nenhum servidor Ethereum respondeu/);
});

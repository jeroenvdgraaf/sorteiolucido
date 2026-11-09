// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
// Conferência (SPEC 9) no núcleo do HTML: certificados de teste, adulterações, legado LucentDraw/1.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { loadCore, ROOT, HTML_PATH } from "./core_loader.mjs";
import { cert, clone, depsFor, statusOf, failing, flipHex, WORLD, readJson } from "./helpers.mjs";

const C = await loadCore();
const verify = (c, opts = {}, deps = depsFor()) => C.verifyCertificate(c, deps, opts);

test("v2 live eth+drand with RFC 3161 anchors: confere", async () => {
  const rep = await verify(cert("v2-live-eth-drand"));
  assert.equal(rep.verdict, "confere", rep.message);
  assert.deepEqual(statusOf(rep), { parse: "passou", spec: "passou", commitment: "passou", eth: "passou", drand: "passou", order: "passou", anchors: "passou", timing: "passou" });
  assert.equal(rep.drawId, "garagem-2027-blocoB");
});
test("v2 scheduled Mega-Sena with official result: confere", async () => {
  const rep = await verify(cert("v2-scheduled-megasena"));
  assert.equal(rep.verdict, "confere", rep.message);
});
test("Caixa blocked: lottery is 'não verificado automaticamente'; confirming by eye allows the verdict", async () => {
  const c = cert("v2-scheduled-megasena"), deps = depsFor(WORLD, { unreachable: ["megasena"] });
  let rep = await verify(c, {}, deps);
  assert.equal(statusOf(rep).megasena, "nao_verificado");
  assert.ok(rep.checks.find((x) => x.id === "megasena").detail.includes("3001:04-12-23-35-41-58"));
  assert.ok(rep.checks.find((x) => x.id === "megasena").detail.includes("loterias.caixa.gov.br"));
  assert.equal(rep.verdict, "incompleto");
  rep = await verify(c, { lotteryConfirmed: true }, deps);
  assert.equal(rep.verdict, "confere", rep.message);
});
test("manual Federal entry is flagged; no anchors gives 'atenção: sem carimbo de tempo' with deadline", async () => {
  const rep = await verify(cert("v2-scheduled-federal-drand-manual"));
  const st = statusOf(rep);
  assert.equal(st.federal, "passou");
  assert.match(rep.checks.find((x) => x.id === "federal").title, /inserido manualmente/);
  assert.equal(st.timing, "atencao");
  assert.match(rep.checks.find((x) => x.id === "timing").detail, /antes de 2026-11-11T22:00:00Z/);
  assert.equal(rep.verdict, "incompleto");
  assert.deepEqual(failing(rep), []);
});
test("anchor after the randomness: timing falhou", async () => {
  const rep = await verify(cert("v2-late-anchor"));
  assert.equal(statusOf(rep).timing, "falhou");
  assert.equal(rep.verdict, "nao_confere");
  assert.deepEqual(failing(rep), ["timing"]);
});
test("seal without randomness is pending, not failed", async () => {
  const rep = await verify(cert("v2-seal-only"));
  assert.deepEqual(failing(rep), []);
  assert.equal(statusOf(rep).eth, "nao_verificado");
  assert.equal(statusOf(rep).order, "nao_verificado");
});
test("legacy LucentDraw/1 certificate (prototype format) verifies", async () => {
  const rep = await verify(cert("v1-legacy-eth-drand"));
  const st = statusOf(rep);
  for (const k of ["parse", "spec", "commitment", "eth", "drand", "order"]) assert.equal(st[k], "passou", k);
  assert.equal(st.timing, "atencao");
  assert.deepEqual(failing(rep), []);
});
test("unknown version is rejected", async () => {
  const c = cert("v2-live-eth-drand"); c.spec.v = "LucentDraw/9";
  const rep = await verify(c);
  assert.deepEqual(failing(rep), ["parse"]);
});
test("network unavailable: sources 'não verificado', never 'confere'", async () => {
  const rep = await verify(cert("v2-live-eth-drand"), {}, depsFor(WORLD, { unreachable: ["eth", "drand"] }));
  assert.equal(statusOf(rep).eth, "nao_verificado");
  assert.equal(statusOf(rep).drand, "nao_verificado");
  assert.equal(statusOf(rep).order, "nao_verificado");
  assert.equal(rep.verdict, "incompleto");
});

// ---- adulterações: cada uma falha na checagem certa
const TAMPER = [
  ["one participant name in spec", "v2-live-eth-drand", (c) => { c.spec.candidates[2] = "Apto 201 · Pereirа"; }, ["anchors", "commitment", "order"], "commitment"],
  ["one name in the order", "v2-live-eth-drand", (c) => { c.order[0] = c.order[0] + "!"; }, ["order"], "order"],
  ["order swapped", "v2-live-eth-drand", (c) => { [c.order[0], c.order[1]] = [c.order[1], c.order[0]]; }, ["order"], "order"],
  ["one hex digit of the eth block hash", "v2-live-eth-drand", (c) => { c.randomness.eth.hash = flipHex(c.randomness.eth.hash); }, ["eth"], "eth"],
  ["one hex digit of the drand randomness", "v2-live-eth-drand", (c) => { c.randomness.drand.randomness = flipHex(c.randomness.drand.randomness); }, ["drand"], "drand"],
  ["one hex digit of the commitment", "v2-live-eth-drand", (c) => { c.commitment = flipHex(c.commitment); }, ["commitment"], "commitment"],
  ["one hex digit of the seed", "v2-live-eth-drand", (c) => { c.seed = flipHex(c.seed); }, ["order"], "order"],
  ["eth block number moved", "v2-live-eth-drand", (c) => { c.randomness.eth.number -= 1; }, ["eth"], "eth"],
  ["anchor time edited", "v2-live-eth-drand", (c) => { c.anchors[0].time = "2026-11-09T00:00:00Z"; }, ["anchors"], "anchors"],
  ["Mega-Sena number changed", "v2-scheduled-megasena", (c) => { c.randomness.megasena.numbers[0] = 5; }, ["megasena"], "megasena"],
  ["Federal prize order changed", "v2-scheduled-federal-drand-manual", (c) => { c.randomness.federal.prizes.reverse(); }, ["federal"], "federal"],
  ["legacy v1 name in spec", "v1-legacy-eth-drand", (c) => { c.spec.candidates[0] = "Apt 101 · Sousa"; }, ["commitment", "order"], "commitment"],
  ["legacy v1 order swapped", "v1-legacy-eth-drand", (c) => { c.order.reverse(); }, ["order"], "order"],
  ["duplicate participant", "v2-scheduled-megasena", (c) => { c.spec.candidates[1] = c.spec.candidates[0]; }, ["commitment", "order", "spec", "anchors"], "spec"],
];
for (const [name, fixture, mutate, expectedFails, main] of TAMPER) {
  test("tampering: " + name + " -> " + main + " falhou", async () => {
    const c = clone(cert(fixture)); mutate(c);
    const rep = await verify(c);
    assert.equal(rep.verdict, "nao_confere");
    assert.equal(statusOf(rep)[main], "falhou");
    assert.deepEqual(failing(rep), [...expectedFails].sort());
  });
}
test("reorg: the canonical block at the target height changed after the result", async () => {
  const world = clone(WORLD); world.eth.blocks["23700000"].hash = "ff".repeat(32);
  const rep = await verify(cert("v2-live-eth-drand"), {}, depsFor(world));
  assert.match(rep.checks.find((x) => x.id === "eth").title, /reorganização/);
  assert.equal(statusOf(rep).order, "falhou"); // a ordem pela regra muda
  assert.ok(rep.order && rep.order.length === 6);
});
test("eth block that is not the first after the seal fails", async () => {
  const world = clone(WORLD); world.eth.blocks["23699999"].timestamp = 1794260001;
  const rep = await verify(cert("v2-live-eth-drand"), {}, depsFor(world));
  assert.match(rep.checks.find((x) => x.id === "eth").title, /não é o primeiro/);
});
test("drand beacon whose randomness is not SHA-256(signature) fails", async () => {
  const world = clone(WORLD); world.drand["33819214"].randomness = flipHex(world.drand["33819214"].randomness);
  const rep = await verify(cert("v2-live-eth-drand"), {}, depsFor(world));
  assert.equal(statusOf(rep).drand, "falhou");
});

// ---- drand-client real (cópia idêntica à fixada no HTML) com uma chave de TESTE
const VENDOR = join(ROOT, "tests", "vendor", "drand-client-1.4.2", "index.mjs");
test("vendored drand-client is byte-identical to the pinned integrity hash", () => {
  const html = readFileSync(HTML_PATH, "utf8");
  const sri = "sha384-" + createHash("sha384").update(readFileSync(VENDOR)).digest("base64");
  assert.equal(sri, "sha384-NA5O1QMT0tvgBTDU3OWQdlH5HIDoRWPAvKkyh2FmyzQc/hofoTURtZ8qA7B+d4bi");
  assert.ok(html.includes('"https://cdn.jsdelivr.net/npm/drand-client@1.4.2/build/esm/index.mjs": "' + sri + '"'));
});
test("drand path: library BLS check through makeDrandClient, endpoint fallback, forged signature rejected", async () => {
  const lib = await import(VENDOR);
  const beacons = readJson("drand_test_beacons.json");
  const info = { ...C.QUICKNET.info, public_key: beacons.publicKey };
  const b = beacons.beacons[0], seen = [];
  const fetchJson = async (url) => {
    seen.push(url);
    if (url.startsWith("https://down.example")) throw new Error("down");
    const r = Number(url.split("/").pop());
    const x = beacons.beacons.find((y) => y.round === r); if (!x) throw new Error("404");
    return { ...x, ...(url.includes("forged") ? { signature: beacons.beacons[1].signature, randomness: beacons.beacons[1].randomness } : {}) };
  };
  const client = C.makeDrandClient(fetchJson, ["https://down.example", "https://up.example"], info);
  const got = await C.fetchVerifiedBeacon(lib, client, b.round);
  assert.deepEqual(got, { round: b.round, randomness: b.randomness, signature: b.signature });
  assert.ok(seen[0].startsWith("https://down.example") && seen[1].startsWith("https://up.example/" + info.hash + "/public/"));
  // Mesma resposta com a chave verdadeira da quicknet: a assinatura de teste é recusada.
  await assert.rejects(C.fetchVerifiedBeacon(lib, C.makeDrandClient(fetchJson, ["https://up.example"]), b.round));
  // Assinatura válida de outra rodada: recusada.
  await assert.rejects(C.fetchVerifiedBeacon(lib, C.makeDrandClient(fetchJson, ["https://forged.example"], info), b.round));
});

// ---- requisitos estáticos do HTML (SPEC 2, 7.5, 8, 10)
test("HTML: single file, no innerHTML, only the pinned drand-client from jsDelivr", () => {
  const html = readFileSync(HTML_PATH, "utf8");
  for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"]) assert.ok(!html.includes(sink), sink);
  assert.ok(!/<script[^>]+src=/i.test(html), "nenhum <script src>");
  assert.ok(!/<link[^>]+rel=["']?stylesheet/i.test(html), "nenhuma folha de estilo externa");
  const imports = [...html.matchAll(/import\(["']([^"']+)["']\)/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(imports)], ["drand-client"]);
  const map = JSON.parse(/<script type="importmap">([\s\S]*?)<\/script>/.exec(html)[1]);
  assert.deepEqual(Object.keys(map.imports), ["drand-client"]);
  assert.ok(map.imports["drand-client"].startsWith("https://cdn.jsdelivr.net/npm/drand-client@1.4.2/"));
  assert.ok(map.integrity[map.imports["drand-client"]].startsWith("sha384-"));
  assert.ok(!/api[_-]?key/i.test(html));
  assert.ok(html.includes('lang="pt-BR"'));
  assert.ok(html.includes("prefers-color-scheme: dark") && html.includes('[data-theme="dark"]') && html.includes("prefers-reduced-motion"));
});
test("HTML: every data-s key exists in the strings table; relay warning text is the SPEC's", () => {
  const html = readFileSync(HTML_PATH, "utf8");
  const keys = [...html.matchAll(/\sdata-s(?:-aria|-ph)?="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(keys.length > 40);
  for (const k of keys) assert.equal(typeof C.STR[k], "string", k);
  assert.equal(C.STR.noRelay, "Sem carimbo de tempo: compartilhe o lacre agora para ter prova de que ele veio antes do sorteio.");
  assert.equal(C.STR.errEthNone, "Nenhum servidor Ethereum respondeu. Confira a conexão ou edite a lista em Detalhes técnicos.");
  // A superfície principal não fala de Bitcoin; o OTS é "registro público de longo prazo".
  const strings = JSON.stringify(C.STR, (k, v) => (typeof v === "function" ? v.toString() : v));
  assert.ok(!/bitcoin/i.test(strings) && !/blockchain/i.test(strings));
});

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
// Núcleo do protocolo (extraído do SorteioLucido.html): vetores da SPEC 11 e regras auxiliares.
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadCore } from "./core_loader.mjs";
import { readJson, cert } from "./helpers.mjs";

const C = await loadCore();
const { vectors } = readJson("vectors.json");

for (const v of vectors) {
  test("SPEC 11 · " + v.name, async () => {
    const spec = JSON.parse(v.canonical);
    assert.equal(C.canon(spec), v.canonical, "canonical JSON");
    assert.deepEqual(C.validateSpec(spec), []);
    const commitment = await C.commitmentOf(spec);
    assert.equal(commitment, v.C, "commitment");
    const seed = await C.seedV2(commitment, v.values);
    assert.equal(seed, v.seed, "seed");
    assert.equal(await C.keyV2(seed, v.key[0]), v.key[1], "key");
    assert.deepEqual((await C.orderV2(seed, spec.candidates)).map((r) => r.name), v.order, "order");
  });
}

test("canonical JSON: key order by code point, UTF-8 raw, integers only", () => {
  assert.equal(C.canon({ b: 1, a: [true === true ? "é" : "", "x\"y"], "ä": 2, Z: 3 }), '{"Z":3,"a":["é","x\\"y"],"b":1,"ä":2}');
  assert.equal(C.canon({ "\u{1F600}": 1, "\uFFFF": 2 }), '{"\uFFFF":2,"\u{1F600}":1}'); // code point, não UTF-16
  assert.throws(() => C.canon({ a: 1.5 }));
  assert.throws(() => C.checkJsonTypes({ a: true }));
});

test("names: NFC, trimmed, blank lines dropped, duplicates reported", () => {
  const r = C.parseNames("  Ana \n\nCe\u0301lia\r\nCélia\n\u00a0Bruno\u00a0\n");
  assert.deepEqual(r.names, ["Ana", "Célia", "Célia", "Bruno"]);
  assert.deepEqual(r.dups, ["Célia"]);
});

test("spec validation: duplicates, empty list, one name, unknown source, extra fields", () => {
  const base = JSON.parse(vectors[1].canonical);
  const bad = (patch) => C.validateSpec({ ...base, ...patch });
  assert.ok(bad({ candidates: ["A", "A"] }).some((p) => p.includes("repetidos")));
  assert.ok(bad({ candidates: [] }).length);
  assert.ok(bad({ candidates: ["Só um"] }).some((p) => p.includes("pelo menos 2")));
  assert.ok(bad({ candidates: ["A ", "B"] }).some((p) => p.includes("normalizado")));
  assert.ok(bad({ sources: { bitcoin: {} } }).some((p) => p.includes("desconhecida")));
  assert.ok(bad({ extra: 1 }).some((p) => p.includes("desconhecidos")));
  assert.ok(bad({ mode: "other" }).length);
  assert.ok(bad({ id: "" }).length);
  assert.ok(bad({ sources: { megasena: { contest: 3001, x: 1 } } }).length);
});

test("drand round selection is 'at or after' (SPEC 4.2)", () => {
  const t = C.drandRoundTime(1000);
  assert.equal(C.drandRoundAtOrAfter(t), 1000);
  assert.equal(C.drandRoundAtOrAfter(t + 1), 1001);
  assert.equal(C.drandRoundAtOrAfter(t - 1), 1000);
  const seal = Date.UTC(2026, 10, 9, 13, 20, 5, 123);
  for (const [preset, lead] of [["drand", 6000], ["eth+drand", 36000]]) {
    const r = C.planSources(preset, seal).drand.round;
    assert.ok(C.drandRoundTime(r) >= seal + lead && C.drandRoundTime(r - 1) < seal + lead, preset);
  }
  const drawMs = C.brtMs("2026-11-11", "19:00");
  const r = C.planSources("federal+drand", seal, { contest: 5900, drawMs }).drand.round;
  assert.ok(C.drandRoundTime(r) >= drawMs + 7200000 && C.drandRoundTime(r - 1) < drawMs + 7200000);
});

test("planSources produces exactly the spec fields of SPEC 4", () => {
  const s = C.planSources("eth+drand", 1794260000999);
  assert.deepEqual(s.eth, { chain: "ethereum-mainnet", rule: "first-block-after", notBefore: 1794260000, confirmations: 1 });
  assert.deepEqual(Object.keys(s.drand).sort(), ["chain", "chainHash", "round"]);
  assert.deepEqual(C.planSources("megasena", 0, { contest: 3001, drawMs: 0 }), { megasena: { contest: 3001 } });
});

test("lottery value strings (SPEC 4.3, 4.4)", () => {
  assert.equal(C.megasenaValue(3001, [58, 4, 41, 12, 35, 23]), "3001:04-12-23-35-41-58");
  assert.equal(C.federalValue(5900, ["01234", "56789", "13579", "24680", "97531"]), "5900:01234-56789-13579-24680-97531");
});

test("lottery calendar suggestion: first draw >= 2 h after the seal", () => {
  const cal = { megasena: { weekdays: [2, 4, 6], time: "21:00", ref: { contest: 3000, date: "2026-11-07" } }, federal: { weekdays: [3, 6], time: "19:00", ref: null } };
  // Segunda 09/11/2026 12:00 BRT -> Mega-Sena terça 10/11, concurso 3001
  let s = C.suggestContest("megasena", C.brtMs("2026-11-09", "12:00"), cal);
  assert.deepEqual([s.date, s.contest], ["2026-11-10", 3001]);
  // Terça 19:30 BRT: menos de 2 h antes das 21:00 -> quinta 12/11, concurso 3002
  s = C.suggestContest("megasena", C.brtMs("2026-11-10", "19:30"), cal);
  assert.deepEqual([s.date, s.contest], ["2026-11-12", 3002]);
  assert.equal(C.dateForContest("megasena", 3003, cal), "2026-11-14");
  // Sem referência: sugere a data, não o número.
  s = C.suggestContest("federal", C.brtMs("2026-11-09", "12:00"), cal);
  assert.deepEqual([s.date, s.contest], ["2026-11-11", null]);
  assert.equal(s.drawMs, Date.UTC(2026, 10, 11, 22, 0));
});

test("Caixa normalization and manual entry", () => {
  assert.deepEqual(C.normalizeCaixa("megasena", 3001, { numero: 3001, dataApuracao: "02/03/2027", listaDezenas: ["58", "04", "12", "23", "35", "41"] }),
    { game: "megasena", contest: 3001, numbers: [4, 12, 23, 35, 41, 58], drawDate: "2027-03-02" });
  assert.equal(C.normalizeCaixa("megasena", 3001, { numero: 3002, listaDezenas: ["01", "02", "03", "04", "05", "06"] }), null);
  assert.equal(C.normalizeCaixa("megasena", 3001, { numero: 3001, listaDezenas: [] }), null);
  assert.deepEqual(C.normalizeCaixa("federal", 5900, { numero: 5900, dataApuracao: "11/11/2026", listaDezenas: ["001234", "056789", "013579", "024680", "097531"] }).prizes, ["01234", "56789", "13579", "24680", "97531"]);
  assert.deepEqual(C.parseManualLottery("megasena", "4 12, 23-35 41 58", "2027-03-02"), { numbers: [4, 12, 23, 35, 41, 58], drawDate: "2027-03-02" });
  assert.ok(C.parseManualLottery("megasena", "4 4 23 35 41 58", "2027-03-02").error);
  assert.ok(C.parseManualLottery("megasena", "4 12 23 35 41 61", "2027-03-02").error);
  assert.deepEqual(C.parseManualLottery("federal", "1234 56789 13579 24680 97531", "2026-11-11").prizes, ["01234", "56789", "13579", "24680", "97531"]);
  assert.ok(C.parseManualLottery("federal", "1 2 3 4", "2026-11-11").error);
  assert.ok(C.parseManualLottery("federal", "1 2 3 4 5", "").error);
});

test("RFC 3161: genTime and imprint read from an openssl-made token", () => {
  const c = cert("v2-live-eth-drand"), a = c.anchors[0];
  const p = C.parseTimestampResponse(C.b64ToBytes(a.token));
  assert.equal(p.imprint, c.commitment);
  assert.equal(p.hashAlg, C.OID.sha256);
  assert.equal(p.genTime, a.time);
  assert.match(a.time, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{3})?Z$/);
  assert.throws(() => C.parseTimestampResponse(C.b64ToBytes(a.token).subarray(0, 50)));
});

test("anchorsFromRelay drops tokens for another hash", () => {
  const c = cert("v2-live-eth-drand");
  const r = C.anchorsFromRelay({ rfc3161: [{ tsa: "x", token: c.anchors[0].token }], ots: "AAA=" }, "00".repeat(32));
  assert.equal(r.anchors.filter((a) => a.type === "rfc3161").length, 0);
  assert.equal(r.problems.length, 1);
  assert.deepEqual(r.anchors.find((a) => a.type === "ots"), { type: "ots", proof: "AAA=", complete: false });
});

test("certificate shape (SPEC 3.3), file name and ata (SPEC 7.3)", () => {
  const c = cert("v2-scheduled-federal-drand-manual");
  assert.deepEqual(Object.keys(c).sort(), ["anchors", "commitment", "order", "randomness", "sealedAt", "seed", "spec"]);
  const seal = C.certificateOf({ spec: c.spec, commitment: c.commitment, sealedAt: c.sealedAt, randomness: {} });
  assert.ok(!("seed" in seal) && !("order" in seal));
  assert.equal(C.certFileName("garagem-2027-blocoB"), "certificado-sorteio-garagem-2027-blocoB.json");
  assert.equal(C.certFileName("a/b c"), "certificado-sorteio-a_b_c.json");
  const ata = C.ataText(c);
  for (const s of [c.spec.title, c.spec.id, c.commitment, c.seed, "1. " + c.order[0], "inserido manualmente", "verify_draw.py", "Conferir", "Sem carimbo de tempo", "https://loterias.caixa.gov.br"]) assert.ok(ata.includes(s), s);
  assert.ok(!/bitcoin/i.test(ata));
  const ata2 = C.ataText(cert("v2-live-eth-drand"));
  assert.ok(ata2.includes("etherscan.io/block/23700000") && ata2.includes("/public/33819214") && ata2.includes("registro público de longo prazo"));
});

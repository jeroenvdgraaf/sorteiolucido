// Gera tests/fixtures/world.json (rede simulada) e tests/fixtures/certificates/*.json.
// Os certificados são produzidos pelo núcleo do próprio SorteioLucido.html; os tokens RFC 3161
// vêm do openssl com a TSA de TESTE; as rodadas drand vêm de drand_test_beacons.json (chave de TESTE).
//   node tests/tools/gen_fixtures.mjs
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { loadCore, ROOT } from "../core_loader.mjs";
import { timeStampRequest } from "../../relay/src/der.js";
import { stamp } from "../../relay/src/ots.js";
import { tsaReply } from "./tsa_reply.mjs";

const C = await loadCore();
const FIX = join(ROOT, "tests", "fixtures");
const beacons = JSON.parse(readFileSync(join(FIX, "drand_test_beacons.json"), "utf8"));
const beacon = (r) => { const b = beacons.beacons.find((x) => x.round === r); if (!b) throw new Error("no beacon " + r); return b; };
const h = (s) => createHash("sha256").update(s).digest("hex");

async function anchorsFor(commitment, withOts = true) {
  const digest = C.hexToBytes(commitment);
  const rfc3161 = ["https://tsa-test-a.example/tsr", "https://tsa-test-b.example/tsr"].map((tsa) => ({ tsa, token: tsaReply(timeStampRequest(digest, new Uint8Array(8).fill(7))).toString("base64") }));
  let ots = null;
  if (withOts) {
    // Agenda simulada: devolve append(…) sha256 → atestado pendente.
    const uri = Buffer.from("https://calendar.test.example");
    const fakeCal = async () => new Response(Buffer.concat([Buffer.from([0xf0, 4, 1, 2, 3, 4, 0x08, 0x00]), Buffer.from("83dfe30d2ef90c8e", "hex"), Buffer.from([uri.length + 1, uri.length]), uri]));
    const st = await stamp(digest, ["https://calendar.test.example"], fakeCal, new Uint8Array(16).fill(9));
    if (!st.ots) throw new Error("ots: " + st.errors.join("; "));
    ots = Buffer.from(st.ots).toString("base64");
  }
  return C.anchorsFromRelay({ rfc3161, ots }, commitment).anchors;
}
async function finish(state) {
  state.commitment = await C.commitmentOf(state.spec);
  if (state.anchorsFrom) { state.anchors = await anchorsFor(state.commitment, state.anchorsFrom === "ots"); delete state.anchorsFrom; }
  if (Object.keys(state.randomness).length) {
    state.seed = await C.seedV2(state.commitment, C.sourceValues(state.randomness));
    state.order = (await C.orderV2(state.seed, state.spec.candidates)).map((r) => r.name);
  }
  return C.certificateOf(state);
}

// ---- rede simulada
const world = {
  note: "Simulated network state for offline tests. All values are FAKE; drand beacons use a TEST key.",
  drandPublicKey: beacons.publicKey,
  eth: { head: 23700060, blocks: {} },
  drand: {},
  lottery: {
    "megasena/3001": { game: "megasena", contest: 3001, numbers: [4, 12, 23, 35, 41, 58], drawDate: "2027-03-02" },
    "federal/5900": { game: "federal", contest: 5900, prizes: ["01234", "56789", "13579", "24680", "97531"], drawDate: "2026-11-11" },
  },
};
const addBlock = (number, timestamp) => (world.eth.blocks[number] = { number, hash: h("block " + number), timestamp });
addBlock(23700000, 1794260015); addBlock(23699999, 1794259991); // slot 1794260003 perdido
addBlock(23000000, 1790000003); addBlock(22999999, 1789999991);
for (const b of beacons.beacons) world.drand[b.round] = b;
const ethEv = (n) => ({ number: n, hash: world.eth.blocks[n].hash, timestamp: world.eth.blocks[n].timestamp, parentTimestamp: world.eth.blocks[n - 1].timestamp, confirmations: 1 });
const drandEv = (r) => ({ round: r, randomness: beacon(r).randomness, signature: beacon(r).signature });

const v1spec = JSON.parse('{"candidates":["Apto 101 · Souza","Apto 102 · Oliveira","Apto 201 · Pereira","Apto 202 · Lima","Apto 301 · Carvalho","Apto 302 · Ribeiro"],"contribution":"4 6 1 3","id":"garagem-2027-blocoB","mode":"live","sources":{"drand":{"chain":"quicknet","chainHash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","round":33819214},"eth":{"chain":"ethereum-mainnet","confirmations":1,"notBefore":1794260000,"rule":"first-block-after"}},"title":"Vagas de garagem, bloco B","v":"LucentDraw/2"}');
const v2spec = JSON.parse('{"candidates":["P-0001","P-0002","P-0003","P-0004","P-0005"],"contribution":"","id":"fila-creche-2027-03","mode":"scheduled","sources":{"megasena":{"contest":3001}},"title":"Fila de creche, março 2027","v":"LucentDraw/2"}');
const v3spec = JSON.parse('{"candidates":["Ana","Bruno","Célia"],"contribution":"","id":"sorteio-federal-teste","mode":"scheduled","sources":{"drand":{"chain":"quicknet","chainHash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","round":33900000},"federal":{"contest":5900}},"title":"Teste Loteria Federal","v":"LucentDraw/2"}');

const certs = {};
certs["v2-live-eth-drand"] = await finish({ spec: v1spec, sealedAt: "2026-11-09T21:33:20.412Z", anchorsFrom: "ots", randomness: { eth: ethEv(23700000), drand: drandEv(33819214) } });
certs["v2-scheduled-megasena"] = await finish({ spec: v2spec, sealedAt: "2027-02-27T15:00:00.000Z", anchorsFrom: "rfc", randomness: { megasena: { contest: 3001, numbers: [4, 12, 23, 35, 41, 58], drawDate: "2027-03-02", source: "caixa-api" } } });
certs["v2-scheduled-federal-drand-manual"] = await finish({ spec: v3spec, sealedAt: "2026-11-09T12:00:00.000Z", randomness: { federal: { contest: 5900, prizes: ["01234", "56789", "13579", "24680", "97531"], drawDate: "2026-11-11", source: "manual" }, drand: drandEv(33900000) } });
const lateSpec = { v: "LucentDraw/2", id: "carimbo-atrasado", title: "Carimbo depois da rodada", mode: "live", candidates: ["A", "B", "C", "D"], contribution: "", sources: { drand: { chain: "quicknet", chainHash: C.QUICKNET.hash, round: 33700000 } } };
certs["v2-late-anchor"] = await finish({ spec: lateSpec, sealedAt: "2026-11-05T12:15:58.000Z", anchorsFrom: "rfc", randomness: { drand: drandEv(33700000) } });
const sealSpec = { v: "LucentDraw/2", id: "so-lacre", title: "", mode: "live", candidates: ["X", "Y"], contribution: "", sources: { eth: { chain: "ethereum-mainnet", rule: "first-block-after", notBefore: 1794260000, confirmations: 1 } } };
certs["v2-seal-only"] = await finish({ spec: sealSpec, sealedAt: "2026-11-09T21:33:20.000Z", randomness: {} });

// Legado LucentDraw/1, no formato exato do protótipo (reference/LucentDraw.html).
{
  const spec = { v: "LucentDraw/1", id: "garage-2026-blockB", title: "Garage spaces, block B", candidates: ["Apt 101 · Souza", "Apt 102 · Oliveira", "Apt 201 · Pereira", "Apt 202 · Lima"], contribution: "4 6 1 3",
    sources: { eth: { chain: "ethereum-mainnet", rule: "first block with timestamp > notBefore", notBefore: 1790000000, confirmations: 1, value: "block hash" }, drand: { chain: "quicknet", chainHash: C.QUICKNET.hash, round: 32398891 } } };
  const commitment = await C.commitmentOf(spec);
  const randomness = { drand: drandEv(32398891), eth: ethEv(23000000) };
  const seed = await C.seedV1(commitment, randomness.eth.hash, randomness.drand.randomness);
  const order = (await C.orderV1(seed, spec.candidates)).map((r) => r.name);
  certs["v1-legacy-eth-drand"] = { spec, commitment, sealedAt: "2026-09-21T13:33:20.000Z", randomness, seed, order, v: "LucentDraw/1" };
}

mkdirSync(join(FIX, "certificates"), { recursive: true });
for (const [name, cert] of Object.entries(certs)) writeFileSync(join(FIX, "certificates", name + ".json"), JSON.stringify(cert, null, 2) + "\n");
writeFileSync(join(FIX, "world.json"), JSON.stringify(world, null, 2) + "\n");
console.log("fixtures:", Object.keys(certs).join(", "));

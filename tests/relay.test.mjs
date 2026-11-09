// Relay (SPEC 6.2) com a rede simulada. As TSAs simuladas respondem com o openssl a partir do
// TimeStampReq que o próprio relay montou, o que testa a codificação DER do pedido.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { handle, DEFAULT_CONFIG } from "../relay/src/index.js";
import { parseOtsFile, serializeTimestamp, TAG_BITCOIN, TAG_PENDING, hasBitcoin, pendingAttestation } from "../relay/src/ots.js";
import { tsaReply } from "./tools/tsa_reply.mjs";
import { loadCore } from "./core_loader.mjs";

const C = await loadCore();
const HAS_OPENSSL = spawnSync("openssl", ["version"]).status === 0;
const HASH = "d6af4d8f3b6126c60afbc36e4f21d987f940e9c53b7ce230c135e026d88518fa";
const sha = (b) => createHash("sha256").update(b).digest();
const hex = (b) => Buffer.from(b).toString("hex");
const CAL = DEFAULT_CONFIG.otsCalendars[0];
const varbytes = (b) => Buffer.concat([Buffer.from([b.length]), b]);
// Resposta de agenda: append(01020304) sha256 -> pendente(CAL)
const calResponse = (uri = CAL) => Buffer.concat([Buffer.from([0xf0, 4, 1, 2, 3, 4, 0x08, 0x00]), Buffer.from(TAG_PENDING, "hex"), varbytes(varbytes(Buffer.from(uri)))]);

function mockNet(routes) {
  const calls = [];
  const fetchFn = async (url, init = {}) => {
    calls.push({ url, init });
    for (const [match, fn] of routes) if (typeof match === "string" ? url === match : match.test(url)) return fn(url, init);
    throw new Error("unexpected fetch " + url);
  };
  return { fetchFn, calls };
}
const post = (path, body, origin = "null") => new Request("https://relay.test" + path, { method: "POST", headers: { "content-type": "application/json", origin }, body: typeof body === "string" ? body : JSON.stringify(body) });

test("POST /v1/timestamp: two RFC 3161 tokens + OTS proof; ICP-Brasil disabled is never called", { skip: !HAS_OPENSSL && "openssl ausente" }, async () => {
  const net = mockNet([
    [/^https:\/\/freetsa\.org/, (u, i) => new Response(tsaReply(Buffer.from(i.body)))],
    [/^http:\/\/timestamp\.digicert\.com/, (u, i) => new Response(tsaReply(Buffer.from(i.body)))],
    [/\/digest$/, () => new Response(calResponse())],
  ]);
  const res = await handle(post("/v1/timestamp", { hash: HASH }), {}, net.fetchFn);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("access-control-allow-origin"), "*");
  const body = await res.json();
  assert.deepEqual(body.rfc3161.map((t) => t.tsa), ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]);
  // A página converte em âncoras e confere hash carimbado e genTime.
  const { anchors, problems } = C.anchorsFromRelay(body, HASH);
  assert.deepEqual(problems, []);
  assert.equal(anchors.filter((a) => a.type === "rfc3161").length, 2);
  for (const a of anchors.filter((x) => x.type === "rfc3161")) assert.ok(Math.abs(C.isoToMs(a.time) - Date.now()) < 120000);
  // Cabeçalho do pedido RFC 3161
  const tsq = net.calls.find((c) => c.url.includes("freetsa"));
  assert.equal(tsq.init.headers["content-type"], "application/timestamp-query");
  // O arquivo .ots começa no hash e chega à agenda por append(nonce) sha256
  const ots = parseOtsFile(Buffer.from(body.ots, "base64"));
  assert.equal(hex(ots.digest), HASH);
  const calCalls = net.calls.filter((c) => c.url.endsWith("/digest"));
  assert.equal(calCalls.length, 3);
  const nonce = ots.root.ops[0].arg;
  assert.equal(hex(calCalls[0].init.body), hex(sha(Buffer.concat([Buffer.from(HASH, "hex"), nonce]))));
  assert.ok(!net.calls.some((c) => /icp/i.test(c.url) || c.url === ""));
  assert.equal(DEFAULT_CONFIG.tsas.find((t) => t.name === "icp-brasil").enabled, false);
});

test("POST /v1/timestamp: one TSA down, token for another hash rejected, still answers", { skip: !HAS_OPENSSL && "openssl ausente" }, async () => {
  const other = C.hexToBytes("11".repeat(32));
  const { timeStampRequest } = await import("../relay/src/der.js");
  const net = mockNet([
    [/^https:\/\/freetsa\.org/, () => new Response("busy", { status: 503 })],
    [/^http:\/\/timestamp\.digicert\.com/, () => new Response(tsaReply(Buffer.from(timeStampRequest(other, new Uint8Array(8)))))],
    [/\/digest$/, () => new Response(calResponse())],
  ]);
  const res = await handle(post("/v1/timestamp", { hash: HASH }), {}, net.fetchFn);
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.deepEqual(body.rfc3161, []);
  assert.ok(body.ots);
  assert.equal(body.errors.length, 2);
  assert.ok(body.errors.some((e) => e.includes("different hash")));
});

test("POST /v1/timestamp: everything down -> 502; bad input -> 400", async () => {
  const net = mockNet([[/.*/, () => { throw new Error("offline"); }]]);
  assert.equal((await handle(post("/v1/timestamp", { hash: HASH }), {}, net.fetchFn)).status, 502);
  assert.equal((await handle(post("/v1/timestamp", { hash: "xyz" }), {}, net.fetchFn)).status, 400);
  assert.equal((await handle(post("/v1/timestamp", "{not json"), {}, net.fetchFn)).status, 400);
  assert.equal((await handle(post("/v1/timestamp", "x".repeat(5000)), {}, net.fetchFn)).status, 413);
});

test("ICP-Brasil can be switched on per deployment through TSAS, and only then is called", { skip: !HAS_OPENSSL && "openssl ausente" }, async () => {
  const tsas = JSON.stringify([{ name: "icp-brasil", url: "https://act.icp.test/tsr", enabled: true }]);
  const net = mockNet([[/icp\.test/, (u, i) => new Response(tsaReply(Buffer.from(i.body)))], [/\/digest$/, () => new Response(calResponse())]]);
  const body = await (await handle(post("/v1/timestamp", { hash: HASH }), { TSAS: tsas }, net.fetchFn)).json();
  assert.deepEqual(body.rfc3161.map((t) => t.tsa), ["https://act.icp.test/tsr"]);
});

async function freshOts() {
  const net = mockNet([[/\/digest$/, () => new Response(calResponse())]]);
  const env = { TSAS: "[]", OTS_CALENDARS: JSON.stringify([CAL]) };
  const body = await (await handle(post("/v1/timestamp", { hash: HASH }), env, net.fetchFn)).json();
  return { ots: body.ots, env, nonce: parseOtsFile(Buffer.from(body.ots, "base64")).root.ops[0].arg };
}
test("POST /v1/ots/upgrade: completes after a Bitcoin attestation; queries the right commitment", async () => {
  const { ots, env, nonce } = await freshOts();
  // mensagem no atestado pendente: sha256( sha256(hash || nonce) || 01020304 )
  const inner = sha(Buffer.concat([Buffer.from(HASH, "hex"), nonce]));
  const expected = hex(sha(Buffer.concat([inner, Buffer.from([1, 2, 3, 4])])));
  const upgraded = serializeTimestamp({ attestations: [], ops: [{ op: 0x08, arg: null, child: { attestations: [{ tag: TAG_BITCOIN, payload: Buffer.from([0x80, 0x9a, 0x3b]) }], ops: [] } }] });
  const net = mockNet([[CAL + "/timestamp/" + expected, () => new Response(upgraded)]]);
  const res = await handle(post("/v1/ots/upgrade", { ots }), env, net.fetchFn);
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.complete, true);
  assert.ok(hasBitcoin(parseOtsFile(Buffer.from(body.ots, "base64")).root));
});
test("POST /v1/ots/upgrade: still pending (404) and non-allowed calendars are not contacted", async () => {
  const { ots, env } = await freshOts();
  let net = mockNet([[/\/timestamp\//, () => new Response("", { status: 404 })]]);
  let body = await (await handle(post("/v1/ots/upgrade", { ots }), env, net.fetchFn)).json();
  assert.equal(body.complete, false);
  assert.equal(body.ots, ots);
  // Atestado apontando para um host interno: nunca consultado.
  const file = parseOtsFile(Buffer.from(ots, "base64"));
  file.root.ops[0].child.ops[0].child.attestations.push(pendingAttestation("http://169.254.169.254"));
  const { serializeOtsFile } = await import("../relay/src/ots.js");
  net = mockNet([[/.*/, () => new Response("", { status: 404 })]]);
  body = await (await handle(post("/v1/ots/upgrade", { ots: Buffer.from(serializeOtsFile(file)).toString("base64") }), env, net.fetchFn)).json();
  assert.ok(!net.calls.some((c) => c.url.includes("169.254")));
  assert.equal((await handle(post("/v1/ots/upgrade", { ots: "AAAA" }), env, net.fetchFn)).status, 400);
});

test("GET /v1/lottery: normalized result, 404 when not drawn, 502 upstream error, 400 bad contest", async () => {
  const net = mockNet([
    [/megasena\/3001$/, () => Response.json({ numero: 3001, dataApuracao: "02/03/2027", listaDezenas: ["04", "12", "23", "35", "41", "58"] })],
    [/federal\/5900$/, () => Response.json({ numero: 5900, dataApuracao: "11/11/2026", listaDezenas: ["001234", "056789", "013579", "024680", "097531"] })],
    [/megasena\/3002$/, () => Response.json({ numero: 3002, listaDezenas: [] })],
    [/megasena\/3003$/, () => new Response("", { status: 500 })],
    [/megasena\/9$/, () => new Response("", { status: 404 })],
  ]);
  const get = (p) => handle(new Request("https://relay.test" + p), {}, net.fetchFn);
  let r = await get("/v1/lottery/megasena/3001");
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { game: "megasena", contest: 3001, numbers: [4, 12, 23, 35, 41, 58], drawDate: "2027-03-02" });
  r = await get("/v1/lottery/federal/5900");
  assert.deepEqual((await r.json()).prizes, ["01234", "56789", "13579", "24680", "97531"]);
  assert.equal((await get("/v1/lottery/megasena/3002")).status, 404);
  assert.equal((await get("/v1/lottery/megasena/9")).status, 404);
  assert.equal((await get("/v1/lottery/megasena/3003")).status, 502);
  assert.equal((await get("/v1/lottery/megasena/0x10")).status, 400);
  assert.equal((await get("/v1/lottery/quina/1")).status, 404);
  assert.ok(net.calls.every((c) => c.url.startsWith(DEFAULT_CONFIG.caixaApi)));
  // A página aceita a resposta do relay quando a Caixa recusa o navegador.
  const fetchJson = async (url) => {
    if (url.startsWith(C.LOTTERY.api)) throw new TypeError("Failed to fetch (CORS)");
    const res = await get(new URL(url).pathname); if (!res.ok) throw Object.assign(new Error("HTTP " + res.status), { status: res.status }); return res.json();
  };
  assert.deepEqual((await C.fetchLottery(fetchJson, "megasena", 3001, "https://relay.test/")).numbers, [4, 12, 23, 35, 41, 58]);
  assert.equal(await C.fetchLottery(fetchJson, "megasena", 3002, "https://relay.test"), null);
  await assert.rejects(C.fetchLottery(fetchJson, "megasena", 3001, ""));
});

test("CORS preflight and restricted origins", async () => {
  let r = await handle(new Request("https://relay.test/v1/timestamp", { method: "OPTIONS", headers: { origin: "null" } }), {}, async () => { throw new Error(); });
  assert.equal(r.status, 204);
  assert.equal(r.headers.get("access-control-allow-origin"), "*");
  const env = { ALLOWED_ORIGINS: '["https://sorteio.example"]' };
  r = await handle(new Request("https://relay.test/", { headers: { origin: "https://evil.example" } }), env);
  assert.equal(r.headers.get("access-control-allow-origin"), null);
  r = await handle(new Request("https://relay.test/", { headers: { origin: "https://sorteio.example" } }), env);
  assert.equal(r.headers.get("access-control-allow-origin"), "https://sorteio.example");
  assert.equal((await handle(new Request("https://relay.test/nope"), {})).status, 404);
});

// Teste opcional da camada de interface (DOM) com jsdom. É pulado se o jsdom não estiver instalado:
//   npm i --prefix /tmp/jsdom jsdom@24 && JSDOM_DIR=/tmp/jsdom/node_modules ./run_tests.sh
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { HTML_PATH, loadCore } from "./core_loader.mjs";

let JSDOM = null;
try { JSDOM = createRequire(join(process.env.JSDOM_DIR || process.cwd(), "x.js"))("jsdom").JSDOM; } catch { /* opcional */ }
const C = await loadCore();
const html = readFileSync(HTML_PATH, "utf8");
const m = /<script type="module">([\s\S]*)<\/script>/.exec(html);
const shell = html.replace(m[0], "").replace(/<script type="importmap">[\s\S]*?<\/script>/, "");
const tick = (ms = 50) => new Promise((r) => setTimeout(r, ms));

function boot(storage = {}) {
  const dom = new JSDOM(shell, { runScripts: "outside-only", url: "https://example.test/", pretendToBeVisual: true });
  const w = dom.window, errors = [];
  Object.defineProperty(w, "crypto", { value: globalThis.crypto });
  w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder; w.matchMedia = () => ({ matches: false });
  w.fetch = async (url) => { throw new TypeError("offline " + url); }; // tudo bloqueado, inclusive a Caixa
  w.Element.prototype.scrollIntoView = () => {};
  for (const [k, v] of Object.entries(storage)) w.localStorage.setItem(k, v);
  w.addEventListener("unhandledrejection", (e) => errors.push(e.reason));
  w.eval("(async () => {" + m[1].replace(/await import\("drand-client"\)/, 'await Promise.reject(new Error("offline"))') + "\n})().catch(e => { window.__err = e; })");
  opened.push(w);
  return { w, errors, $: (id) => w.document.getElementById(id) };
}
const opened = [];
after(() => { for (const w of opened) w.close(); });

test("UI: prepare, seal without relay, one seal per ID, no HTML injection", { skip: !JSDOM && "jsdom não instalado" }, async () => {
  const { w, $, errors } = boot();
  await tick();
  assert.equal($("candCount").textContent, "6 participantes");
  $("cands").value = "A\nB\nA"; $("cands").dispatchEvent(new w.Event("input"));
  assert.match($("candErr").textContent, /Repetidos: A/);
  $("drawId").value = "x"; $("sealBtn").click(); await tick();
  assert.match($("sealErr").textContent, /repetidos/);
  $("cands").value = "Ana\nBruno\n<b>Célia</b>"; $("drawId").value = "teste-1";
  w.document.querySelector('input[name="preset"][value="drand"]').checked = true;
  $("sealBtn").click(); await tick(200);
  assert.match($("commitHash").textContent, /^[0-9a-f]{64}$/);
  assert.equal($("anchorMsg").textContent, C.STR.noRelay);
  assert.ok($("cands").disabled && $("sealBtn").disabled);
  assert.equal(w.document.querySelectorAll("b").length, [...w.document.querySelectorAll(".src b")].length); // nenhum <b> injetado
  $("newDraw").click(); $("drawId").value = "teste-1"; $("cands").value = "X\nY"; $("sealBtn").click(); await tick();
  assert.match($("sealErr").textContent, /já foi lacrado/);
  assert.equal($("otherIdBtn").hidden, false);
  assert.deepEqual(errors, []);
});

test("UI: scheduled draw reopened after the contest, Caixa blocked, manual entry verifies", { skip: !JSDOM && "jsdom não instalado" }, async () => {
  const spec = { v: "LucentDraw/2", id: "fila-federal-x", title: "Fila", mode: "scheduled", candidates: ["Ana", "Bruno", "Célia", "Davi"], contribution: "", sources: { federal: { contest: 5900 } } };
  const state = { spec, commitment: await C.commitmentOf(spec), sealedAt: "2026-11-09T12:00:00.000Z", anchors: [], randomness: {}, meta: { preset: "federal", lotteryDrawMs: Date.now() - 3600e3 } };
  const { w, $, errors } = boot({ "sorteiolucido.draws": JSON.stringify({ [spec.id]: state }), "sorteiolucido.current": JSON.stringify(spec.id) });
  await tick(300);
  assert.ok($("cands").disabled, "retomado e travado");
  assert.equal($("manualBox").hidden, false);
  $("manualNums").value = "1234 56789 13579 24680 97531"; $("manualDate").value = "2026-11-09"; $("manualConfirm").checked = true;
  $("manualSave").click(); await tick(200);
  const saved = JSON.parse(w.localStorage.getItem("sorteiolucido.draws"))[spec.id];
  assert.equal(saved.randomness.federal.source, "manual");
  assert.match($("ataText").textContent, /inserido manualmente/);
  const rep = await C.verifyCertificate(C.certificateOf(saved), { lottery: async () => { throw new Error("bloqueada"); } }, { lotteryConfirmed: true });
  assert.deepEqual(rep.checks.filter((c) => c.status === "falhou"), []);
  assert.equal(rep.checks.find((c) => c.id === "order").status, "passou");
  assert.deepEqual(errors, []);
});

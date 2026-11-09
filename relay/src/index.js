// SorteioLúcido · relay de carimbo de tempo (SPEC 6.2), Cloudflare Worker.
// Só repassa pedidos: nunca recebe a lista de participantes, só o hash (lacre). Sem estado além dos logs.
//
//   POST /v1/timestamp        { "hash": "<64 hex>" } -> { rfc3161: [{tsa, token}], ots, errors? }
//   POST /v1/ots/upgrade      { "ots": "<base64>" }  -> { ots, complete }
//   GET  /v1/lottery/<megasena|federal>/<contest>     -> resultado normalizado ou 404
import { timeStampRequest, inspectTimeStampResp } from "./der.js";
import { stamp, upgrade } from "./ots.js";
import { normalizeCaixa } from "./lottery.js";

export const DEFAULT_CONFIG = {
  // Duas TSAs gratuitas de organizações diferentes; ICP-Brasil presente mas DESLIGADA (SPEC 6.1).
  tsas: [
    { name: "freetsa", url: "https://freetsa.org/tsr", enabled: true },
    { name: "digicert", url: "http://timestamp.digicert.com", enabled: true },
    { name: "icp-brasil", url: "", enabled: false, note: "carimbo do tempo ICP-Brasil: exige certificado da empresa e contrato com autoridade credenciada" },
  ],
  otsCalendars: ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com"],
  caixaApi: "https://servicebus2.caixa.gov.br/portaldeloterias/api/",
  allowedOrigins: ["*"],
  timeoutMs: 15000,
};

function jsonVar(env, name, fallback) {
  const v = env && env[name];
  if (v == null || v === "") return fallback;
  if (typeof v !== "string") return v;
  try { return JSON.parse(v); } catch { throw new Error("invalid JSON in variable " + name); }
}
export function configFrom(env) {
  return {
    tsas: jsonVar(env, "TSAS", DEFAULT_CONFIG.tsas),
    otsCalendars: jsonVar(env, "OTS_CALENDARS", DEFAULT_CONFIG.otsCalendars),
    caixaApi: (env && env.CAIXA_API) || DEFAULT_CONFIG.caixaApi,
    allowedOrigins: jsonVar(env, "ALLOWED_ORIGINS", DEFAULT_CONFIG.allowedOrigins),
    timeoutMs: Number((env && env.TIMEOUT_MS) || DEFAULT_CONFIG.timeoutMs),
  };
}

const b64 = (u) => { let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const fromHex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));

function cors(req, cfg) {
  const origin = req.headers.get("origin");
  const allow = cfg.allowedOrigins.includes("*") ? "*" : origin && cfg.allowedOrigins.includes(origin) ? origin : null;
  const h = { "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "content-type", "access-control-max-age": "86400", vary: "origin" };
  if (allow) h["access-control-allow-origin"] = allow;
  return h;
}
const json = (req, cfg, status, body, extra = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...cors(req, cfg), ...extra } });

async function readJson(req, max) {
  const text = await req.text();
  if (text.length > max) throw Object.assign(new Error("body too large"), { status: 413 });
  try { return JSON.parse(text); } catch { throw Object.assign(new Error("invalid JSON"), { status: 400 }); }
}
function withTimeout(fetchFn, ms) {
  return async (url, init = {}) => {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), ms);
    try { return await fetchFn(url, { ...init, signal: ctl.signal }); } finally { clearTimeout(t); }
  };
}

async function timestampHandler(req, cfg, fetchFn) {
  const body = await readJson(req, 1024);
  const hash = typeof body.hash === "string" ? body.hash.toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(hash)) return json(req, cfg, 400, { error: "hash must be 64 hex characters" });
  const digest = fromHex(hash), errors = [];
  const tsas = cfg.tsas.filter((t) => t.enabled && t.url);
  const rfc = await Promise.all(tsas.map(async (t) => {
    try {
      const tsq = timeStampRequest(digest, crypto.getRandomValues(new Uint8Array(8)));
      const r = await fetchFn(t.url, { method: "POST", body: tsq, headers: { "content-type": "application/timestamp-query", accept: "application/timestamp-reply" } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const der = new Uint8Array(await r.arrayBuffer());
      if (der.length > 65536) throw new Error("response too large");
      const info = inspectTimeStampResp(der);
      if (info.imprint !== hash) throw new Error("TSA stamped a different hash");
      return { tsa: t.url, token: b64(der) };
    } catch (e) { errors.push(t.url + ": " + e.message); return null; }
  }));
  const st = await stamp(digest, cfg.otsCalendars, fetchFn);
  errors.push(...st.errors);
  const out = { rfc3161: rfc.filter(Boolean), ots: st.ots ? b64(st.ots) : null };
  if (errors.length) out.errors = errors;
  console.log(JSON.stringify({ path: "/v1/timestamp", hash: hash.slice(0, 12), tokens: out.rfc3161.length, ots: !!out.ots, errors: errors.length }));
  if (!out.rfc3161.length && !out.ots) return json(req, cfg, 502, { error: "no timestamp service answered", errors });
  return json(req, cfg, 200, out);
}

async function upgradeHandler(req, cfg, fetchFn) {
  const body = await readJson(req, 96 * 1024);
  if (typeof body.ots !== "string" || !body.ots) return json(req, cfg, 400, { error: "ots must be base64" });
  let bytes;
  try { bytes = unb64(body.ots); } catch { return json(req, cfg, 400, { error: "ots must be base64" }); }
  try {
    const r = await upgrade(bytes, cfg.otsCalendars, fetchFn);
    console.log(JSON.stringify({ path: "/v1/ots/upgrade", complete: r.complete, errors: r.errors.length }));
    return json(req, cfg, 200, { ots: b64(r.ots), complete: r.complete });
  } catch (e) { return json(req, cfg, 400, { error: e.message }); }
}

async function lotteryHandler(req, cfg, fetchFn, game, contestStr) {
  const contest = parseInt(contestStr, 10);
  if (!/^[1-9][0-9]{0,6}$/.test(contestStr)) return json(req, cfg, 400, { error: "invalid contest" });
  let r;
  try { r = await fetchFn(cfg.caixaApi + game + "/" + contest, { headers: { accept: "application/json" } }); }
  catch (e) { return json(req, cfg, 502, { error: "upstream unreachable: " + e.message }); }
  if (r.status === 404) return json(req, cfg, 404, { error: "not found" });
  if (!r.ok) return json(req, cfg, 502, { error: "upstream HTTP " + r.status });
  let j;
  try { j = await r.json(); } catch { return json(req, cfg, 502, { error: "upstream sent invalid JSON" }); }
  const n = normalizeCaixa(game, contest, j);
  console.log(JSON.stringify({ path: "/v1/lottery", game, contest, found: !!n }));
  if (!n) return json(req, cfg, 404, { error: "no result for this contest yet" });
  return json(req, cfg, 200, n, { "cache-control": "public, max-age=3600" });
}

export async function handle(req, env = {}, fetchFn = fetch) {
  let cfg;
  try { cfg = configFrom(env); } catch (e) { return new Response(JSON.stringify({ error: e.message }), { status: 500 }); }
  const f = withTimeout(fetchFn, cfg.timeoutMs);
  const url = new URL(req.url);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req, cfg) });
  try {
    if (req.method === "POST" && url.pathname === "/v1/timestamp") return await timestampHandler(req, cfg, f);
    if (req.method === "POST" && url.pathname === "/v1/ots/upgrade") return await upgradeHandler(req, cfg, f);
    const m = /^\/v1\/lottery\/(megasena|federal)\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && m) return await lotteryHandler(req, cfg, f, m[1], m[2]);
    if (req.method === "GET" && url.pathname === "/") return json(req, cfg, 200, { service: "SorteioLúcido timestamp relay", endpoints: ["POST /v1/timestamp", "POST /v1/ots/upgrade", "GET /v1/lottery/<megasena|federal>/<contest>"] });
    return json(req, cfg, 404, { error: "not found" });
  } catch (e) {
    return json(req, cfg, e.status || 500, { error: e.status ? e.message : "internal error" });
  }
}

export default { fetch: (req, env) => handle(req, env) };

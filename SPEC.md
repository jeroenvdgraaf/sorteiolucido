# SorteioLúcido — implementation spec

Protocol: **LucentDraw/2**. Product: **SorteioLúcido** (Brazilian Portuguese UI), part of the LucentCrypto family. The English prototype `LucentDraw.html` (protocol LucentDraw/1) exists and is the starting point.

This document is written as input for an implementer, human or AI. Where it says MUST, the behavior is part of the protocol and affects verification; everything else is product guidance. When in doubt, ask instead of guessing: a different hash input means certificates that no longer verify.

---

## 1. What the product does

SorteioLúcido runs random draws that anyone can check afterwards without trusting the operator.

1. **Prepare:** the operator enters a title, a draw ID and a list of participants, and picks a randomness source.
2. **Seal:** the app freezes everything into a JSON object (`spec`), hashes it into the **commitment**, and timestamps that commitment with independent services. The form locks.
3. **Draw:** the app waits for the randomness the seal points to (a future Ethereum block, a drand round, or a Mega-Sena / Loteria Federal contest), then computes the order deterministically from the commitment and that randomness.
4. **Certificate:** the app outputs a **draw certificate** (JSON) and a human-readable **ata do sorteio**.
5. **Verify:** any person can load a certificate and recompute everything.

The security argument: the participant list is fixed before the randomness exists, the randomness cannot be chosen by the operator, and the order follows from a published rule. The one thing software cannot prove is that the seal was shared before the randomness appeared; the timestamps in section 6 provide that evidence.

### Use cases
- **Live** (assembly, meeting, online call): garage spaces in a condominium, speaking order, picking committee members. Result in about 10–30 seconds.
- **Scheduled** (announced days ahead): waiting lists for daycare or housing, draws whose date is set in an edital. Result after the chosen lottery contest.

### Out of scope for this version
Listed in section 12 so they are not built by accident.

---

## 2. Deliverable

- **One self-contained HTML file** (`SorteioLucido.html`) that runs locally in current Chrome, Edge, Firefox and Safari, on desktop and phone. No build step required to use it.
- **Plus one small optional server component**, the *timestamp relay* (section 6), because timestamp servers do not accept requests from a browser page. The HTML must work without the relay; it then skips timestamping and says so.
- **A reference verifier in Python** (`verify_draw.py`, standard library only, plus `requests` for fetching) implementing section 9. It is the second, independent implementation; the HTML and the Python verifier must agree on the test vectors in section 11.

Libraries in the HTML: only `drand-client` (for BLS verification), loaded from jsDelivr, pinned to an exact version **and** to its content hash (import map `integrity`, as in the prototype). No other third-party code. No API keys anywhere.

---

## 3. Data model

### 3.1 Canonical encoding (MUST)
- **Text:** every string is Unicode NFC-normalized and trimmed of leading and trailing whitespace before it enters `spec`.
- **Canonical JSON:** object keys sorted by code point, no whitespace, separators `,` and `:`, non-ASCII characters written as UTF-8 (not `\u` escapes). This equals Python `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8.
- **Numbers:** integers only inside `spec`. No floats, no booleans as numbers.
- **Hashes:** SHA-256, written as 64 lowercase hex characters without `0x`.
- **Hex values from outside** (block hashes, drand randomness): lowercase, `0x` stripped, before use.

### 3.2 `spec`: the sealed object (MUST)

```json
{
  "v": "LucentDraw/2",
  "id": "garagem-2027-blocoB",
  "title": "Vagas de garagem, bloco B",
  "mode": "live",
  "candidates": ["Apto 101 · Souza", "Apto 102 · Oliveira"],
  "contribution": "4 6 1 3",
  "sources": { "eth": { ... }, "drand": { ... } }
}
```

| Field | Rule |
|---|---|
| `v` | Exactly `"LucentDraw/2"`. |
| `id` | Draw ID, non-empty. Announced in advance; one seal per ID (section 8). |
| `title` | Free text, may be empty. |
| `mode` | `"live"` or `"scheduled"`. Informational; verification does not depend on it. |
| `candidates` | At least 2 entries, each non-empty after normalization, **all distinct** (exact string comparison after NFC). Order as entered. Blank lines in the input are dropped; duplicates are an error, never silently merged. |
| `contribution` | Optional free text from the operator or people present (dice, a phrase). May be `""`. |
| `sources` | Non-empty object; keys from section 4. |

### 3.3 Draw certificate (output)

```json
{
  "spec": { ... },
  "commitment": "<SHA-256 of canonical spec>",
  "sealedAt": "2026-11-09T13:20:05.123Z",
  "anchors": [ ... ],
  "randomness": { "eth": { ... }, "drand": { ... } },
  "seed": "<hex>",
  "order": ["Apto 201 · Pereira", "..."]
}
```

- `sealedAt` is the operator's claim; the `anchors` are the evidence (section 6).
- `randomness` holds one entry per source, with the fields defined in section 4.
- A certificate whose randomness has not arrived yet has an empty `randomness`, no `seed` and no `order`. The UI calls it a *seal*, not a certificate.

---

## 4. Randomness sources (MUST)

Each source has (a) parameters fixed in `spec.sources.<name>`, (b) a **value string** used in the seed, and (c) evidence stored in `certificate.randomness.<name>`.

### 4.1 `eth`: next Ethereum block (live)

`spec.sources.eth`:
```json
{ "chain": "ethereum-mainnet", "rule": "first-block-after", "notBefore": 1794260000, "confirmations": 1 }
```
- `notBefore` = `floor(sealTimeMs / 1000)`, unix seconds.
- **Target block:** the first canonical block with `timestamp > notBefore`. Ethereum timestamps are exact slot start times (genesis `1606824023`, 12 s slots), so this block's slot started after the seal. Do not target "head + 1": a block appears a few seconds after its slot starts, so head + 1 can have a timestamp before the seal.
- **Accept** only when `head ≥ target.number + confirmations`, and re-read the target block to confirm its hash is unchanged.
- **Value string:** the block hash.
- **Evidence:** `{ "number", "hash", "timestamp", "parentTimestamp", "confirmations" }`.
- **Reorg rule:** the canonical block at the target height counts. If a reorg replaces it after the result was shown, the result changes; the verifier reports this clearly.
- **Access:** public JSON-RPC endpoints, user-editable list, tried in order (defaults: `https://ethereum-rpc.publicnode.com`, `https://eth.llamarpc.com`, `https://1rpc.io/eth`). Methods: `eth_blockNumber`, `eth_getBlockByNumber(hex, false)`.

### 4.2 `drand`: drand quicknet (live)

`spec.sources.drand`:
```json
{ "chain": "quicknet", "chainHash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", "round": 33819214 }
```
- Round timing: genesis `1692803367`, period 3 s; round `r` is published at `genesis + (r − 1) × 3`.
- **Choosing the round at seal time:** drand alone: first round at or after seal + 6 s. Combined with `eth`: first round at or after seal + 36 s, so it falls after the Ethereum block is confirmed. Combined with a lottery: first round at or after the lottery's scheduled draw time + 2 hours.
- **Value string:** the round's `randomness`.
- **Evidence:** `{ "round", "randomness", "signature" }`.
- **Verification:** BLS signature check against the quicknet public key (via `drand-client`), and `randomness == SHA-256(signature bytes)`. Fetch from `https://api.drand.sh/<chainHash>/public/<round>`; fall back to `https://drand.cloudflare.com/<chainHash>/public/<round>`.

### 4.3 `megasena`: Mega-Sena (scheduled)

`spec.sources.megasena`: `{ "contest": 3001 }`
- **Value string:** `"<contest>:<n1>-<n2>-<n3>-<n4>-<n5>-<n6>"`, the six drawn numbers in **ascending** order, two digits each. Example: `"3001:04-12-23-35-41-58"`.
- **Evidence:** `{ "contest", "numbers": [4,12,23,35,41,58], "drawDate": "YYYY-MM-DD", "source": "caixa-api" | "manual" }`.

### 4.4 `federal`: Loteria Federal (scheduled)

`spec.sources.federal`: `{ "contest": 5900 }`
- **Value string:** `"<contest>:<p1>-<p2>-<p3>-<p4>-<p5>"`, the five winning ticket numbers **in prize order** (1st to 5th prize), as published, zero-padded to five digits. Example: `"5900:01234-56789-13579-24680-97531"`.
- **Evidence:** `{ "contest", "prizes": ["01234", ...], "drawDate", "source" }`.

### 4.5 Getting lottery results
- Caixa publishes results on its lottery portal (`https://loterias.caixa.gov.br`). There is an unofficial JSON endpoint behind it (`https://servicebus2.caixa.gov.br/portaldeloterias/api/<megasena|federal>/<contest>`). **Verify it before relying on it**: it is undocumented, may refuse browser requests (CORS) or non-Brazilian IPs, and may change.
- The app tries the endpoint (directly, or through the relay if configured). If that fails, it asks the operator to type the result, with a link to the official page, and records `"source": "manual"`.
- **The verifier always shows the numbers it used and links to the official page**, so the person verifying can compare by eye.
- **Postponed draws:** the contest number defines the value; the certificate stays pending until that contest has a result.
- **Choosing the contest at seal time:** the app suggests the first contest whose scheduled draw is at least 2 hours after the seal (the operator can choose a later one). The app must know the draw calendar; keep it as a small editable table (weekdays and time), and show the operator the date it assumes. **Check the current Caixa schedule when implementing.**

### 4.6 Allowed combinations (UI presets)

| Preset | Sources | Typical wait |
|---|---|---|
| Ao vivo · Ethereum (default for live) | `eth` | 15–30 s |
| Ao vivo · drand | `drand` | 6–9 s |
| Ao vivo · Ethereum + drand | `eth`, `drand` | about 40 s |
| Agendado · Loteria Federal (default for scheduled) | `federal` | until the contest |
| Agendado · Mega-Sena | `megasena` | until the contest |
| Agendado · lottery + drand | `federal` or `megasena`, plus `drand` | contest + about 2 h |

Bitcoin is deliberately not a randomness source.

---

## 5. Computing the order (MUST)

```
C    = SHA-256( canonicalJSON(spec) )
seed = SHA-256( "LucentDraw/2" + "\n" + "seed" + "\n" + C + "\n"
                + "eth="      + (value or "-") + "\n"
                + "drand="    + (value or "-") + "\n"
                + "megasena=" + (value or "-") + "\n"
                + "federal="  + (value or "-") )
key(name) = SHA-256( "LucentDraw/2" + "\n" + "key" + "\n" + seed + "\n" + name )
order = candidates sorted by key ascending (compare the hex strings); ties broken by name in code-point order
```

- All strings are UTF-8. No trailing newline after the last line.
- Sources appear in the fixed order `eth, drand, megasena, federal`, each line present, `-` for an unused source.
- Ties have probability ~2⁻²⁵⁶; the tie-break exists only so the rule is total.
- Equal chances for every candidate. Weighted draws are a later feature (section 12) and will use a different, explicitly named rule.

### Legacy LucentDraw/1 (prototype certificates)
The verifier MUST also accept `v: "LucentDraw/1"`: seed = `SHA-256("LucentDraw/1\nseed\n" + C + "\n" + (eth block hash or "-") + "\n" + (drand randomness or "-"))`, key = `SHA-256("LucentDraw/1\nkey\n" + seed + "\n" + name)`, ascending, no tie-break; its `eth` source uses `notBefore` and `confirmations` as in 4.1 and stores `randomness.eth.hash`.

---

## 6. Timestamps (anchoring the seal)

Purpose: evidence that the commitment existed before the randomness. Essential for scheduled draws; useful for live draws with remote participants.

### 6.1 Providers
- **RFC 3161 time-stamping:** two free servers from different organizations, configurable (defaults: `https://freetsa.org/tsr` and `http://timestamp.digicert.com`). Request a timestamp on the 32-byte commitment (SHA-256 message imprint).
- **OpenTimestamps:** submit the commitment to the public calendars; store the incomplete proof; upgrade it later (it completes after a Bitcoin block, hours later). In the UI call it "registro público de longo prazo", never "Bitcoin".
- **ICP-Brasil timestamp (carimbo do tempo):** same RFC 3161 protocol, **present in the configuration but disabled by default**; enabled per deployment once a company certificate and a contract with an accredited authority exist. No code path may require it.

### 6.2 The relay
Browsers cannot call these services directly. Specify and build a minimal relay (any small server; no state beyond logs):

```
POST /v1/timestamp
  body: { "hash": "<64 hex>" }
  200:  { "rfc3161": [ { "tsa": "<url>", "token": "<base64 DER TimeStampResp>" }, ... ],
          "ots": "<base64 .ots file>" }
POST /v1/ots/upgrade
  body: { "ots": "<base64>" }  →  { "ots": "<base64>", "complete": true|false }
GET  /v1/lottery/<megasena|federal>/<contest>  →  normalized result or 404
```

The relay only forwards; it never sees the participant list. Its URL is a setting in the HTML. Without it, the seal step says: "Sem carimbo de tempo: compartilhe o lacre agora para ter prova de que ele veio antes do sorteio."

### 6.3 In the certificate
`anchors`: `[ { "type": "rfc3161", "tsa": "...", "token": "...", "time": "<genTime from the token>" }, { "type": "ots", "proof": "...", "complete": false } ]`.

### 6.4 Verification of anchors
- **v1:** the HTML shows each token's provider and `genTime` (parse the DER enough to read `genTime` and the message imprint, and check the imprint equals the commitment). Full signature-chain validation is done by the Python verifier (`openssl ts -verify` or `rfc3161` / `asn1crypto` libraries) and documented.
- **Rule shown to the user:** the earliest anchor time must be before the randomness: before the target Ethereum slot, the drand round time, or the lottery's draw time. The verifier states this comparison explicitly as pass/fail when anchors exist, and as "não verificável" when they do not.

---

## 7. User interface (pt-BR)

### 7.1 Structure
- Two tabs: **Sortear** and **Conferir**.
- **Sortear** has three steps in order: **1 Preparar**, **2 Lacrar**, **3 Resultado**, plus a status column showing each source's progress and a countdown.
- A mode switch at the top: **Ao vivo** / **Agendado**, which selects the presets in 4.6.
- Technical details (hashes, endpoints, block numbers, relay URL) live in collapsed **Detalhes técnicos** sections. The main surface never says "blockchain", "Ethereum" or "Bitcoin" without context; the source names appear as "bloco público Ethereum", "farol drand", "Mega-Sena", "Loteria Federal".

### 7.2 Behavior
- Live count of participants; duplicate names shown as an error before sealing.
- **Sealing locks the form.** Changing anything requires starting a new draw.
- After sealing, the commitment is shown large, with **Copiar lacre** and a hint to share it now (group chat, projector, minutes).
- **Resume:** a sealed draw survives a reload (localStorage, wrapped in try/catch) and continues waiting for the same targets. Scheduled draws can be closed and reopened days later; reopening fetches the result if available.
- **Result:** ordered table (position, participant, short key with full key on hover), the source values with links (Etherscan block page, drand round JSON, Caixa results page), and the seed.
- **Outputs:** download the certificate as `certificado-sorteio-<id>.json`; copy it; show the **ata do sorteio** (section 7.3) as text with a copy button.

### 7.3 Ata do sorteio
Plain text in Portuguese, generated from the certificate: title, draw ID, date and time of sealing, number of participants, sources and their values with official links, the commitment, the anchors (provider and time), the resulting order, and a closing paragraph: how anyone can verify (open SorteioLúcido, tab Conferir, load the certificate; or run `verify_draw.py`). No claim the software has not checked.

### 7.4 Conferir (verify) tab
Load a certificate (paste or file). Show a list of checks, each **passou / falhou / não verificado / atenção**, then a one-line verdict. Checks are listed in section 9.

### 7.5 Language and copy
- All UI strings in Brazilian Portuguese, kept in one strings table so an English version can be added later.
- Errors say what went wrong and what to do, e.g. "Nenhum servidor Ethereum respondeu. Confira a conexão ou edite a lista em Detalhes técnicos."
- Accessibility: keyboard navigation, visible focus, `prefers-reduced-motion`, light and dark themes, usable at 400 px width.

---

## 8. Security requirements

- **No HTML injection:** participant names and all external data are inserted with `textContent`, never `innerHTML`.
- **One seal per draw ID:** the app keeps a local list of IDs it has sealed and refuses to reseal the same ID without an explicit "novo sorteio com outro ID". The verifier shows the draw ID prominently and reminds the user that a second seal with the same ID invalidates the draw. (A shared registry of IDs via the anchoring log is future work.)
- **Strict first-block rule** for `eth` (4.1); never accept a target block whose timestamp is not after `notBefore`.
- **drand:** never accept a beacon without the BLS check; the library is pinned by version and integrity hash.
- **No secrets** in the file; no analytics; network requests only to the sources, the configured endpoints and the relay. State this in the footer.
- **Clock independence:** the app's own clock is used only for UX (countdowns) and for `notBefore`/round selection at seal time. Verification never depends on the verifier's clock.
- **Manual lottery entry** is marked as such in the certificate and in the ata.

---

## 9. Verification algorithm (MUST, in both HTML and Python)

1. **Parse** the certificate; reject unknown `v`.
2. **Spec well-formed:** names are NFC, trimmed, non-empty, distinct; at least 2; sources known.
3. **Commitment:** recompute C; must equal `commitment`.
4. **Each source**, fetched independently (never trusting values in the certificate):
   - `eth`: read block `number` and `number − 1`; pass if `block.timestamp > notBefore ≥ parent.timestamp`, and the canonical hash equals `randomness.eth.hash`; report current confirmations.
   - `drand`: fetch the round, check BLS and `randomness = SHA-256(signature)`; must equal the certificate's value.
   - `megasena` / `federal`: fetch the official result if reachable and compare; otherwise show the certificate's numbers with the official link and mark **não verificado automaticamente**.
5. **Seed and order:** recompute; `order` must equal the certificate's `order`.
6. **Timing:** if anchors exist, compare the earliest anchor time with the randomness time of each source (6.4). If none exist, show **atenção: sem carimbo de tempo** and the deadline the seal must have been shared before.
7. **Verdict:** "Este sorteio confere." only if every check is *passou* (with lottery checks allowed to be *não verificado* when the verifier confirmed by eye). Otherwise "Este sorteio não confere" listing failures.

---

## 10. Acceptance criteria

- The test vectors in section 11 produce exactly the listed commitment, seed and order, in the HTML and in `verify_draw.py`.
- A live Ethereum draw finishes within 40 s on a normal connection; a drand draw within 15 s.
- Reloading during the wait resumes and produces the same result.
- A seal made mid-slot targets the next slot's block, never a block whose timestamp precedes the seal (unit test with a simulated chain: missed slots, lagging head, seal at the start, middle and end of a slot).
- Duplicate names, an empty list, or one name cannot be sealed.
- A certificate edited in any field (one name, one hex digit of a value, the order) fails verification with the right check named.
- A scheduled Loteria Federal draw sealed today, reopened after the contest, completes and verifies; with the Caixa endpoint blocked, manual entry works and is marked as manual.
- With the relay unavailable, sealing still works and the warning in 6.2 is shown.
- No `innerHTML` with user data (grep check); the drand library loads only with its integrity hash.

---

## 11. Test vectors

Values marked *fake* are invented for testing and do not come from the real sources. Each `canonical` line is the exact byte string hashed into C (UTF-8).

### Vector 1: live, `eth` + `drand`
```
canonical: {"candidates":["Apto 101 · Souza","Apto 102 · Oliveira","Apto 201 · Pereira","Apto 202 · Lima","Apto 301 · Carvalho","Apto 302 · Ribeiro"],"contribution":"4 6 1 3","id":"garagem-2027-blocoB","mode":"live","sources":{"drand":{"chain":"quicknet","chainHash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","round":33819214},"eth":{"chain":"ethereum-mainnet","confirmations":1,"notBefore":1794260000,"rule":"first-block-after"}},"title":"Vagas de garagem, bloco B","v":"LucentDraw/2"}
C:        d6af4d8f3b6126c60afbc36e4f21d987f940e9c53b7ce230c135e026d88518fa
eth   (fake): 1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f
drand (fake): a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7
seed:     e6052659239924d144fb683dd4d71292946626dbf6c452b6af1ec72f423a065b
key("Apto 101 · Souza"): f4a0899c86332231cf4cf1da90c8f19c3229f391123addd6ef7a82eeb32d5a38
order:    Apto 201 · Pereira, Apto 301 · Carvalho, Apto 202 · Lima, Apto 102 · Oliveira, Apto 302 · Ribeiro, Apto 101 · Souza
```

### Vector 2: scheduled, Mega-Sena
```
canonical: {"candidates":["P-0001","P-0002","P-0003","P-0004","P-0005"],"contribution":"","id":"fila-creche-2027-03","mode":"scheduled","sources":{"megasena":{"contest":3001}},"title":"Fila de creche, março 2027","v":"LucentDraw/2"}
C:        4c00fc31ab02a166240237f26088b55f94d05c6986868f5c16c76813cd06576c
megasena (fake): 3001:04-12-23-35-41-58
seed:     a69966fa7ecc95fc8c0ad94187568a061dfd6809ec9f4ff1851e54cc0f7413be
key("P-0001"): d801509502752e603e2e6f0ca934532fbec03cf998b3297949322a02b723d53d
order:    P-0002, P-0005, P-0001, P-0003, P-0004
```

### Vector 3: scheduled, Loteria Federal + drand
```
canonical: {"candidates":["Ana","Bruno","Célia"],"contribution":"","id":"sorteio-federal-teste","mode":"scheduled","sources":{"drand":{"chain":"quicknet","chainHash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","round":33900000},"federal":{"contest":5900}},"title":"Teste Loteria Federal","v":"LucentDraw/2"}
C:        5a02f062f672c1834288773aece0dd6c8fdd0de5493f1b213f4976f4f636d0a8
federal (fake): 5900:01234-56789-13579-24680-97531
drand   (fake): 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
seed:     1fb0af54c3e3969e706823b2f5dac496e7bd8d9a8960ac6f98e29a8ddf903c24
key("Ana"): 0425c05ec105ff7ffbb12ea4b1d59cafe3bcaaa6fab6309a7d333e524ca51658
order:    Ana, Bruno, Célia   (coincides with the input order; a valid outcome)
```

### Reference code (Python, for checking an implementation)
```python
import hashlib, json
H = lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest()
def C_of(spec): return H(json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
def seed_of(C, vals):  # vals: dict source -> value string
    lines = ["LucentDraw/2", "seed", C] + [f"{k}={vals.get(k, '-')}" for k in ("eth", "drand", "megasena", "federal")]
    return H("\n".join(lines))
def order_of(seed, names):
    return sorted(names, key=lambda n: (H("LucentDraw/2\nkey\n" + seed + "\n" + n), n))
```

---

## 12. Later (do not build now)

- **Weighted draws:** weights per participant as exact numbers (`3`, `0.35`, `1/7`), stored as text, converted to integers over a common denominator; selection position by position using `SHA-256(seed, position)` as a big integer, reduced into the remaining total weight with rejection sampling; integer arithmetic only (no floating-point keys). Shown as each participant's percentage. Named rule `"weighted"` in `spec`.
- **Tiers / priority groups** for waiting lists, and the category-to-weight table published with an edital.
- **FilaLúcida:** an append-only log of applications, documents and signed decisions, alternating with scheduled draws.
- **Participant contributions** collected remotely, with inclusion receipts.
- **ICP-Brasil timestamps** switched on; signed atas.
- **Shared registry of draw IDs** in the anchoring log.
- **English UI** (LucentDraw), Spanish UI.
- **AmigoLúcido** (secret-friend draw with households and helpers).

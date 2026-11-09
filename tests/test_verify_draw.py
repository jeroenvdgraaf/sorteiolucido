# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jeroen van de Graaf
"""Testes do verificador de referência verify_draw.py (rodam sem rede)."""
import base64
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "verifier"))
sys.path.insert(0, HERE)

import verify_draw as v  # noqa: E402
import world as w  # noqa: E402

VECTORS = w.load("vectors.json")["vectors"]
BEACONS = w.load("drand_test_beacons.json")
TEST_PK = BEACONS["publicKey"]
TSA_CA = os.path.join(w.FIX, "tsa", "ca.crt")
OTHER_CA = os.path.join(w.FIX, "tsa", "other-ca.crt")
HAS_OPENSSL = shutil.which("openssl") is not None


def verify(cert, fetched=None, **kw):
    kw.setdefault("drand_pubkey", TEST_PK)
    return v.verify_certificate(cert, w.fetched_for(cert) if fetched is None else fetched, **kw)


def status(rep):
    return {c["id"]: c["status"] for c in rep["checks"]}


def failing(rep):
    return sorted(c["id"] for c in rep["checks"] if c["status"] == v.FAIL)


def flip(h, i=10):
    return h[:i] + ("1" if h[i] == "0" else "0") + h[i + 1:]


class Vectors(unittest.TestCase):
    def test_spec_section_11(self):
        for vec in VECTORS:
            with self.subTest(vec["name"]):
                spec = json.loads(vec["canonical"])
                self.assertEqual(v.canonical_json(spec), vec["canonical"])
                self.assertEqual(v.validate_spec(spec), [])
                C = v.commitment_of(spec)
                self.assertEqual(C, vec["C"])
                seed = v.seed_v2(C, vec["values"])
                self.assertEqual(seed, vec["seed"])
                self.assertEqual(v.key_v2(seed, vec["key"][0]), vec["key"][1])
                self.assertEqual(v.order_v2(seed, spec["candidates"]), vec["order"])

    def test_spec_reference_code_agrees(self):
        # O código de referência da SPEC 11, literalmente.
        import hashlib
        H = lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest()  # noqa: E731

        def seed_of(C, vals):
            lines = ["LucentDraw/2", "seed", C] + [f"{k}={vals.get(k, '-')}" for k in ("eth", "drand", "megasena", "federal")]
            return H("\n".join(lines))

        for vec in VECTORS:
            self.assertEqual(seed_of(vec["C"], vec["values"]), v.seed_v2(vec["C"], vec["values"]))

    def test_value_strings(self):
        self.assertEqual(v.megasena_value(3001, [58, 4, 41, 12, 35, 23]), "3001:04-12-23-35-41-58")
        self.assertEqual(v.federal_value(5900, ["01234", "56789", "13579", "24680", "97531"]),
                         "5900:01234-56789-13579-24680-97531")

    def test_canonical_rules(self):
        self.assertRaises(ValueError, v.canonical_json, {"a": 1.5})
        self.assertRaises(ValueError, v.canonical_json, {"a": True})
        self.assertEqual(v.norm_text("﻿ Célia "), "Célia")
        self.assertEqual(v.norm_text("\x1fA"), "\x1fA")  # mesmo conjunto do String.prototype.trim


class BLS(unittest.TestCase):
    def test_rfc9380_hash_to_g1_vectors(self):
        dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"
        x, y = v.hash_to_g1(b"", dst)
        self.assertEqual(x, 0x052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1)
        self.assertEqual(y, 0x08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265)
        x, _ = v.hash_to_g1(b"abc", dst)
        self.assertEqual(x, 0x03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903)

    def test_quicknet_public_key_is_a_valid_g2_point(self):
        v.g2_decompress(bytes.fromhex(v.QUICKNET_PUBKEY))

    def test_beacon_signature(self):
        b = BEACONS["beacons"][0]
        self.assertTrue(v.drand_beacon_valid(b["round"], b["signature"], TEST_PK))
        self.assertFalse(v.drand_beacon_valid(b["round"] + 1, b["signature"], TEST_PK))
        self.assertFalse(v.drand_beacon_valid(b["round"], BEACONS["beacons"][1]["signature"], TEST_PK))
        self.assertFalse(v.drand_beacon_valid(b["round"], b["signature"], v.QUICKNET_PUBKEY))
        self.assertFalse(v.drand_beacon_valid(b["round"], flip(b["signature"], 50), TEST_PK))


class Certificates(unittest.TestCase):
    def test_live_eth_drand_confere(self):
        rep = verify(w.cert("v2-live-eth-drand"))
        self.assertEqual(rep["verdict"], "confere", rep["message"])
        self.assertEqual(set(status(rep).values()), {v.PASS})
        self.assertEqual(rep["drawId"], "garagem-2027-blocoB")

    def test_megasena_confere_and_caixa_blocked(self):
        c = w.cert("v2-scheduled-megasena")
        self.assertEqual(verify(c)["verdict"], "confere")
        f = w.fetched_for(c, unreachable=("megasena",))
        rep = verify(c, f)
        self.assertEqual(status(rep)["megasena"], v.UNVERIFIED)
        detail = next(x for x in rep["checks"] if x["id"] == "megasena")["detail"]
        self.assertIn("3001:04-12-23-35-41-58", detail)
        self.assertIn("loterias.caixa.gov.br", detail)
        self.assertEqual(rep["verdict"], "incompleto")
        self.assertEqual(verify(c, f, lottery_confirmed=True)["verdict"], "confere")

    def test_manual_federal_and_no_anchor(self):
        rep = verify(w.cert("v2-scheduled-federal-drand-manual"))
        st = status(rep)
        self.assertEqual(st["federal"], v.PASS)
        self.assertIn("manualmente", next(x for x in rep["checks"] if x["id"] == "federal")["title"])
        self.assertEqual(st["timing"], v.WARN)
        self.assertEqual(rep["verdict"], "incompleto")

    def test_late_anchor(self):
        rep = verify(w.cert("v2-late-anchor"))
        self.assertEqual(failing(rep), ["timing"])

    def test_seal_only_is_pending(self):
        rep = verify(w.cert("v2-seal-only"))
        self.assertEqual(failing(rep), [])
        self.assertEqual(status(rep)["eth"], v.UNVERIFIED)

    def test_legacy_v1(self):
        rep = verify(w.cert("v1-legacy-eth-drand"))
        st = status(rep)
        for k in ("parse", "spec", "commitment", "eth", "drand", "order"):
            self.assertEqual(st[k], v.PASS, k)
        self.assertEqual(st["timing"], v.WARN)

    def test_unknown_version(self):
        c = w.cert("v2-live-eth-drand")
        c["spec"]["v"] = "LucentDraw/9"
        self.assertEqual(failing(verify(c)), ["parse"])

    def test_offline_is_never_confere(self):
        c = w.cert("v2-live-eth-drand")
        rep = verify(c, w.fetched_for(c, unreachable=("eth", "drand")))
        self.assertEqual(status(rep)["eth"], v.UNVERIFIED)
        self.assertEqual(status(rep)["order"], v.UNVERIFIED)
        self.assertEqual(rep["verdict"], "incompleto")

    def test_reorg_reported(self):
        c = w.cert("v2-live-eth-drand")
        world = copy.deepcopy(w.WORLD)
        world["eth"]["blocks"]["23700000"]["hash"] = "ff" * 32
        rep = verify(c, w.fetched_for(c, world))
        eth = next(x for x in rep["checks"] if x["id"] == "eth")
        self.assertIn("reorganização", eth["title"])
        self.assertEqual(status(rep)["order"], v.FAIL)

    def test_invalid_bls_from_source_fails(self):
        c = w.cert("v2-live-eth-drand")
        f = w.fetched_for(c)
        f["drand"]["signature"] = BEACONS["beacons"][1]["signature"]
        f["drand"]["randomness"] = BEACONS["beacons"][1]["randomness"]
        rep = verify(c, f)
        self.assertEqual(status(rep)["drand"], v.FAIL)
        self.assertIn("BLS", next(x for x in rep["checks"] if x["id"] == "drand")["title"])


TAMPER = [
    ("name in spec", "v2-live-eth-drand", lambda c: c["spec"]["candidates"].__setitem__(2, "Apto 201 · Pereirа"), ["anchors", "commitment", "order"], "commitment"),
    ("name in order", "v2-live-eth-drand", lambda c: c["order"].__setitem__(0, c["order"][0] + "!"), ["order"], "order"),
    ("order swapped", "v2-live-eth-drand", lambda c: c.__setitem__("order", [c["order"][1], c["order"][0]] + c["order"][2:]), ["order"], "order"),
    ("eth hash hex digit", "v2-live-eth-drand", lambda c: c["randomness"]["eth"].__setitem__("hash", flip(c["randomness"]["eth"]["hash"])), ["eth"], "eth"),
    ("drand hex digit", "v2-live-eth-drand", lambda c: c["randomness"]["drand"].__setitem__("randomness", flip(c["randomness"]["drand"]["randomness"])), ["drand"], "drand"),
    ("commitment hex digit", "v2-live-eth-drand", lambda c: c.__setitem__("commitment", flip(c["commitment"])), ["commitment"], "commitment"),
    ("seed hex digit", "v2-live-eth-drand", lambda c: c.__setitem__("seed", flip(c["seed"])), ["order"], "order"),
    ("anchor time", "v2-live-eth-drand", lambda c: c["anchors"][0].__setitem__("time", "2026-11-09T00:00:00Z"), ["anchors"], "anchors"),
    ("megasena number", "v2-scheduled-megasena", lambda c: c["randomness"]["megasena"]["numbers"].__setitem__(0, 5), ["megasena"], "megasena"),
    ("federal prize order", "v2-scheduled-federal-drand-manual", lambda c: c["randomness"]["federal"]["prizes"].reverse(), ["federal"], "federal"),
    ("v1 name", "v1-legacy-eth-drand", lambda c: c["spec"]["candidates"].__setitem__(0, "Apt 101 · Sousa"), ["commitment", "order"], "commitment"),
    ("v1 order", "v1-legacy-eth-drand", lambda c: c["order"].reverse(), ["order"], "order"),
    ("duplicate name", "v2-scheduled-megasena", lambda c: c["spec"]["candidates"].__setitem__(1, c["spec"]["candidates"][0]), ["anchors", "commitment", "order", "spec"], "spec"),
]


class Tampering(unittest.TestCase):
    def test_tampering_fails_with_the_right_check(self):
        for name, fixture, mutate, expected, main in TAMPER:
            with self.subTest(name):
                c = copy.deepcopy(w.cert(fixture))
                fetched = w.fetched_for(c)  # a rede não muda quando o certificado é adulterado
                mutate(c)
                rep = verify(c, fetched)
                self.assertEqual(rep["verdict"], "nao_confere")
                self.assertEqual(status(rep)[main], v.FAIL)
                self.assertEqual(failing(rep), sorted(expected))


@unittest.skipUnless(HAS_OPENSSL, "openssl ausente")
class TimestampTokens(unittest.TestCase):
    def setUp(self):
        self.cert = w.cert("v2-live-eth-drand")
        self.anchor = self.cert["anchors"][0]
        self.der = base64.b64decode(self.anchor["token"])

    def test_parse(self):
        t = v.parse_timestamp_response(self.der)
        self.assertEqual(t["imprint"], self.cert["commitment"])
        self.assertEqual(t["hashAlg"], v.OID_SHA256)
        self.assertEqual(t["genTime"], self.anchor["time"])

    def test_chain_valid_with_test_ca(self):
        val = v.openssl_tsa_validator([TSA_CA])
        st, note = val(self.der, v.parse_timestamp_response(self.der)["token"], self.cert["commitment"])
        self.assertEqual(st, v.PASS, note)
        rep = verify(self.cert, tsa_validator=val)
        self.assertIn("cadeia da TSA válidas", next(x for x in rep["checks"] if x["id"] == "anchors")["detail"])

    def test_untrusted_chain_is_warning(self):
        val = v.openssl_tsa_validator([OTHER_CA])
        rep = verify(self.cert, tsa_validator=val)
        self.assertEqual(status(rep)["anchors"], v.WARN)

    def test_broken_signature_fails(self):
        bad = bytearray(self.der)
        bad[-5] ^= 0x01  # dentro da assinatura, no fim do SignerInfo
        c = copy.deepcopy(self.cert)
        c["anchors"] = [dict(self.anchor, token=base64.b64encode(bytes(bad)).decode())]
        rep = verify(c, tsa_validator=v.openssl_tsa_validator([TSA_CA]))
        self.assertEqual(status(rep)["anchors"], v.FAIL)
        self.assertEqual(status(rep)["timing"], v.WARN)  # o token inválido não serve de prova de horário


class FakeResp:
    def __init__(self, status, payload):
        self.status_code, self._p = status, payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._p


class FakeSession:
    """Substitui `requests` nos testes da camada de rede."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def _go(self, url, body=None):
        self.calls.append(url)
        for prefix, fn in self.routes:
            if url.startswith(prefix):
                return fn(url, body)
        raise ConnectionError("offline: " + url)

    def get(self, url, **kw):
        return self._go(url)

    def post(self, url, json=None, **kw):
        return self._go(url, json)


class Network(unittest.TestCase):
    def test_fetch_all_with_fallbacks_then_verify(self):
        c = w.cert("v2-live-eth-drand")
        blocks = w.WORLD["eth"]["blocks"]

        def rpc(url, body):
            if body["method"] == "eth_blockNumber":
                return FakeResp(200, {"result": hex(w.WORLD["eth"]["head"])})
            b = blocks.get(str(int(body["params"][0], 16)))
            return FakeResp(200, {"result": b and {"number": hex(b["number"]), "hash": "0x" + b["hash"], "timestamp": hex(b["timestamp"])}})

        def drand(url, body):
            return FakeResp(200, w.WORLD["drand"][url.rsplit("/", 1)[1]])

        s = FakeSession([("https://second-rpc.example", rpc), ("https://drand.cloudflare.com", drand)])
        f = v.fetch_all(c, rpcs=("https://first-rpc.example", "https://second-rpc.example"), session=s)
        self.assertEqual(f["eth"]["block"]["hash"], c["randomness"]["eth"]["hash"])
        self.assertTrue(any("api.drand.sh" in u for u in s.calls))  # tentou o primeiro farol
        self.assertEqual(verify(c, f)["verdict"], "confere")

    def test_lottery_caixa_then_relay(self):
        caixa = {"numero": 3001, "dataApuracao": "02/03/2027", "listaDezenas": ["04", "12", "23", "35", "41", "58"]}
        s = FakeSession([("https://servicebus2.caixa.gov.br", lambda u, b: FakeResp(200, caixa))])
        self.assertEqual(v.fetch_lottery("megasena", 3001, session=s)["numbers"], [4, 12, 23, 35, 41, 58])
        relay = {"game": "federal", "contest": 5900, "prizes": ["01234", "56789", "13579", "24680", "97531"], "drawDate": "2026-11-11"}
        s = FakeSession([("https://relay.example", lambda u, b: FakeResp(200, relay))])
        self.assertEqual(v.fetch_lottery("federal", 5900, relay="https://relay.example", session=s), relay)
        self.assertIn("error", v.fetch_lottery("federal", 5900, session=FakeSession([])))
        self.assertEqual(v.normalize_caixa("federal", 5900, {"numero": 5900, "listaDezenas": ["001234", "056789", "013579", "024680", "097531"]})["prizes"],
                         ["01234", "56789", "13579", "24680", "97531"])


def dump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)


class CLI(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = v.main(list(args))
        return code, out.getvalue()

    def test_offline_values_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            c = w.cert("v2-scheduled-megasena")
            cp, vp = os.path.join(d, "c.json"), os.path.join(d, "v.json")
            dump(c, cp)
            dump(w.fetched_for(c), vp)
            code, out = self.run_cli(cp, "--values", vp, "--no-tsa-check")
            self.assertEqual(code, 0, out)
            self.assertIn("Este sorteio confere.", out)
            self.assertIn("fila-creche-2027-03", out)
            self.assertIn("mesmo ID invalida", out)
            c["order"].reverse()
            dump(c, cp)
            self.assertEqual(self.run_cli(cp, "--values", vp, "--no-tsa-check")[0], 1)
            dump({"megasena": {"error": "x"}}, vp)
            c["order"].reverse()
            dump(c, cp)
            self.assertEqual(self.run_cli(cp, "--values", vp, "--no-tsa-check")[0], 2)
            code, out = self.run_cli(cp, "--values", vp, "--no-tsa-check", "--json")
            self.assertEqual(json.loads(out)["verdict"], "incompleto")

    def test_script_runs_standalone(self):
        r = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), "verifier", "verify_draw.py"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--confirm-lottery", r.stdout)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jeroen van de Graaf
"""Rede simulada para os testes do verify_draw.py (lê tests/fixtures/world.json)."""
import json
import os

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


def cert(name):
    return load(os.path.join("certificates", name + ".json"))


WORLD = load("world.json")


def fetched_for(cert, world=WORLD, unreachable=()):
    """Monta o `fetched` de verify_certificate como se a rede fosse `world`."""
    src = cert["spec"]["sources"]
    rand = cert.get("randomness") or {}
    out = {}
    if "eth" in src and "eth" in rand:
        if "eth" in unreachable:
            out["eth"] = {"error": "simulado: sem rede"}
        else:
            n = rand["eth"]["number"]
            b = world["eth"]["blocks"]
            out["eth"] = {"block": b.get(str(n)), "parent": b.get(str(n - 1)), "head": world["eth"]["head"]}
    if "drand" in src:
        r = src["drand"]["round"]
        out["drand"] = {"error": "simulado: sem rede"} if "drand" in unreachable else dict(world["drand"].get(str(r)) or {"error": "rodada não encontrada"})
    for g in ("megasena", "federal"):
        if g in src:
            key = f"{g}/{src[g]['contest']}"
            out[g] = {"error": "simulado: Caixa bloqueada"} if g in unreachable else world["lottery"].get(key)
    return out

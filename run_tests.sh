#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jeroen van de Graaf
# Roda todos os testes, sem rede: núcleo do HTML, buscador de bloco, conferência, relay (Node)
# e verificador de referência (Python).
set -e
cd "$(dirname "$0")"
echo "== Node: núcleo do LucentSorteios.html, relay =="
node --test tests/*.test.mjs
echo
echo "== Python: verifier/verify_draw.py =="
python3 -m unittest discover -s tests -p "test_*.py"

#!/bin/sh
# Roda todos os testes, sem rede: núcleo do HTML, buscador de bloco, conferência, relay (Node)
# e verificador de referência (Python).
set -e
cd "$(dirname "$0")"
echo "== Node: núcleo do SorteioLucido.html, relay =="
node --test tests/*.test.mjs
echo
echo "== Python: verify_draw.py =="
python3 -m unittest discover -s tests -p "test_*.py"

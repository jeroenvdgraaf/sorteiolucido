# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jeroen van de Graaf
.PHONY: test fixtures

# Todos os testes (offline).
test:
	./run_tests.sh

# Regera os certificados de teste (requer openssl).
fixtures:
	node tests/tools/gen_fixtures.mjs

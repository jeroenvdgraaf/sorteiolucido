.PHONY: test fixtures

# Todos os testes (offline).
test:
	./run_tests.sh

# Regera os certificados de teste (requer openssl).
fixtures:
	node tests/tools/gen_fixtures.mjs

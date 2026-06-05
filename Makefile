PROJECT:=threatray-mcp
VERSION=$(shell { date +%Y%m%d-%H%M%S; git log -n 1 --format="%h" 2>/dev/null || echo "nogit"; } | sed ':a;N;$$!ba;s/\n/./' )
VERSION_DEV="${VERSION}-dev"
REGISTRY ?= ghcr.io/threatray
injected_version:=$(if $(INJECTED_VERSION),$(INJECTED_VERSION),$(VERSION_DEV))

# Declare all targets as phony.
# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: %

# By default, `make` without arguments runs the first target. Declare it explicitly.
_default:

# ─── Unit tests ─────────────────────────────────────────────────────────────
# `make unit-tests` runs all supported Python versions; `make unit-tests-3-13`
# runs only one.
unit-tests: unit-tests-3-11 unit-tests-3-12 unit-tests-3-13

unit-tests-%:
	docker compose -f docker-compose.yml --profile $@ build
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans
	docker compose -f docker-compose.yml --profile $@ up --exit-code-from $(PROJECT)-$@
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans

# ─── Integration tests ──────────────────────────────────────────────────────
int-tests: int-tests-3-11 int-tests-3-12 int-tests-3-13

int-tests-%:
	docker compose -f docker-compose.yml --profile $@ build --pull
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans
	docker compose -f docker-compose.yml --profile $@ up --exit-code-from $(PROJECT)-$@
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans

test: unit-tests int-tests

# ─── Lint ───────────────────────────────────────────────────────────────────
lint:
	docker compose -f docker-compose.yml --profile lint build --pull
	docker compose -f docker-compose.yml --profile lint down --remove-orphans
	docker compose -f docker-compose.yml --profile lint run ruff
	docker compose -f docker-compose.yml --profile lint down --remove-orphans
	docker compose -f docker-compose.yml --profile lint run vulture
	docker compose -f docker-compose.yml --profile lint down --remove-orphans

lint-fix:
	docker compose -f docker-compose.yml --profile lint-fix build --pull
	docker compose -f docker-compose.yml --profile lint-fix down --remove-orphans
	docker compose -f docker-compose.yml --profile lint-fix run ruff-fix
	docker compose -f docker-compose.yml --profile lint-fix run ruff-format
	docker compose -f docker-compose.yml --profile lint-fix down --remove-orphans

vulture-whitelist:
	docker compose -f docker-compose.yml --profile lint build
	docker compose -f docker-compose.yml --profile lint run vulture-whitelist > vulture_whitelist.py
	docker compose -f docker-compose.yml --profile lint down --remove-orphans

# ─── Type check ─────────────────────────────────────────────────────────────
type-check: type-check-3-11 type-check-3-12 type-check-3-13

type-check-%:
	docker compose -f docker-compose.yml --profile $@ build
	docker compose -f docker-compose.yml --profile $@ run type-check-$*
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans

# ─── Build / lock / version ─────────────────────────────────────────────────
build:
	docker build -t $(REGISTRY)/$(PROJECT):$(injected_version) .

lock:
	docker build --target lock -t $(PROJECT) --pull .
	docker run --rm $(PROJECT) cat /app/uv.lock > uv.lock

version-dev:
	echo -n $(VERSION_DEV)

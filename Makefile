.DEFAULT_GOAL := help

.PHONY: help generate fmt lint test build production-check production-check-database production-check-systemd production-check-controlplane production-check-db-fault production-check-soak dev-server dev-web clean

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\n"} /^[a-zA-Z_-]+:.*?## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

generate: ## Generate protocol and API clients
	cd contracts && ./scripts/generate.sh

fmt: ## Format all subprojects
	cd agent && gofmt -w $$(find . -name '*.go' -type f)
	cd server && gofmt -w $$(find . -name '*.go' -type f)
	cd web && npm run format --if-present

lint: ## Run static checks
	cd agent && go vet ./...
	cd server && go vet ./...
	cd web && npm run lint

test: ## Run all unit tests
	cd agent && go test ./...
	cd server && go test ./...
	cd web && npm test -- --run

build: ## Build all deliverables
	mkdir -p bin
	cd agent && go build -o ../bin/frp-agent ./cmd/frp-agent
	cd agent && go build -o ../bin/frp-agent-helper ./cmd/frp-agent-helper
	cd server && go build -o ../bin/frp-admin-server ./cmd/frp-admin-server
	cd web && npm run build

production-check: ## Run deterministic local production checks (external gates remain separate)
	./scripts/production-check.sh

production-check-database: ## Run one real MySQL/PostgreSQL contract (requires integration DB env)
	@test -n "$$FRP_ADMIN_INTEGRATION_DB_DRIVER" -a -n "$$FRP_ADMIN_INTEGRATION_DB_DSN" || { echo 'set FRP_ADMIN_INTEGRATION_DB_DRIVER and FRP_ADMIN_INTEGRATION_DB_DSN' >&2; exit 2; }
	cd server && go test ./internal/store/sqlstore -run 'TestDatabase(Contract|MigrationReplay)' -count=1 -v

production-check-systemd: ## Run privileged Linux/systemd Agent E2E
	./deploy/e2e/systemd/run-container.sh

production-check-controlplane: ## Run real Server/Agent control-plane E2E
	./deploy/e2e/controlplane/run-container.sh

production-check-db-fault: ## Run PostgreSQL outage and recovery E2E
	./deploy/e2e/db-fault/run.sh

production-check-soak: ## Run the required 168-hour soak against an explicit target
	SOAK_DURATION=168h SOAK_REQUIRE_168H=true ./deploy/soak/run.sh

dev-server: ## Run the control-plane server
	cd server && go run ./cmd/frp-admin-server

dev-web: ## Run the web development server
	cd web && npm run dev

clean: ## Remove build outputs
	rm -rf bin web/dist coverage

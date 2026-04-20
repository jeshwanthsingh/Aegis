GO ?= go
BIN_DIR := .aegis/bin
AEGIS_BIN := $(BIN_DIR)/aegis
ORCH_BIN := $(BIN_DIR)/orchestrator
SETCAP_FLAGS := cap_net_admin,cap_net_raw,cap_net_bind_service+eip

.PHONY: build setcap build-with-caps

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -buildvcs=false -o $(AEGIS_BIN) ./cmd/aegis-cli
	$(GO) build -buildvcs=false -o $(ORCH_BIN) ./cmd/orchestrator

setcap:
	@test -f $(ORCH_BIN) || (echo "orchestrator binary missing at $(ORCH_BIN); run \`make build\` first" >&2; exit 1)
	@test -f $(AEGIS_BIN) || (echo "aegis binary missing at $(AEGIS_BIN); run \`make build\` first" >&2; exit 1)
	@echo "About to run: sudo setcap $(SETCAP_FLAGS) $(ORCH_BIN)"
	@sudo setcap $(SETCAP_FLAGS) $(ORCH_BIN)
	@echo "About to run: sudo setcap $(SETCAP_FLAGS) $(AEGIS_BIN)"
	@sudo setcap $(SETCAP_FLAGS) $(AEGIS_BIN)
	@echo "Capability confirmation: $(ORCH_BIN)"
	@getcap $(ORCH_BIN)
	@echo "Capability confirmation: $(AEGIS_BIN)"
	@getcap $(AEGIS_BIN)

build-with-caps: build setcap

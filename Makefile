# Makefile for ssl-update
# ----------------------
# Cross-compile commands based on Go 1.22+ (uses CGO_ENABLED=0 for static binaries).
#
# Literal commands (copy-paste in bash / Git Bash):
#
#   # Linux amd64
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
#     go build -trimpath -ldflags="-s -w -buildid=" \
#     -o pkg/ssl-update-0.1.2-linux-amd64/ssl-update \
#     ./cmd/ssl-update
#
#   # Linux arm64
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
#     go build -trimpath -ldflags="-s -w -buildid=" \
#     -o pkg/ssl-update-0.1.2-linux-arm64/ssl-update \
#     ./cmd/ssl-update
#
#   # Current platform (Windows host, dev machine)
#   go build -trimpath -ldflags="-s -w -buildid=" -o ssl-update.exe ./cmd/ssl-update
#
# After build, verify with:
#   file pkg/ssl-update-0.1.2-linux-amd64/ssl-update
#   # Expected: ELF 64-bit LSB executable, x86-64, statically linked, stripped

BINARY       := ssl-update
WINDOWS_BIN  := ssl-update.exe
VERSION      := 0.1.2
LDFLAGS      := -s -w -buildid=
GOFLAGS      := -trimpath
PKG_DIR      := pkg

# Supported release targets (format: OS-ARCH)
PLATFORMS    := linux-amd64 linux-arm64

# Default: build for current platform (developer convenience)
.DEFAULT_GOAL := build

# ----- Help -----
.PHONY: help
help:
	@echo "ssl-update v$(VERSION) - Makefile targets"
	@echo ""
	@echo "  make              - build for current OS/ARCH (fast dev loop)"
	@echo "  make build-all     - cross-compile for all release platforms"
	@echo "  make build-linux-amd64"
	@echo "  make build-linux-arm64"
	@echo "  make test         - run unit tests"
	@echo "  make vet          - go vet"
	@echo "  make fmt          - gofmt"
	@echo "  make clean        - remove pkg/"
	@echo "  make version      - print version"
	@echo "  make sha256       - regenerate checksums for all built artifacts"

# ----- Current platform -----
.PHONY: build
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(WINDOWS_BIN) ./cmd/ssl-update

# ----- Cross-compile -----
.PHONY: build-all
build-all: $(addprefix build-,$(PLATFORMS))

.PHONY: build-linux-amd64
build-linux-amd64:
	@mkdir -p $(PKG_DIR)/ssl-update-$(VERSION)-linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' \
		-o $(PKG_DIR)/ssl-update-$(VERSION)-linux-amd64/$(BINARY) \
		./cmd/ssl-update
	@cd $(PKG_DIR)/ssl-update-$(VERSION)-linux-amd64 && sha256sum $(BINARY) > sha256sum.txt
	@echo "Built pkg/ssl-update-$(VERSION)-linux-amd64/$(BINARY)"

.PHONY: build-linux-arm64
build-linux-arm64:
	@mkdir -p $(PKG_DIR)/ssl-update-$(VERSION)-linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' \
		-o $(PKG_DIR)/ssl-update-$(VERSION)-linux-arm64/$(BINARY) \
		./cmd/ssl-update
	@cd $(PKG_DIR)/ssl-update-$(VERSION)-linux-arm64 && sha256sum $(BINARY) > sha256sum.txt
	@echo "Built pkg/ssl-update-$(VERSION)-linux-arm64/$(BINARY)"

# ----- Test / vet / fmt -----
.PHONY: test
test:
	go test ./... -count=1

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -w .

# ----- Clean -----
.PHONY: clean
clean:
	rm -rf $(PKG_DIR)
	@echo "Cleaned pkg/"

# ----- Checksum regeneration -----
.PHONY: sha256
sha256:
	@for d in $(PKG_DIR)/ssl-update-$(VERSION)-*; do \
		if [ -f "$$d/$(BINARY)" ]; then \
			( cd $$d && sha256sum $(BINARY) > sha256sum.txt ); \
			echo "checksum updated: $$d/sha256sum.txt"; \
		fi; \
	done

# ----- Version -----
.PHONY: version
version:
	@echo "ssl-update $(VERSION)"

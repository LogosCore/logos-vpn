# logos-vpn's builds: one binary a system, as core serves them
# (VPN_CLIENT_DIR: logos-vpn-{os}-{arch}, .exe on Windows), and the
# installers core serves beside them (install/install.sh, install.ps1).

VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORMS      := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64
WINTUN_VERSION := 0.14.1
WINTUN_SHA256  := 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
WINTUN_ZIP     := build/wintun-$(WINTUN_VERSION).zip
LDFLAGS        := -s -w -X main.version=$(VERSION)
export GOTOOLCHAIN := local

.PHONY: dist test lint clean

dist: $(WINTUN_ZIP)
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%-*}; arch=$${p#*-}; out=dist/logos-vpn-$$p; tags=""; \
		if [ $$os = windows ]; then \
			out=$$out.exe; tags="-tags wintun"; \
			mkdir -p cmd/logos-vpn/wintun build/wintun-$$arch; \
			unzip -o -q -j $(WINTUN_ZIP) wintun/bin/$$arch/wintun.dll -d build/wintun-$$arch; \
			cp build/wintun-$$arch/wintun.dll cmd/logos-vpn/wintun/wintun.dll; \
		fi; \
		echo "$$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath $$tags -ldflags "$(LDFLAGS)" -o $$out ./cmd/logos-vpn || exit 1; \
	done
	@rm -rf cmd/logos-vpn/wintun
	cp install/install.sh install/install.ps1 dist/

# Wintun's release, checked against WireGuard's published hash.
$(WINTUN_ZIP):
	@mkdir -p build
	curl -fsSLo $@.part https://www.wintun.net/builds/wintun-$(WINTUN_VERSION).zip
	echo "$(WINTUN_SHA256)  $@.part" | sha256sum -c -
	mv $@.part $@

test:
	go test -race ./...

lint:
	@for os in linux darwin windows; do echo "GOOS=$$os"; GOOS=$$os golangci-lint run ./... || exit 1; done

clean:
	rm -rf dist build cmd/logos-vpn/wintun

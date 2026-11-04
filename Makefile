# Warden build entry points.
#
# The macOS CLI targets cross-build from Linux with cargo-zigbuild and a macOS
# SDK (the SDK is needed for CoreFoundation, pulled in by wasmtime/YARA-X).

SDKROOT ?= $(HOME)/sdk/MacOSX15.5.sdk
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

ifeq ($(shell uname -s),Linux)
GUI_TEST_ENV := WGPU_BACKEND=gl
endif

.PHONY: help build linux test lint gui gui-build gui-test gui-linux gui-mac gui-mac-x86_64 gui-mac-arm64 mac-x86_64 mac-arm64 clean

help: ## List these targets
	@grep -E '^[a-z0-9_%-]+:.*##' $(MAKEFILE_LIST) \
	    | sed -E 's/:.*##[[:space:]]*/\t/' \
	    | expand -t 18

build: ## Build the CLI for the current host
	cargo build --release

linux: ## Build the Linux CLI
	cargo build --release

test: ## Run all tests and the CLI self-test
	$(GUI_TEST_ENV) cargo test --workspace
	cargo run --quiet -- selftest

lint: ## Lint and format-check the workspace
	cargo fmt --check
	cargo clippy --workspace --all-targets -- -D warnings

gui: ## Run the desktop app
	cargo run --release -p warden-gui

gui-build: ## Build the desktop app for the current host
	cargo build --release -p warden-gui

gui-test: ## Run headless desktop UI snapshot tests
	$(GUI_TEST_ENV) cargo test -p warden-gui

gui-linux: ## Package the Linux desktop app (tarball)
	scripts/package-linux-gui.sh

gui-mac: ## Package the desktop app natively on macOS
	packaging/macos/package-gui.sh

gui-mac-x86_64: ## Cross-build and package the macOS Intel desktop app
	SDKROOT=$(SDKROOT) packaging/macos/cross-build-gui.sh --target x86_64-apple-darwin
	packaging/macos/package-gui.sh --arch x86_64 \
	    --binary target/x86_64-apple-darwin/release/warden-gui --skip-build

gui-mac-arm64: ## Cross-build and package the macOS Apple Silicon desktop app
	SDKROOT=$(SDKROOT) packaging/macos/cross-build-gui.sh --target aarch64-apple-darwin
	packaging/macos/package-gui.sh --arch aarch64 \
	    --binary target/aarch64-apple-darwin/release/warden-gui --skip-build

mac-x86_64: ## Cross-build macOS Intel CLI
	SDKROOT=$(SDKROOT) scripts/build-macos.sh x86_64-apple-darwin

mac-arm64: ## Cross-build Apple Silicon CLI
	SDKROOT=$(SDKROOT) scripts/build-macos.sh aarch64-apple-darwin

clean:
	cargo clean
	rm -rf dist

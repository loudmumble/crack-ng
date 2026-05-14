.PHONY: build build-linux build-darwin build-win build-all test clean

BINARY_NAME := crack-ng
BUILD_DIR   := build
VERSION     := $(shell cat VERSION 2>/dev/null || echo "0.1.0")

build:
	@mkdir -p $(BUILD_DIR)
	cargo build --release
	cp target/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)

build-linux:
	@mkdir -p $(BUILD_DIR)
	cargo build --release --target x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64
	cargo build --release --target aarch64-unknown-linux-musl
	cp target/aarch64-unknown-linux-musl/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64

build-darwin:
	@mkdir -p $(BUILD_DIR)
	cargo build --release --target x86_64-apple-darwin
	cp target/x86_64-apple-darwin/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64
	cargo build --release --target aarch64-apple-darwin
	cp target/aarch64-apple-darwin/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64

build-win:
	@mkdir -p $(BUILD_DIR)
	cargo build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/$(BINARY_NAME).exe $(BUILD_DIR)/$(BINARY_NAME)-win-amd64.exe

build-all: build-linux build-darwin build-win

test:
	cargo test

clean:
	cargo clean
	rm -rf $(BUILD_DIR)

BIN     := envsec
PKG     := ./...
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build release test vet fmt

build:
	go build -o $(BIN) .

# Release build: static, stripped, reproducible. Nothing is reimplemented —
# sops + age are still compiled in as libraries; ldflags only strip symbol
# and DWARF tables (61M -> 42M).
release:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN) .

test:
	go test $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -l .
BIN := envsec
PKG := ./...

.PHONY: build release test vet fmt

build:
	go build -o $(BIN) .

release:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN) .

test:
	go test $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -l .
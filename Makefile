BINARY   := guard
MODULE   := github.com/MauroProto/guard
VERSION  ?= dev
GOFLAGS  := -trimpath
LDFLAGS  := -s -w -X $(MODULE)/internal/engine.Version=$(VERSION)

.PHONY: build test install clean vet

## build: Compile the binary
build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/guard/

## test: Run all tests
test:
	go test ./... -v

## cover: Run tests with coverage
cover:
	go test ./... -cover

## vet: Run static analysis
vet:
	go vet ./...

## install: Install to GOPATH/bin
install:
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/guard/

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)

## all: Build + test + vet
all: vet test build

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'

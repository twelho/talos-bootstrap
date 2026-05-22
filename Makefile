GO ?= go
BINARY ?= bootstrap
CMD ?= ./cmd/bootstrap
LDFLAGS ?= -s -w
GOLANGCI_LINT ?= golangci-lint

.PHONY: build test lint
build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	$(GO) test ./...

lint:
	$(GOLANGCI_LINT) run ./...

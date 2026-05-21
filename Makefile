GO ?= go
BINARY ?= bootstrap
CMD ?= ./cmd/bootstrap
LDFLAGS ?= -s -w

.PHONY: build test
build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	$(GO) test ./...

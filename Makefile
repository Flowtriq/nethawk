VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build install clean test

build:
	go build $(LDFLAGS) -o bin/nethawk ./cmd/nethawk

install:
	go install $(LDFLAGS) ./cmd/nethawk

clean:
	rm -rf bin/

test:
	go test ./...

# Cross-compile for common targets
release:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/nethawk-linux-amd64 ./cmd/nethawk
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/nethawk-linux-arm64 ./cmd/nethawk
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/nethawk-darwin-amd64 ./cmd/nethawk
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/nethawk-darwin-arm64 ./cmd/nethawk

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint clean release-snapshot

build:
	go build $(LDFLAGS) -o id3injector .

test:
	go test -v -race -count=1 ./...

lint:
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || \
		(echo "golangci-lint not found, running go vet instead" && go vet ./...)

clean:
	rm -f id3injector
	rm -rf dist/

release-snapshot:
	goreleaser release --snapshot --clean

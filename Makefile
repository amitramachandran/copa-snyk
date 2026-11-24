CLI_BINARY := copa-snyk
OUT_DIR    := ./dist

.PHONY: build test install
build:
	go build -o $(OUT_DIR)/$(CLI_BINARY) .

test:
	go test ./...

# Copa finds the plugin on $PATH
install: build
	install $(OUT_DIR)/$(CLI_BINARY) $(shell go env GOPATH)/bin/$(CLI_BINARY)

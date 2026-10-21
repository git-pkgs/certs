.PHONY: build test lint bench fuzz

build:
	CGO_ENABLED=0 go build -o bin/certs ./cmd/certs

test:
	go test -race ./...

lint:
	golangci-lint run --enable gocritic,gocognit,gocyclo,maintidx,dupl,mnd,unparam,ireturn,goconst,errcheck ./...
	govulncheck ./...
	deadcode ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

FUZZTIME ?= 30s
fuzz:
	go test -fuzz=FuzzScan -fuzztime=$(FUZZTIME) .

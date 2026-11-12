.PHONY: build test check e2e e2e-repeat

build:
	mkdir -p bin
	go build -trimpath -o bin/pgsniffer ./cmd/pgsniffer

test:
	go test ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

e2e:
	PGSNIFFER_E2E_REQUIRED=1 go test -tags=e2e ./tests/e2e -run TestDockerEndToEnd -v -count=1

e2e-repeat:
	PGSNIFFER_E2E_REQUIRED=1 go test -tags=e2e ./tests/e2e -run TestDockerEndToEnd -v -count=3

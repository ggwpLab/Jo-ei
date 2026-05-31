.PHONY: build test lint clean

build:
	go build -o bin/sca-proxy ./cmd/sca-proxy

test:
	go test ./... -v -race

lint:
	go vet ./...

run:
	go run ./cmd/sca-proxy --config config.yaml

clean:
	rm -rf bin/

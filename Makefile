.PHONY: build test lint fmt clean

build:
	go build -o bin/jo-ei ./cmd/jo-ei

test:
	go test ./... -v -race

fmt:
	gofmt -w .

lint:
	go vet ./...

run:
	go run ./cmd/jo-ei --config config.yaml

clean:
	rm -rf bin/

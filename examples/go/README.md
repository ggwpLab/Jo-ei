# Go modules through Jōei

Point the Go toolchain at the Jōei proxy so module downloads pass the
supply-chain, CVE, and malware gates.

## Setup

    export GOPROXY=http://localhost:8080/go
    # No ",direct": a proxy miss is a 404 instead of an unscanned VCS fetch.

    go mod download        # pulls modules through Jōei
    go build ./...

## Checksum database

Jōei proxies module content only (`.info`, `.mod`, `.zip`, `list`), not the
Go checksum database (`sum.golang.org`). In a closed environment where the
toolchain can't reach the sumdb directly, disable it:

    export GOSUMDB=off

(Or configure `GONOSUMCHECK` / `GONOSUMDB` / `GOFLAGS` per your policy.)

## What is gated

Jōei intercepts module **zip** downloads and runs them through every enabled
gate. Resolution manifests (`.info`, `.mod`, `@v/list`, `@latest`) are proxied
transparently — they carry no executable code, and any dependency that ends up
compiled is fetched as its own zip and gated independently. A blocked module's
zip returns a structured 423/403 and `go build` fails.

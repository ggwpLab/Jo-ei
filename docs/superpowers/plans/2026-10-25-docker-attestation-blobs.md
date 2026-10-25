# Docker Attestation Blobs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `docker pull` through Jō-ei works with containerd-based clients (Docker Desktop's default image store), which also fetch an image's BuildKit attestation blobs.

**Architecture:** Attestation manifests are already served un-gated (passthrough); their blobs were never cached, so `serveBlob` answered 404. The handler now records, every time it serves an attestation manifest (fresh or from cache), the digests of that manifest's config and non-filesystem layers in a bounded in-memory set. `serveBlob` serves a blob missing from the cache only if it is in that set: fetched from upstream, size-capped, verified against its digest, not cached. Filesystem (tar) layers never take this path — they are only ever served from the gated cache.

**Tech Stack:** Go (toolchain go1.26.10).

**Spec:** `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` — P0 #0c. Owner chose it as the next PR (2026-10-25).

## Global Constraints

- Recorded digests: an attestation-passthrough manifest's `config.digest` and every `layers[].digest` whose media type is **not** a filesystem layer (`!isFilesystemLayer`). Key `repo@digest`; FIFO bound **4096** (same as `tagIndex`).
- Attestation blob fetch: `Adapter.FetchBlob`; at most **16 MiB** (`maxAttestationBlobBytes`), buffered; sha256 of the bytes must equal the digest (only `sha256:` digests accepted); mismatch, oversize or upstream failure → Docker error envelope `404 BLOB_UNKNOWN` (`502 UNAVAILABLE` for upstream failure); success → `200`, `Content-Length`, `Docker-Content-Digest`, `Content-Type: application/octet-stream`. Not cached, not recorded as telemetry (blob serves never are).
- A digest in the gated blob cache is always served from the cache first (existing behaviour, including `!clean` → 404).
- Tests in a container only; `golangci-lint run ./...` → `0 issues.`
- Branch `fix/docker-attestation-blobs`, stacked on `fix/shutdown-health-compose` (PR #108).

## Review Focus

1. **Filesystem layer listed in a mixed passthrough manifest** — must still 404, never be proxied unscanned; pinned by `TestHandlerAttestationNeverServesFilesystemLayer`.
2. **Restart / cached verdict** — attestation manifest served from cache must still enable its blobs; pinned by `TestHandlerAttestationBlobsAfterCachedManifest`.
3. **Upstream returns different bytes** — digest mismatch must not be served; pinned by `TestHandlerAttestationBlobDigestMismatch`.
4. **Huge "attestation" blob** — capped; pinned by `TestHandlerAttestationBlobOversized`.
5. **Repo scoping** — a digest recorded for repo A is not served under repo B; pinned by `TestHandlerAttestationBlobRepoScoped`.

---

### Task 1: Record and serve attestation blobs

**Files:** create `internal/proxy/dockerproxy/attestation.go` (+ `attestation_test.go`); modify `handler.go` (`Config.Attest`, `serveManifest`, `serveBlob`, `New`).

**Interfaces:**
- `type attestationBlobs` with `newAttestationBlobs(max int)`, `remember(repo string, manifestBody []byte)`, `has(repo, digest string) bool`.
- `Config.Attest *attestationBlobs`; `New` wires one shared instance.

- [ ] **Step 1: Failing tests** (handler level, httptest upstream serving an attestation manifest with config `sha256:<real>` and an in-toto layer whose digests are the real sha256 of their bodies):
  - `TestHandlerServesAttestationBlobs`: GET manifest (passthrough), then GET config blob and in-toto blob → 200, bodies match, `Docker-Content-Digest` set, `Content-Length` set.
  - `TestHandlerAttestationNeverServesFilesystemLayer`: mixed manifest (one tar+gzip layer, one in-toto layer) → tar layer digest → 404; in-toto → 200.
  - `TestHandlerAttestationBlobsAfterCachedManifest`: two handlers sharing one cache; handler 1 serves the manifest; handler 2 (fresh set) serves it from cache, then its blob → 200.
  - `TestHandlerAttestationBlobDigestMismatch`: upstream body differs from digest → 404, body not leaked.
  - `TestHandlerAttestationBlobOversized`: 17 MiB body → 404.
  - `TestHandlerAttestationBlobRepoScoped`: recorded under `library/test`, requested under `library/other` → 404.
  - `TestAttestationBlobs_Bounded` (unit): max 2, remember three digests → oldest gone.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS + lint.
- [ ] **Step 5:** Commit `fix(docker): serve attestation blobs to containerd clients`.

### Task 2: e2e with Docker Desktop (containerd store), docs, PR

- [ ] **Step 1:** Full compose stack (scratch config with image CVE gate off so a public image passes): `docker pull 127.0.0.1:8080/library/<image not in the local store>` → completes; retry if the first attempt hits containerd's 30 s header timeout (audit P2 #19). Proxy log: one PASS for the platform manifest, no 404 blob errors.
- [ ] **Step 2:** CHANGELOG `Fixed`; audit P0 #0c marked fixed. Full suite + lint.
- [ ] **Step 3:** Commit `docs: changelog for attestation blobs`; final review; PR `--base fix/shutdown-health-compose`.

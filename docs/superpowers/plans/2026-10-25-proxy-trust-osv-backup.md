# Reverse-proxy Trust, OSV Transport & Backup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Behind the documented reverse proxy, login throttling keys on real clients; the CVE gate honours the operator's CA trust and upstream limits; operators can back up and restore the state database safely.

**Architecture:** `server.trusted_proxies` / `server.client_ip_header` become real (uncommented) keys so the environment can set them, with a reverse-proxy section in the docs (the untrusted-forwarding warning already exists). The OSV scanner takes an `*http.Client` option and is built on the shared upstream transport. A `jo-ei backup --output <file>` command takes a consistent online copy with SQLite's `VACUUM INTO`; restore is documented.

**Tech Stack:** Go (toolchain go1.26.10), cobra, modernc sqlite.

**Spec:** `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` — P1 #4, #9, #10.

## Global Constraints

- `config.yaml`: `trusted_proxies: []` and `client_ip_header: "X-Forwarded-For"` uncommented under `server:` (behaviour unchanged: empty list = peer address).
- OSV: `scanner.NewOSVScanner(baseURL string, ttl time.Duration, opts ...OSVOption)`; `scanner.WithOSVHTTPClient(c *http.Client) OSVOption`; default client unchanged (`Timeout: 15s`, default transport). Wired: `&http.Client{Timeout: 15 * time.Second, Transport: <shared upstream transport>}`.
- Backup: `jo-ei backup --output <path>`; refuses an existing output file; refuses a missing database (same check/message style as `reset-admin-password`); runs `VACUUM INTO ?` on the main DB (`database.path`) and works while the server is running; prints the output path. The cache index (`<cache>/index.db`) is not backed up — documented as disposable together with the cache volume.
- Tests in a container only; lint `0 issues.`
- Branch `fix/proxy-trust-osv-backup`, stacked on `fix/docker-attestation-blobs` (PR #109).

## Review Focus

1. **Backup while the server writes** — the copy must be consistent; pinned by `TestBackup_WhileOpenElsewhere` (another open handle writing).
2. **Overwrite** — never clobbers an existing file; pinned by `TestBackup_RefusesExistingOutput`.
3. **OSV over the shared transport** — requests go through the given client; pinned by `TestOSV_UsesGivenClient`.
4. **Env override of trusted proxies** — key present in `config.yaml`; pinned by `TestShippedConfig_HasTrustedProxiesKey`.
5. **Restore procedure** — documented, including removing `-wal`/`-shm`.

---

### Task 1: Trusted-proxy keys and reverse-proxy docs

**Files:** `config.yaml`, `cmd/jo-ei/main_test.go` (or a new test), `README.md` ("Running in Production": reverse proxy, `trusted_proxies` for the compose bridge gateway), `.env.example` (mention `JOEI_SERVER_TRUSTED_PROXIES`).

- [ ] **Step 1: Failing test** `TestShippedConfig_HasTrustedProxiesKey`: load the repo's `config.yaml` with `JOEI_SERVER_TRUSTED_PROXIES=10.0.0.1` set (`t.Setenv`) → `cfg.Server.TrustedProxies == []string{"10.0.0.1"}`.
- [ ] **Step 2–4** RED → uncomment keys → GREEN; docs. **Step 5:** commit `fix(config): make trusted proxies settable from the environment`.

### Task 2: OSV on the shared upstream transport

**Files:** `internal/scanner/osv.go` (+ test), `cmd/jo-ei/scanners.go`, `cmd/jo-ei/main.go`.

- [ ] **Step 1: Failing test** `TestOSV_UsesGivenClient`: a client whose transport records requests; scan one package against an httptest OSV → the recorder saw the request.
- [ ] **Step 2–4.** `buildScanners` takes the shared transport (`up.adapter.Transport`). **Step 5:** commit `fix(cve): send OSV lookups through the shared upstream transport`.

### Task 3: `jo-ei backup`

**Files:** create `cmd/jo-ei/backup.go`, `cmd/jo-ei/backup_test.go`; `README.md` (backup/restore), `CHANGELOG.md`, audit doc.

- [ ] **Step 1: Failing tests:**
  - `TestBackup_CopiesData`: DB with a user created via `users.Store`; `backup` → output opens with `storage.Open`, the user is there.
  - `TestBackup_RefusesExistingOutput`: output exists → error, file untouched.
  - `TestBackup_MissingDatabase`: error mentions the path.
  - `TestBackup_WhileOpenElsewhere`: a second `storage.DB` handle holds the DB open and inserts a setting before the backup → backup contains it.
- [ ] **Step 2–4.** **Step 5:** docs; full suite + lint; commit `feat(cli): online database backup`; final review; PR `--base fix/docker-attestation-blobs`.

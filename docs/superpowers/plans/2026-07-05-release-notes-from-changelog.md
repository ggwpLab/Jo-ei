# Release Notes from CHANGELOG.md Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GitHub release notes come verbatim from the tagged version's section in `CHANGELOG.md`; goreleaser's auto-changelog is disabled; the unreadable v0.1.0 notes are replaced.

**Architecture:** A POSIX shell script extracts the `## [X.Y.Z]` section body and appends the Docker-pull footer. The release workflow runs it before goreleaser (acting as a guard: missing section = failed release before any build) and passes the output via `--release-notes`. A companion test script runs in CI.

**Tech Stack:** POSIX sh + awk, GitHub Actions, goreleaser v2, `gh` CLI.

**Spec:** `docs/superpowers/specs/2026-07-05-release-notes-from-changelog-design.md`

## Global Constraints

- Scripts must be POSIX sh + awk only — no bash-isms, no GNU-only flags (CI is ubuntu, dev machine is Windows/Git Bash).
- Docker image reference is exactly `ghcr.io/ggwplab/jo-ei` (lowercase org).
- The extraction script must never match the `[Unreleased]` section or the link-reference block at the bottom of `CHANGELOG.md`.
- Work happens on branch `build/release-notes-from-changelog`; commits follow Conventional Commits as in `git log`.
- On Windows, run scripts through Git Bash (the Bash tool), and set the executable bit with `git update-index --chmod=+x <file>` after `git add`.

---

### Task 1: Extraction script + its test script

**Files:**
- Create: `scripts/release-notes.sh`
- Create: `scripts/release-notes_test.sh`
- Modify: `.github/workflows/ci.yml` (add one step to the `build-test` job)

**Interfaces:**
- Produces: `scripts/release-notes.sh VERSION [CHANGELOG_PATH]` — prints the section body + Docker footer to stdout; exit 0 on success, exit 1 with a message on stderr when the section is missing or empty. Task 2's workflow step and Task 4's retro-fix call it exactly like this.

- [ ] **Step 1: Write the failing test script**

Create `scripts/release-notes_test.sh`:

```sh
#!/usr/bin/env sh
# Tests for scripts/release-notes.sh. Run from anywhere; exits non-zero on failure.
set -eu
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $1" >&2; exit 1; }

# Case 1: existing version in the real CHANGELOG.md
out=$(sh scripts/release-notes.sh 0.1.0) || fail "0.1.0 extraction exited non-zero"
echo "$out" | grep -q 'First public release.' || fail "0.1.0 section content missing"
echo "$out" | grep -q 'docker pull ghcr.io/ggwplab/jo-ei:0.1.0' || fail "docker footer missing"
echo "$out" | grep -q '^## \[0.1.0\]' && fail "output contains the section heading itself"
echo "$out" | grep -q 'keepachangelog.com' && fail "output leaked the file preamble"
echo "$out" | grep -q '^\[0\.1\.0\]: ' && fail "output leaked link references"

# Case 2: missing version fails
if sh scripts/release-notes.sh 9.9.9 >/dev/null 2>&1; then
  fail "9.9.9 (missing section) should exit non-zero"
fi

# Case 3: present but empty section fails
tmp=$(mktemp)
cat >"$tmp" <<'EOF'
# Changelog

## [Unreleased]

## [0.2.0] - 2026-01-01

## [0.1.0] - 2025-12-01

- something

[0.2.0]: https://example.com/0.2.0
[0.1.0]: https://example.com/0.1.0
EOF
if sh scripts/release-notes.sh 0.2.0 "$tmp" >/dev/null 2>&1; then
  rm -f "$tmp"
  fail "empty 0.2.0 section should exit non-zero"
fi
rm -f "$tmp"

echo "release-notes tests: OK"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash scripts/release-notes_test.sh`
Expected: FAIL — `scripts/release-notes.sh` does not exist yet, so case 1 aborts with "0.1.0 extraction exited non-zero".

- [ ] **Step 3: Write the extraction script**

Create `scripts/release-notes.sh`:

```sh
#!/usr/bin/env sh
# Print the release-notes body for a version from CHANGELOG.md:
# the "## [VERSION]" section (blank-line-trimmed) plus a Docker-pull footer.
# Used by .github/workflows/release.yml via goreleaser --release-notes.
#
# Usage: release-notes.sh VERSION [CHANGELOG_PATH]
#   VERSION without the leading "v", e.g. 0.2.0
set -eu

version="${1:?usage: release-notes.sh VERSION [CHANGELOG_PATH]}"
changelog="${2:-CHANGELOG.md}"

# index() (not a regex) so dots in the version are literal.
# A section ends at the next "## " heading or the link-reference block.
status=0
body=$(awk -v ver="$version" '
  BEGIN { header = "## [" ver "]" }
  !insec && index($0, header) == 1 { insec = 1; found = 1; next }
  insec && (/^## / || /^\[[^]]*\]: /) { insec = 0 }
  insec { lines[n++] = $0 }
  END {
    if (!found) exit 2
    while (n > 0 && lines[n-1] ~ /^[[:space:]]*$/) n--
    start = 0
    while (start < n && lines[start] ~ /^[[:space:]]*$/) start++
    if (start >= n) exit 3
    for (i = start; i < n; i++) print lines[i]
  }
' "$changelog") || status=$?
if [ "$status" -ne 0 ]; then
  case $status in
    2) echo "release-notes.sh: no section '## [$version]' in $changelog" >&2 ;;
    3) echo "release-notes.sh: section '## [$version]' in $changelog is empty" >&2 ;;
    *) echo "release-notes.sh: failed to parse $changelog" >&2 ;;
  esac
  exit 1
fi

printf '%s\n\n**Docker image:** `docker pull ghcr.io/ggwplab/jo-ei:%s`\n' "$body" "$version"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `bash scripts/release-notes_test.sh`
Expected: `release-notes tests: OK`

Also eyeball the real output once: `bash scripts/release-notes.sh 0.1.0` — should print the curated 0.1.0 section followed by the Docker line, no heading, no link refs.

- [ ] **Step 5: Wire the test script into CI**

In `.github/workflows/ci.yml`, add a step to the `build-test` job directly after the `gofmt` step:

```yaml
      - name: Release-notes script tests
        run: sh scripts/release-notes_test.sh
```

- [ ] **Step 6: Commit (with executable bits)**

```bash
git add scripts/release-notes.sh scripts/release-notes_test.sh .github/workflows/ci.yml
git update-index --chmod=+x scripts/release-notes.sh scripts/release-notes_test.sh
git commit -m "build(release): add CHANGELOG.md release-notes extraction script"
```

---

### Task 2: Wire the script into the release pipeline

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `.goreleaser.yaml` (changelog block, release footer)

**Interfaces:**
- Consumes: `scripts/release-notes.sh VERSION` from Task 1 (exit 1 when the section is missing — that failure is the release guard).

- [ ] **Step 1: Add the extraction step and pass the notes to goreleaser**

In `.github/workflows/release.yml`, insert between the `actions/setup-go` step and the `docker/setup-qemu-action` step:

```yaml
      - name: Extract release notes from CHANGELOG.md
        run: ./scripts/release-notes.sh "${GITHUB_REF_NAME#v}" > /tmp/release-notes.md
```

And change the goreleaser step's args line to:

```yaml
          args: release --clean --release-notes=/tmp/release-notes.md
```

- [ ] **Step 2: Disable goreleaser's changelog and drop the footer**

In `.goreleaser.yaml`, replace the entire `changelog:` block (sort/groups/filters, lines 40–56) with:

```yaml
# Release notes come from CHANGELOG.md, extracted by scripts/release-notes.sh
# and passed with --release-notes in the release workflow.
changelog:
  disable: true
```

Delete the `release:` block at the bottom entirely (the Docker-pull footer now comes from the script; goreleaser ignores `release.footer` when `--release-notes` is set):

```yaml
release:
  footer: |
    **Docker image:** `docker pull ghcr.io/ggwplab/jo-ei:{{ .Version }}`
```

- [ ] **Step 3: Validate the goreleaser config**

Run: `go run github.com/goreleaser/goreleaser/v2@latest check`
Expected: `1 configuration file(s) validated` / no errors.

- [ ] **Step 4: Snapshot dry run**

Run: `go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=docker`
Expected: completes successfully, builds all six platform binaries into `dist/`, no changelog-related errors. (`dist/` is gitignored; if not, do not commit it.)

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml .goreleaser.yaml
git commit -m "build(release): source GitHub release notes from CHANGELOG.md"
```

---

### Task 3: Document the release process

**Files:**
- Modify: `CONTRIBUTING.md` (new section between `## Before You Open a PR` and `## Reporting Issues`)

**Interfaces:**
- Consumes: `scripts/release-notes.sh X.Y.Z` dry-run usage from Task 1.

- [ ] **Step 1: Add the "Release process" section**

Insert into `CONTRIBUTING.md` after the `## Before You Open a PR` section (before `## Reporting Issues`):

```markdown
## Release Process (maintainers)

GitHub release notes are taken verbatim from `CHANGELOG.md`. The release
workflow fails — before anything is built or published — if the tagged
version has no non-empty section there.

1. Move the content of `## [Unreleased]` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section. Keep `[Unreleased]` in place, empty.
2. Update the link references at the bottom of `CHANGELOG.md`: point
   `[Unreleased]` at `compare/vX.Y.Z...HEAD` and add the `[X.Y.Z]` link.
3. Optional dry run: `sh scripts/release-notes.sh X.Y.Z` prints exactly
   what the GitHub release body will be.
4. Land the changelog update on `main` through the normal PR flow.
5. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The Release
   workflow builds the binaries, publishes the Docker images, and creates
   the GitHub release with the extracted notes.
```

- [ ] **Step 2: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs(contributing): document the CHANGELOG-driven release process"
```

---

### Task 4: Retroactively fix the v0.1.0 release notes

Run this after Tasks 1–3 are committed (the script must exist in the working tree; the GitHub release edit is independent of the PR merge).

**Files:** none (external `gh` operation; temp file only).

**Interfaces:**
- Consumes: `scripts/release-notes.sh 0.1.0` from Task 1.

- [ ] **Step 1: Generate the notes and preview them**

```bash
bash scripts/release-notes.sh 0.1.0 > /tmp/v0.1.0-notes.md
cat /tmp/v0.1.0-notes.md
```

Expected: the curated 0.1.0 section from `CHANGELOG.md` plus the line
`**Docker image:** \`docker pull ghcr.io/ggwplab/jo-ei:0.1.0\``.

- [ ] **Step 2: Replace the release body**

This edits a published GitHub release — confirm the preview from Step 1 looks right first.

```bash
gh release edit v0.1.0 --notes-file /tmp/v0.1.0-notes.md
```

- [ ] **Step 3: Verify**

```bash
gh release view v0.1.0 --json body -q '.body' | head -20
```

Expected: starts with `First public release.` (or the `### Added` heading), no 40-character SHAs anywhere.

---

## Verification (whole plan)

1. `bash scripts/release-notes_test.sh` → `release-notes tests: OK`
2. `go run github.com/goreleaser/goreleaser/v2@latest check` → config valid
3. Snapshot dry run passes with changelog disabled
4. `gh release view v0.1.0` shows curated notes
5. CI green on the PR (including the new script-test step)

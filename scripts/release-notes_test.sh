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

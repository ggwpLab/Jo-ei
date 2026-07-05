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

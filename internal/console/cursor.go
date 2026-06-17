package console

import (
	"strconv"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// validVerdict reports whether v is one of the four accepted verdict
// constants. The empty string (meaning "any verdict" per Repo.Page) is not a
// valid value here; callers must guard with v != "" before calling.
func validVerdict(v string) bool {
	switch v {
	case proxy.VerdictPass, proxy.VerdictCache, proxy.VerdictBlock, proxy.VerdictError:
		return true
	default:
		return false
	}
}

// encodeCursor renders a keyset cursor as "<unixNanos>:<id>". The zero cursor
// (no more pages / start-from-newest) renders as the empty string.
func encodeCursor(c telemetry.Cursor) string {
	if c.Zero() {
		return ""
	}
	return strconv.FormatInt(c.TS.UnixNano(), 10) + ":" + strconv.FormatInt(c.ID, 10)
}

// parseCursor inverts encodeCursor on untrusted client input. It rejects
// malformed input, any id < 1 (ids are SQLite rowids starting at 1; id 0 is the
// zero-cursor sentinel), and any tsNano < 1 (real event timestamps are positive
// UnixNano; non-positive values are tampered/garbage and would otherwise make
// the keyset predicate match every or no row). The timestamp is normalized to
// UTC so the returned Cursor.TS compares cleanly regardless of server zone.
func parseCursor(s string) (telemetry.Cursor, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return telemetry.Cursor{}, false
	}
	tsNano, err1 := strconv.ParseInt(parts[0], 10, 64)
	id, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || id < 1 || tsNano < 1 {
		return telemetry.Cursor{}, false
	}
	return telemetry.Cursor{TS: time.Unix(0, tsNano).UTC(), ID: id}, true
}

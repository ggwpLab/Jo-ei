package console

import (
	"strconv"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// validVerdicts is the set accepted by GET /api/requests?verdict=.
var validVerdicts = map[string]bool{
	proxy.VerdictPass:  true,
	proxy.VerdictCache: true,
	proxy.VerdictBlock: true,
	proxy.VerdictError: true,
}

func validVerdict(v string) bool { return validVerdicts[v] }

// encodeCursor renders a keyset cursor as "<unixNanos>:<id>". The zero cursor
// (no more pages / start-from-newest) renders as the empty string.
func encodeCursor(c telemetry.Cursor) string {
	if c.Zero() {
		return ""
	}
	return strconv.FormatInt(c.TS.UnixNano(), 10) + ":" + strconv.FormatInt(c.ID, 10)
}

// parseCursor inverts encodeCursor. It rejects malformed input and any id < 1
// (ids are SQLite rowids starting at 1; id 0 is the zero-cursor sentinel).
func parseCursor(s string) (telemetry.Cursor, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return telemetry.Cursor{}, false
	}
	tsNano, err1 := strconv.ParseInt(parts[0], 10, 64)
	id, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || id < 1 {
		return telemetry.Cursor{}, false
	}
	return telemetry.Cursor{TS: time.Unix(0, tsNano), ID: id}, true
}

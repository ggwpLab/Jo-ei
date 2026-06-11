package console

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Wire shapes mirror the field names the SPA already renders (web/console),
// so the JSX screens change minimally.

type cveJSON struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss"`
	Summary  string  `json:"summary"`
}

type malwareJSON struct {
	Engine    string `json:"engine"`
	Signature string `json:"signature"`
}

type supplyJSON struct {
	PublishedAt time.Time  `json:"published_at"`
	BlockUntil  *time.Time `json:"block_until,omitempty"`
}

type eventJSON struct {
	RequestID string       `json:"request_id"`
	TS        time.Time    `json:"ts"`
	Eco       string       `json:"eco"`
	Pkg       string       `json:"pkg"`
	Ver       string       `json:"ver"`
	Verdict   string       `json:"verdict"`
	Gate      string       `json:"gate"`
	Lat       int64        `json:"lat"`
	HTTP      int          `json:"http,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	BlockedBy []string     `json:"blocked_by,omitempty"`
	CVEs      []cveJSON    `json:"cves,omitempty"`
	Malware   *malwareJSON `json:"malware,omitempty"`
	Supply    *supplyJSON  `json:"supply,omitempty"`
}

func toEventJSON(ev proxy.Event) eventJSON {
	out := eventJSON{
		RequestID: ev.RequestID, TS: ev.Time,
		Eco: ev.Ecosystem, Pkg: ev.Package, Ver: ev.Version,
		Verdict: ev.Verdict, Gate: ev.Gate, Lat: ev.LatencyMS,
		HTTP: ev.HTTPStatus, Reason: ev.Reason, BlockedBy: ev.BlockedBy,
	}
	for _, f := range ev.CVEs {
		out.CVEs = append(out.CVEs, cveJSON{ID: f.ID, Severity: f.Severity.String(), CVSS: f.Score, Summary: f.Summary})
	}
	if ev.MalwareEngine != "" || ev.MalwareSignature != "" {
		out.Malware = &malwareJSON{Engine: ev.MalwareEngine, Signature: ev.MalwareSignature}
	}
	if !ev.PublishedAt.IsZero() {
		sj := &supplyJSON{PublishedAt: ev.PublishedAt}
		if !ev.BlockUntil.IsZero() {
			bu := ev.BlockUntil
			sj.BlockUntil = &bu
		}
		out.Supply = sj
	}
	return out
}

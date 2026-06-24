package proxy

import "time"

// Verdict values recorded for an intercepted request.
const (
	VerdictPass  = "PASS"
	VerdictCache = "CACHE"
	VerdictBlock = "BLOCK"
	VerdictError = "ERROR"
)

// Gate identifiers. For BLOCK events: the gate that blocked. For ERROR
// events: the stage that failed. For PASS events: the deepest gate the
// artifact cleared.
const (
	GateCache     = "cache"
	GateSupply    = "supply"
	GateCVE       = "cve"
	GateMalware   = "malware"
	GateImageScan = "image_scan"
)

// Event is one telemetry record per intercepted request outcome. Field
// semantics mirror the console's request objects (web/console).
type Event struct {
	RequestID  string
	Time       time.Time // outcome timestamp (request arrival = Time - LatencyMS)
	Ecosystem  string
	Package    string
	Version    string
	Verdict    string // PASS | CACHE | BLOCK | ERROR
	Gate       string // cache | supply | cve | malware
	LatencyMS  int64
	HTTPStatus int
	Reason     string
	BlockedBy  []string // "supply_chain" | "cve" | "malware" | "denylist"

	// CVE block details.
	CVEs []CVEFinding

	// Malware block details.
	MalwareEngine    string
	MalwareSignature string

	// Supply-chain details (also set on PASS when metadata was fetched).
	PublishedAt time.Time
	BlockUntil  time.Time // non-zero only for supply-chain blocks
}

// ReasonDenylisted is the block reason produced by the policy engine for
// denylisted packages; telemetry counts it separately from CVE blocks.
const ReasonDenylisted = "denylisted"

// Recorder receives telemetry events. Implementations must be safe for
// concurrent use and must never block or fail the proxy data path: Record
// returns nothing. Defined here (like ArtifactCache) to avoid the import
// cycle proxy → telemetry → proxy; telemetry.Hub satisfies it structurally.
type Recorder interface {
	Record(Event)
}

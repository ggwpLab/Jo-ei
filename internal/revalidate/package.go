package revalidate

import (
	"context"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// packageRevalidator re-checks a cached package artifact (pypi/npm/maven/rubygems)
// against CVE+policy and malware. The supply-chain time rule is not re-run (a
// cached entry has matured); denylist changes are caught by the policy step.
type packageRevalidator struct {
	cve    gate.CVEScanner
	policy gate.PolicyDecider
	av     gate.AVScanner
}

// NewPackageRevalidator builds a Revalidator for package ecosystems. Any of the
// scanners may be nil (that check is skipped).
func NewPackageRevalidator(cve gate.CVEScanner, policy gate.PolicyDecider, av gate.AVScanner) Revalidator {
	return &packageRevalidator{cve: cve, policy: policy, av: av}
}

func (p *packageRevalidator) Revalidate(ctx context.Context, e cache.RevalEntry) (Outcome, *EvictReason) {
	ref := e.Ref

	// 1. CVE + policy (cheap metadata check first).
	if p.cve != nil && p.policy != nil {
		res, err := p.cve.Scan(ctx, &ref)
		if err != nil {
			return Retry, nil
		}
		if decision := p.policy.Evaluate(&ref, res); !decision.Allowed {
			by := "cve"
			if decision.Reason == gate.ReasonDenylisted {
				by = "denylist"
			}
			return Evict, &EvictReason{
				Gate: gate.GateCVE, Reason: decision.Reason,
				BlockedBy: by, Findings: decision.Findings,
			}
		}
	}

	// 2. Malware re-scan of the cached bytes.
	if p.av != nil {
		res, err := p.av.Scan(ctx, e.FilePath)
		if err != nil {
			return Retry, nil
		}
		if !res.Clean {
			return Evict, &EvictReason{
				Gate: gate.GateMalware, Reason: "malware_found",
				BlockedBy: "malware", Engine: res.Engine, Signature: res.Signature,
			}
		}
	}

	return Keep, nil
}

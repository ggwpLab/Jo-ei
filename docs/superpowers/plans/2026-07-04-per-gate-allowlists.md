# Per-Gate Allowlists Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the single runtime allowlist (which bypassed both the supply-chain age gate and the CVE gate) into two per-gate lists — `allowlist_supply` (bypasses only the min-age hold) and `allowlist_cve` (bypasses only the CVE block) — and remove the no-op "Wait" button from the console quarantine screen.

**Architecture:** `policy.RuntimeParams` gains `AllowlistSupply`/`AllowlistCVE` replacing `Allowlist`. `Runtime.install` feeds the supply list (merged with the immutable `supply_chain.allowlist_path` file entries) to `supplychain.Filter` and the CVE list to `policy.Engine` (whose `profile.Allowlist` mechanics are untouched). A new stored-policy codec in the policy package migrates legacy persisted rows (single `"allowlist"` key) into **both** lists (user decision: no silent behavior change). Console API and UI expose the two lists; the quarantine screen's trust action writes only to the supply list; the threat drawer targets the list matching the blocking gate. The malware gate is never bypassable (unchanged).

**Tech Stack:** Go 1.x, testify, embedded SQLite settings store, React-ish console (global-scope JSX bundled via `go generate ./...` / esbuild).

## Global Constraints

- Branch off `main`: `feat/per-gate-allowlists`; PR into `main` (never commit to main directly).
- Run `golangci-lint run ./...` before pushing (CI gate includes ineffassign/staticcheck/unused).
- Wire JSON field names: `allowlist_supply`, `allowlist_cve` (snake_case like existing fields).
- Legacy persisted `"allowlist"` entries migrate into BOTH new lists, deduplicated.
- YAML `policy.profiles.<name>.allowlist` seeds BOTH lists (README documents it as bypassing CVE and age checks — behavior preserved).
- `supply_chain.allowlist_path` file entries remain supply-only and immutable at runtime (already the case).
- Malware (AV) gate is never allowlist-bypassable.
- Console entries stay version-pinned (`eco/pkg@ver`).
- Regenerate `web/console/app.bundle.js` with `go generate ./...` after any `web/console/src` change; never hand-edit the bundle.

---

### Task 1: policy runtime — per-gate params

**Files:**
- Modify: `internal/policy/runtime.go`
- Test: `internal/policy/runtime_test.go`, `internal/policy/runtime_persist_test.go`

**Interfaces:**
- Produces: `policy.RuntimeParams{Mode string; MinAgeHours int; CVEBlockOn string; AllowlistSupply []string "json:\"allowlist_supply\""; AllowlistCVE []string "json:\"allowlist_cve\""; Denylist []string "json:\"denylist\""}` — the `Allowlist` field is REMOVED. All later tasks use these exact field/JSON names.
- Consumes: existing `supplychain.NewFilter`, `supplychain.NewAllowlist`, `policy.NewEngine` (unchanged).

- [ ] **Step 0: Create the feature branch**

```bash
git checkout main
git pull
git checkout -b feat/per-gate-allowlists
```

- [ ] **Step 1: Write the failing test**

Add to `internal/policy/runtime_test.go`:

```go
func TestRuntimePerGateAllowlists(t *testing.T) {
	r := newRuntime(t, nil)

	// Supply-only entry: bypasses the age hold, NOT the CVE block.
	p := r.Current()
	p.CVEBlockOn = "HIGH"
	p.AllowlistSupply = []string{"pypi/requests@2.31.0"}
	require.NoError(t, r.Apply(p))
	res := r.Check(context.Background(), rtRef(), freshMeta())
	assert.True(t, res.Allowed, "supply allowlist bypasses min-age hold")
	assert.Equal(t, "allowlisted", res.Reason)
	d := r.Evaluate(rtRef(), highFinding())
	assert.False(t, d.Allowed, "supply allowlist must NOT bypass the CVE gate")
	assert.Equal(t, "cve_found", d.Reason)

	// CVE-only entry: bypasses the CVE block, NOT the age hold.
	p = r.Current()
	p.AllowlistSupply = []string{}
	p.AllowlistCVE = []string{"pypi/requests@2.31.0"}
	require.NoError(t, r.Apply(p))
	d = r.Evaluate(rtRef(), highFinding())
	assert.True(t, d.Allowed, "cve allowlist bypasses the CVE gate")
	assert.Equal(t, "allowlisted_bypass", d.Reason)
	res = r.Check(context.Background(), rtRef(), freshMeta())
	assert.False(t, res.Allowed, "cve allowlist must NOT bypass min-age hold")
}

func TestRuntimeSeedsProfileAllowlistIntoBothLists(t *testing.T) {
	r := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{Enabled: true, BlockOn: "HIGH"},
		config.PolicyProfile{CVEBlock: true, Allowlist: []string{"pypi/requests"}},
		nil,
	)
	p := r.Current()
	assert.Equal(t, []string{"pypi/requests"}, p.AllowlistSupply)
	assert.Equal(t, []string{"pypi/requests"}, p.AllowlistCVE)
	assert.True(t, r.Check(context.Background(), rtRef(), freshMeta()).Allowed)
	assert.True(t, r.Evaluate(rtRef(), highFinding()).Allowed)
}
```

Update existing tests in the same file:
- `TestRuntimeBootFromConfig` (line ~47): replace `assert.Empty(t, p.Allowlist)` with `assert.Empty(t, p.AllowlistSupply)` and `assert.Empty(t, p.AllowlistCVE)`.
- `TestRuntimeApplyValidation` (lines ~104-105): replace the two `allowlist[0]` cases with four:

```go
{"allowlist_supply[0]", func(p *policy.RuntimeParams) { p.AllowlistSupply = []string{"no-slash"} }},
{"allowlist_supply[0]", func(p *policy.RuntimeParams) { p.AllowlistSupply = []string{"eco / name"} }},
{"allowlist_cve[0]", func(p *policy.RuntimeParams) { p.AllowlistCVE = []string{"no-slash"} }},
{"allowlist_cve[0]", func(p *policy.RuntimeParams) { p.AllowlistCVE = []string{"eco / name"} }},
```

- `TestRuntimeFileAllowlistAlwaysMerged` (line ~127): replace `p.Allowlist = []string{}` with `p.AllowlistSupply = []string{}`.

Update `internal/policy/runtime_persist_test.go`:
- `TestNewRuntimeWithStore_LoadsExisting` (line ~54): replace `Allowlist: []string{}, Denylist: []string{},` with `AllowlistSupply: []string{}, AllowlistCVE: []string{}, Denylist: []string{},`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run TestRuntime -v`
Expected: compile error `p.AllowlistSupply undefined` (the new fields don't exist yet).

- [ ] **Step 3: Implement in `internal/policy/runtime.go`**

Replace the `RuntimeParams` struct (lines 14-21):

```go
// RuntimeParams are the console-editable policy knobs (PUT /api/policy).
// Allowlists are per-gate: supply entries bypass only the min-age hold, cve
// entries bypass only the CVE block. Nothing bypasses the malware gate.
type RuntimeParams struct {
	Mode            string   `json:"mode"`          // supply-chain mode: enforce | dry_run | off
	MinAgeHours     int      `json:"min_age_hours"` // supply-chain minimum age, >= 0
	CVEBlockOn      string   `json:"cve_block_on"`  // CRITICAL | HIGH | MEDIUM | LOW
	AllowlistSupply []string `json:"allowlist_supply"` // "eco/name[@version]", bypasses the age hold
	AllowlistCVE    []string `json:"allowlist_cve"`    // "eco/name[@version]", bypasses the CVE block
	Denylist        []string `json:"denylist"`
}
```

Replace the NewRuntime doc-comment note (lines 68-71) with:

```go
// NewRuntime builds the boot snapshot from config. fileAllow entries are
// always honored by the supply-chain filter regardless of runtime edits.
//
// The YAML profile allowlist historically bypassed CVE and age checks, so it
// seeds BOTH per-gate lists. Runtime edits manage the two lists independently.
```

In `newRuntimeSeed`, replace the `Allowlist:` seed line with:

```go
		AllowlistSupply: append([]string{}, profile.Allowlist...),
		AllowlistCVE:    append([]string{}, profile.Allowlist...),
```

Replace `install`:

```go
func (r *Runtime) install(p RuntimeParams) {
	p.AllowlistSupply = append([]string{}, p.AllowlistSupply...)
	p.AllowlistCVE = append([]string{}, p.AllowlistCVE...)
	p.Denylist = append([]string{}, p.Denylist...)
	merged := append(append([]string{}, r.fileAllow...), p.AllowlistSupply...)
	filter := supplychain.NewFilter(
		config.SupplyChainConfig{Mode: p.Mode, MinAgeHours: p.MinAgeHours},
		supplychain.NewAllowlist(merged),
	)
	prof := r.profile
	prof.CVEMinSeverity = p.CVEBlockOn
	prof.Allowlist = p.AllowlistCVE
	prof.Denylist = p.Denylist
	r.cur.Store(&runtimeSnapshot{
		engine: NewEngine(r.cveCfg, prof),
		filter: filter,
		params: p,
	})
}
```

In `Apply`, replace the single allowlist validation loop with:

```go
	for i, e := range p.AllowlistSupply {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("allowlist_supply[%d]", i), Message: msg}
		}
	}
	for i, e := range p.AllowlistCVE {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("allowlist_cve[%d]", i), Message: msg}
		}
	}
```

In `Current`, replace the copy lines with:

```go
	p.AllowlistSupply = append([]string{}, p.AllowlistSupply...)
	p.AllowlistCVE = append([]string{}, p.AllowlistCVE...)
	p.Denylist = append([]string{}, p.Denylist...)
```

- [ ] **Step 4: Run package tests** (console/cmd will not compile yet — that's Tasks 2-3)

Run: `go test ./internal/policy/ ./internal/supplychain/ -v`
Expected: PASS (all, including the two new tests).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/runtime.go internal/policy/runtime_test.go internal/policy/runtime_persist_test.go
git commit -m "feat(policy): split runtime allowlist into per-gate supply/cve lists"
```

---

### Task 2: stored-policy codec with legacy migration

**Files:**
- Create: `internal/policy/store.go`
- Test: `internal/policy/store_test.go`
- Modify: `cmd/jo-ei/main.go:487-509` (policySettingsStore), `cmd/jo-ei/main.go:225` (log copy), `integration/settings_persistence_test.go:20-39` (policyStore mirror)

**Interfaces:**
- Produces: `policy.DecodeStored(b []byte) (RuntimeParams, error)` and `policy.EncodeStored(p RuntimeParams) ([]byte, error)`.
- Consumes: `RuntimeParams` from Task 1.

- [ ] **Step 1: Write the failing test**

Create `internal/policy/store_test.go`:

```go
package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/policy"
)

func TestDecodeStored_MigratesLegacyAllowlistIntoBothLists(t *testing.T) {
	legacy := []byte(`{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH",` +
		`"allowlist":["pypi/requests@2.31.0","npm/left-pad@1.3.0"],"denylist":[]}`)
	p, err := policy.DecodeStored(legacy)
	require.NoError(t, err)
	assert.Equal(t, []string{"pypi/requests@2.31.0", "npm/left-pad@1.3.0"}, p.AllowlistSupply)
	assert.Equal(t, []string{"pypi/requests@2.31.0", "npm/left-pad@1.3.0"}, p.AllowlistCVE)
	assert.Equal(t, "enforce", p.Mode)
}

func TestDecodeStored_NewFormatRoundTrip(t *testing.T) {
	in := policy.RuntimeParams{
		Mode: "dry_run", MinAgeHours: 5, CVEBlockOn: "LOW",
		AllowlistSupply: []string{"pypi/a@1"}, AllowlistCVE: []string{"npm/b@2"},
		Denylist: []string{"pypi/evil"},
	}
	b, err := policy.EncodeStored(in)
	require.NoError(t, err)
	out, err := policy.DecodeStored(b)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestDecodeStored_LegacyEntriesDeduplicated(t *testing.T) {
	mixed := []byte(`{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH",` +
		`"allowlist":["pypi/a@1"],"allowlist_supply":["pypi/a@1"],"allowlist_cve":[],"denylist":[]}`)
	p, err := policy.DecodeStored(mixed)
	require.NoError(t, err)
	assert.Equal(t, []string{"pypi/a@1"}, p.AllowlistSupply, "no duplicate from legacy merge")
	assert.Equal(t, []string{"pypi/a@1"}, p.AllowlistCVE)
}

func TestDecodeStored_InvalidJSON(t *testing.T) {
	_, err := policy.DecodeStored([]byte("{nope"))
	require.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestDecodeStored -v`
Expected: compile error `undefined: policy.DecodeStored`.

- [ ] **Step 3: Implement `internal/policy/store.go`**

```go
package policy

import "encoding/json"

// storedParams is the persisted JSON shape of the runtime policy.
// LegacyAllowlist accepts rows written before the per-gate split, when a
// single "allowlist" bypassed all gates; DecodeStored migrates those entries
// into both per-gate lists so behavior does not change silently on upgrade.
type storedParams struct {
	RuntimeParams
	LegacyAllowlist []string `json:"allowlist,omitempty"`
}

// DecodeStored parses a persisted policy row, migrating the legacy single
// allowlist into both per-gate lists (deduplicated, order preserved).
func DecodeStored(b []byte) (RuntimeParams, error) {
	var sp storedParams
	if err := json.Unmarshal(b, &sp); err != nil {
		return RuntimeParams{}, err
	}
	p := sp.RuntimeParams
	for _, e := range sp.LegacyAllowlist {
		p.AllowlistSupply = appendMissing(p.AllowlistSupply, e)
		p.AllowlistCVE = appendMissing(p.AllowlistCVE, e)
	}
	return p, nil
}

// EncodeStored marshals the params in the current (per-gate) format; the
// legacy "allowlist" key is never written back.
func EncodeStored(p RuntimeParams) ([]byte, error) {
	return json.Marshal(p)
}

func appendMissing(list []string, e string) []string {
	for _, x := range list {
		if x == e {
			return list
		}
	}
	return append(list, e)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/ -run TestDecodeStored -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Wire the adapters**

In `cmd/jo-ei/main.go` replace the body of `policySettingsStore.LoadPolicy` / `SavePolicy`:

```go
func (p policySettingsStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	b, ok, err := p.s.Get("policy")
	if err != nil || !ok {
		return policy.RuntimeParams{}, ok, err
	}
	rp, err := policy.DecodeStored(b)
	if err != nil {
		return policy.RuntimeParams{}, false, fmt.Errorf("decoding stored policy: %w", err)
	}
	return rp, true, nil
}

func (p policySettingsStore) SavePolicy(rp policy.RuntimeParams) error {
	b, err := policy.EncodeStored(rp)
	if err != nil {
		return err
	}
	return p.s.Put("policy", b)
}
```

(If `encoding/json` becomes unused in `cmd/jo-ei/main.go` after this, remove the import; it is likely still used elsewhere in the file — check compiler output.)

In `cmd/jo-ei/main.go:225` update the warn copy to name the split list:

```go
logger.Warn().Msg("cve.enabled is false — console policy edits to cve_block_on, allowlist_cve and denylist have no effect (supply-chain mode/min-age/allowlist_supply still apply)")
```

In `integration/settings_persistence_test.go` replace the `policyStore` methods with the same codec calls:

```go
func (p policyStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	b, ok, err := p.s.Get("policy")
	if err != nil || !ok {
		return policy.RuntimeParams{}, ok, err
	}
	rp, derr := policy.DecodeStored(b)
	return rp, true, derr
}

func (p policyStore) SavePolicy(rp policy.RuntimeParams) error {
	b, err := policy.EncodeStored(rp)
	if err != nil {
		return err
	}
	return p.s.Put("policy", b)
}
```

Also add a migration assertion to `TestPolicyPersistsAcrossRestart` — in the "first process" block, before `db.Close()`, overwrite the row with a legacy-format payload, then assert after reopen:

```go
		// Simulate a pre-split row: single "allowlist" key.
		require.NoError(t, st.Put("policy", []byte(`{"mode":"dry_run","min_age_hours":0,"cve_block_on":"CRITICAL","allowlist":["pypi/requests@2.31.0"],"denylist":[]}`)))
```

and in the second-process assertions:

```go
	assert.Equal(t, []string{"pypi/requests@2.31.0"}, r.Current().AllowlistSupply, "legacy allowlist migrated to supply list")
	assert.Equal(t, []string{"pypi/requests@2.31.0"}, r.Current().AllowlistCVE, "legacy allowlist migrated to cve list")
```

(`json` import in that file stays — the registries test uses it.)

- [ ] **Step 6: Verify**

Run: `go build ./... ; go test ./internal/policy/ ; go test -tags integration ./integration/ -run TestPolicyPersistsAcrossRestart -v`
Expected: build fails ONLY in `internal/console` (server.go still references `p.Allowlist` — fixed in Task 3). If so, run the two test commands anyway; both must PASS. If `internal/console` blocks the integration build, defer the integration run to Task 3 Step 4 and note it.

- [ ] **Step 7: Commit**

```bash
git add internal/policy/store.go internal/policy/store_test.go cmd/jo-ei/main.go integration/settings_persistence_test.go
git commit -m "feat(policy): stored-policy codec migrates legacy allowlist into both gate lists"
```

---

### Task 3: console API exposes per-gate lists

**Files:**
- Modify: `internal/console/server.go:262-274` (writePolicy)
- Test: `internal/console/server_test.go` (TestPolicyGetAndPut, line ~189-248; auth body line ~434), `internal/console/registries_test.go:309`, `integration/console_test.go:122`, `integration/console_auth_test.go:140`

**Interfaces:**
- Consumes: `RuntimeParams` (Task 1). `putPolicy` already embeds `policy.RuntimeParams`, so the new JSON field names apply automatically; `DisallowUnknownFields` now rejects a legacy `"allowlist"` key in PUT bodies (intended — console and server ship together).
- Produces: GET/PUT `/api/policy` JSON with `allowlist_supply` and `allowlist_cve` arrays (no `allowlist` key).

- [ ] **Step 1: Update the test**

In `internal/console/server_test.go` `TestPolicyGetAndPut`:

Replace the response struct field (line ~196):

```go
		AllowlistSupply []string `json:"allowlist_supply"`
		AllowlistCVE    []string `json:"allowlist_cve"`
```

Replace the two PUT bodies and assertions (lines ~228-237):

```go
	resp := put(`{"mode":"dry_run","min_age_hours":48,"cve_block_on":"CRITICAL","allowlist_supply":["pypi/requests"],"allowlist_cve":["npm/left-pad"],"denylist":[]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pol))
	assert.Equal(t, "dry_run", pol.Mode)
	assert.Equal(t, 48, pol.MinAgeHours)
	assert.Equal(t, []string{"pypi/requests"}, pol.AllowlistSupply)
	assert.Equal(t, []string{"npm/left-pad"}, pol.AllowlistCVE)
	assert.Equal(t, "dry_run", f.runtime.Current().Mode, "runtime actually swapped")

	resp = put(`{"mode":"yolo","min_age_hours":1,"cve_block_on":"HIGH","allowlist_supply":[],"allowlist_cve":[],"denylist":[]}`)
```

Add a rejection check for the legacy key right after the yolo case assertions:

```go
	resp = put(`{"mode":"enforce","min_age_hours":1,"cve_block_on":"HIGH","allowlist":["pypi/x"],"denylist":[]}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "legacy allowlist key rejected by DisallowUnknownFields")
```

Update the other hard-coded PUT bodies (mechanical `"allowlist":[]` → `"allowlist_supply":[],"allowlist_cve":[]`):
- `internal/console/server_test.go:434`
- `internal/console/registries_test.go:309`
- `integration/console_test.go:122`
- `integration/console_auth_test.go:140`

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/console/ -run TestPolicyGetAndPut -v`
Expected: FAIL — `writePolicy` still emits `"allowlist"`, so `AllowlistSupply` decodes empty and the first PUT (with `allowlist_supply`) may 400 only if the field were unknown — it is known (RuntimeParams), so the failure appears at the GET/PUT round-trip or the `pol.AllowlistSupply` assertion.

- [ ] **Step 3: Implement**

In `internal/console/server.go` `writePolicy`, replace `"allowlist": p.Allowlist,` with:

```go
		"allowlist_supply": p.AllowlistSupply,
		"allowlist_cve":    p.AllowlistCVE,
```

- [ ] **Step 4: Verify the whole tree compiles and unit+integration tests pass**

Run: `go build ./... ; go test ./... ; go test -tags integration ./integration/ -run 'TestPolicy|TestConsole' -v`
Expected: PASS everywhere (this is the first point the full tree compiles again).

- [ ] **Step 5: Commit**

```bash
git add internal/console/server.go internal/console/server_test.go internal/console/registries_test.go integration/console_test.go integration/console_auth_test.go
git commit -m "feat(console): expose per-gate allowlists in the policy API"
```

---

### Task 4: console UI — per-gate lists, remove Wait button

**Files:**
- Modify: `web/console/src/api.js`, `web/console/src/app.jsx`, `web/console/src/quarantine.jsx`, `web/console/src/drawer.jsx`, `web/console/src/policy.jsx`
- Generated: `web/console/app.bundle.js` (via `go generate ./...` — never hand-edit)

**Interfaces:**
- Consumes: API fields `allowlist_supply` / `allowlist_cve` (Task 3).
- Produces: `onAllowlist(target, gate)` where `target = {eco, pkg, ver}` and `gate` is `"supply"` or `"cve"`; `JOEI.policy.allowlist_supply` / `JOEI.policy.allowlist_cve` arrays.

There is no JS test framework in this repo; verification is the bundle build plus Task 5's end-to-end check.

- [ ] **Step 1: `api.js` — defaults and save body**

Policy default (line ~36-39):

```js
    policy: {
      mode: "off", min_age_hours: 0, cve_block_on: "CRITICAL",
      allowlist_supply: [], allowlist_cve: [], denylist: [], persistence: "database",
    },
```

`savePolicy` body (line ~160-163):

```js
    const body = {
      mode: p.mode, min_age_hours: p.min_age_hours, cve_block_on: p.cve_block_on,
      allowlist_supply: p.allowlist_supply, allowlist_cve: p.allowlist_cve, denylist: p.denylist,
    };
```

- [ ] **Step 2: `app.jsx` — gate-aware onAllowlist**

Replace `onAllowlist` (lines ~105-114):

```jsx
  // target: { eco, pkg, ver }; gate: "supply" | "cve" — each gate has its own
  // allowlist, so trusting a quarantined package does not waive its CVE check
  // (and vice versa). Entries added from the console always pin the exact
  // version — a bare eco/pkg entry would trust every future release of a
  // package that was just blocked.
  const GATE_LIST = {
    supply: { key: "allowlist_supply", label: "supply-chain gate" },
    cve: { key: "allowlist_cve", label: "CVE gate" },
  };
  const onAllowlist = (target, gate) => {
    const { key, label } = GATE_LIST[gate] || GATE_LIST.supply;
    const t = `${target.eco}/${target.pkg}@${target.ver}`;
    saveLists(() => {
      const list = JOEI.policy[key];
      return { [key]: list.includes(t) ? list : [...list, t] };
    }, { kind: "ok", code: "200 OK", title: "Added to allowlist", msg: <>Now trusted at the {label}: <span className="t-pkg">{t}</span></> });
  };
```

- [ ] **Step 3: `quarantine.jsx` — remove Wait, target the supply gate**

Replace the actions block (lines ~36-41):

```jsx
      <div className="q-actions">
        <button className="btn jade sm grow" onClick={() => onAllowlist(q)}>
          <Icons.check /> Allowlist (trust)
        </button>
      </div>
```

Update `handle` in `Quarantine` (line ~54-57) to pass the gate:

```jsx
  const handle = (q) => {
    setItems((xs) => xs.filter((x) => x !== q));
    onAllowlist(q, "supply");
  };
```

Update the intro copy (line ~73) tail from "Trust one early by adding it to the allowlist." to:

```
Trust one early by adding it to the supply-chain allowlist — CVE and malware scans still apply.
```

- [ ] **Step 4: `drawer.jsx` — allowlist targets the blocking gate**

In `ThreatDrawer`, before the return, derive the gate (uses `r.blocked_by`, always an array per api.js `reviveEvent`):

```jsx
  const allowGate = r.blocked_by.includes("cve") ? "cve"
    : r.blocked_by.includes("supply_chain") ? "supply" : null;
  const allowGateLabel = allowGate === "cve" ? "CVE gate" : "supply-chain gate";
```

Replace the footer (lines ~154-175) so the allowlist path only renders when `allowGate` is set (malware- and denylist-blocked rows get no allowlist button — an entry would not unblock them):

```jsx
        <div className="drawer-foot">
          {confirm === "allow" && allowGate ? (
            <>
              <span className="muted grow" style={{ fontSize: 12.5 }}>Trust <b className="mono" style={{ color: "var(--washi)" }}>{target}@{r.ver}</b> at the {allowGateLabel}?</span>
              <button className="btn ghost sm" onClick={() => setConfirm(null)}>Cancel</button>
              <button className="btn jade sm" onClick={() => { onAllowlist({ eco: r.eco, pkg: r.pkg, ver: r.ver }, allowGate); onClose(); }}>Confirm allowlist</button>
            </>
          ) : confirm === "deny" ? (
            <>
              <span className="muted grow" style={{ fontSize: 12.5 }}>Permanently deny <b className="mono" style={{ color: "var(--washi)" }}>{target}@{r.ver}</b>?</span>
              <button className="btn ghost sm" onClick={() => setConfirm(null)}>Cancel</button>
              <button className="btn primary sm" onClick={() => { onDenylist(`${target}@${r.ver}`); onClose(); }}>Confirm denylist</button>
            </>
          ) : (
            <>
              {allowGate && (
                <button className="btn primary grow" onClick={() => setConfirm("allow")}>
                  <Icons.check /> Add to allowlist
                </button>
              )}
              <button className={`btn danger${allowGate ? "" : " grow"}`} onClick={() => setConfirm("deny")}>Add to denylist</button>
            </>
          )}
        </div>
```

- [ ] **Step 5: `policy.jsx` — two allowlist editors + YAML view**

Replace the single allowlist card (lines ~174-185) with two cards:

```jsx
          {/* supply-chain allowlist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--jade-l)" }}>Allowlist · 衛 supply-chain</label>
              <div className="hint">Format <span className="mono">ecosystem/name</span> or <span className="mono">ecosystem/name@version</span>. Bypasses only the minimum-age hold — CVE and malware scans still run.</div>
            </div>
            <div style={{ marginTop: 12 }}>
              <ListEditor kind="allow" items={p.allowlist_supply}
                onAdd={(v) => update({ allowlist_supply: [...p.allowlist_supply, v] })}
                onRemove={(v) => update({ allowlist_supply: p.allowlist_supply.filter((x) => x !== v) })} />
            </div>
          </div>

          {/* CVE allowlist */}
          <div className="card" style={{ padding: 22 }}>
            <div className="field">
              <label style={{ color: "var(--jade-l)" }}>Allowlist · 浄 CVE</label>
              <div className="hint">Format <span className="mono">ecosystem/name</span> or <span className="mono">ecosystem/name@version</span>. Bypasses only the CVE block — age hold and malware scan still run.</div>
            </div>
            <div style={{ marginTop: 12 }}>
              <ListEditor kind="allow" items={p.allowlist_cve}
                onAdd={(v) => update({ allowlist_cve: [...p.allowlist_cve, v] })}
                onRemove={(v) => update({ allowlist_cve: p.allowlist_cve.filter((x) => x !== v) })} />
            </div>
          </div>
```

Update `buildYaml` (lines ~39-40):

```js
    ["k", "allowlist_supply:"],
    ...p.allowlist_supply.map((x) => ["li", x]),
    ["c", ""],
    ["k", "allowlist_cve:"],
    ...p.allowlist_cve.map((x) => ["li", x]),
```

- [ ] **Step 6: Regenerate the bundle and verify it builds**

Run: `go generate ./...`
Expected: `web/console/app.bundle.js` regenerated, no esbuild errors. `git status` shows the five sources plus the bundle modified.

- [ ] **Step 7: Commit**

```bash
git add web/console/src web/console/app.bundle.js
git commit -m "feat(console-ui): per-gate allowlist editors; quarantine trusts supply gate only; drop no-op Wait button"
```

---

### Task 5: docs, full verification, PR

**Files:**
- Modify: `README.md:341,372,399,437`, `config.yaml:106-126` (comment only)

- [ ] **Step 1: README copy**

Line 341 — replace the row description with: `Packages that bypass CVE and age checks at boot (seeds both per-gate runtime allowlists). Format: \`pypi/requests\` (all versions) or \`pypi/requests@2.31.0\` (exact version)`.

Line 372 — replace "Or add the package to `policy.profiles.<name>.allowlist` to bypass the age check for" with: "Or add the package to the supply-chain allowlist (console → Policy → Allowlist · supply-chain, or `policy.profiles.<name>.allowlist` in YAML) to bypass the age check for".

Line 399 — replace "Or add the package+version to `allowlist` if the CVE has been reviewed and accepted" with: "Or add the package+version to the CVE allowlist (console → Policy → Allowlist · CVE) if the CVE has been reviewed and accepted".

Line 437 — keep, but change "an `allowlist` entry" to "an allowlist entry"; read the surrounding sentence and keep its meaning intact.

- [ ] **Step 2: config.yaml comment**

Above the `policy:` block (line 106) add:

```yaml
# Profile allowlists seed BOTH runtime per-gate lists (supply-chain age hold
# and CVE block). Per-gate edits live in the console and persist to the DB.
```

- [ ] **Step 3: Full verification**

```bash
gofmt -l ./cmd ./internal ./integration        # expect: no output
go test ./...                                  # expect: all PASS
go test -tags integration ./integration/...    # expect: all PASS
golangci-lint run ./...                        # expect: no issues
```

- [ ] **Step 4: Commit and PR**

```bash
git add README.md config.yaml
git commit -m "docs: per-gate allowlist semantics"
git push -u origin feat/per-gate-allowlists
gh pr create --base main --title "feat: per-gate allowlists (supply/CVE) + remove no-op quarantine Wait button" --body "..."
```

PR body must cover: why the single list was a hole (quarantine trust also waived CVE), the migration rule (legacy persisted entries → both lists, dedup), the DisallowUnknownFields consequence (old `allowlist` PUT key now 400s), and that the malware gate remains never-bypassable.

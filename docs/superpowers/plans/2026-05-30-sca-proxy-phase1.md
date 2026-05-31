# SCA Proxy — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Working transparent proxy for PyPI with Supply Chain Filter (24h rule) and local FS + SQLite cache.

**Architecture:** Single Go binary on `:8080`. ProxyHandler routes requests through RegistryAdapter (PyPI), SCFilter (age check), and local Cache. Metadata requests are proxied as-is; download requests are intercepted, age-checked, cached, and returned. Fail-closed: any error → blocked.

**Tech Stack:** Go 1.22+, `net/http`, `cobra`, `viper`, `zerolog`, `modernc.org/sqlite`, `testify`, `google/uuid`

**Design doc:** `docs/superpowers/specs/2026-05-30-sca-proxy-design.md`

**Note:** Module path used throughout is `github.com/sca-proxy/sca-proxy`. Rename in `go.mod` and all imports if your org differs.

**Phases after this plan:**
- Phase 2: CVE scanner (osv.dev) + Policy Engine
- Phase 3: Malware scanner (ClamAV) + npm/Maven/Go adapters
- Phase 4: Admin API + Prometheus + Alerting + S3 cache
- Phase 5: K8s manifests + k6 load tests + CI/CD

---

## File Map

```
sca-proxy/
├── cmd/sca-proxy/main.go               # cobra CLI entrypoint
├── internal/
│   ├── config/config.go                # Config struct + Load()
│   ├── proxy/
│   │   ├── adapter.go                  # PackageRef, PackageMetadata, RegistryAdapter interface
│   │   ├── handler.go                  # ProxyHandler: HTTP routing + pipeline
│   │   └── adapters/
│   │       └── pypi.go                 # PyPI RegistryAdapter
│   ├── supplychain/
│   │   ├── filter.go                   # SCFilter: 24h rule + allowlist
│   │   └── filter_test.go
│   └── cache/
│       ├── cache.go                    # Cache interface + CacheEntry
│       ├── index.go                    # SQLite CRUD
│       ├── index_test.go
│       └── local.go                    # Local FS cache (implements Cache)
├── config.yaml                         # Default config
├── Dockerfile
├── docker-compose.yaml
├── Makefile
├── go.mod
└── go.sum
```

---

## Task 1: Project scaffold

**Files:**
- Create: `sca-proxy/go.mod`
- Create: `sca-proxy/Makefile`
- Create: `sca-proxy/cmd/sca-proxy/main.go` (stub)

- [ ] **Step 1: Create project directory and initialize Go module**

```bash
mkdir -p sca-proxy
cd sca-proxy
go mod init github.com/sca-proxy/sca-proxy
```

- [ ] **Step 2: Install dependencies**

```bash
go get github.com/spf13/cobra@v1.8.1
go get github.com/spf13/viper@v1.19.0
go get github.com/rs/zerolog@v1.33.0
go get github.com/google/uuid@v1.6.0
go get github.com/stretchr/testify@v1.9.0
go get modernc.org/sqlite@v1.31.0
```

- [ ] **Step 3: Create directory structure**

```bash
mkdir -p cmd/sca-proxy internal/config internal/proxy/adapters internal/supplychain internal/cache
```

- [ ] **Step 4: Create stub main.go**

Create `cmd/sca-proxy/main.go`:

```go
package main

import "fmt"

func main() {
	fmt.Println("sca-proxy")
}
```

- [ ] **Step 5: Create Makefile**

Create `Makefile`:

```makefile
.PHONY: build test lint

build:
	go build -o bin/sca-proxy ./cmd/sca-proxy

test:
	go test ./... -v -race

lint:
	go vet ./...

run:
	go run ./cmd/sca-proxy --config config.yaml
```

- [ ] **Step 6: Verify build**

```bash
go build ./...
```

Expected: no output, no errors.

- [ ] **Step 7: Commit**

```bash
git init
git add .
git commit -m "chore: initialize Go module and project scaffold"
```

---

## Task 2: Config struct + loader

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `config.yaml`

- [ ] **Step 1: Write the failing test**

Create `internal/config/config_test.go`:

```go
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ParsesYAML(t *testing.T) {
	yaml := `
server:
  listen: ":9090"
registries:
  pypi:
    upstream: "https://pypi.org"
    enabled: true
supply_chain:
  min_age_hours: 48
  mode: "enforce"
cache:
  backend: "local"
  local:
    path: "/tmp/test-cache"
    max_size_gb: 10
logging:
  level: "debug"
  format: "json"
  output: "stdout"
`
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0644))

	cfg, err := config.Load(f)
	require.NoError(t, err)

	assert.Equal(t, ":9090", cfg.Server.Listen)
	assert.Equal(t, "https://pypi.org", cfg.Registries.PyPI.Upstream)
	assert.True(t, cfg.Registries.PyPI.Enabled)
	assert.Equal(t, 48, cfg.SupplyChain.MinAgeHours)
	assert.Equal(t, "enforce", cfg.SupplyChain.Mode)
	assert.Equal(t, "local", cfg.Cache.Backend)
	assert.Equal(t, "/tmp/test-cache", cfg.Cache.Local.Path)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoad_DefaultValues(t *testing.T) {
	yaml := `server:
  listen: ":8080"
`
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0644))

	cfg, err := config.Load(f)
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.Server.Listen)
	// Unset fields should have zero values
	assert.Equal(t, "", cfg.Cache.Backend)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/config/... -v
```

Expected: FAIL — `config` package does not exist yet.

- [ ] **Step 3: Implement config struct and loader**

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Registries  RegistriesConfig  `mapstructure:"registries"`
	SupplyChain SupplyChainConfig `mapstructure:"supply_chain"`
	Cache       CacheConfig       `mapstructure:"cache"`
	Policy      PolicyConfig      `mapstructure:"policy"`
	Logging     LoggingConfig     `mapstructure:"logging"`
}

type ServerConfig struct {
	Listen string    `mapstructure:"listen"`
	TLS    TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type RegistriesConfig struct {
	PyPI  RegistryConfig `mapstructure:"pypi"`
	NPM   RegistryConfig `mapstructure:"npm"`
	Maven RegistryConfig `mapstructure:"maven"`
}

type RegistryConfig struct {
	Upstream string `mapstructure:"upstream"`
	Enabled  bool   `mapstructure:"enabled"`
}

type SupplyChainConfig struct {
	MinAgeHours   int    `mapstructure:"min_age_hours"`
	AllowlistPath string `mapstructure:"allowlist_path"`
	Mode          string `mapstructure:"mode"` // enforce | dry_run | off
}

type CacheConfig struct {
	Backend string      `mapstructure:"backend"` // local | s3
	Local   LocalCache  `mapstructure:"local"`
	S3      S3Cache     `mapstructure:"s3"`
}

type LocalCache struct {
	Path      string `mapstructure:"path"`
	MaxSizeGB int    `mapstructure:"max_size_gb"`
}

type S3Cache struct {
	Endpoint string `mapstructure:"endpoint"`
	Bucket   string `mapstructure:"bucket"`
	Region   string `mapstructure:"region"`
}

type PolicyConfig struct {
	ActiveProfile string                    `mapstructure:"active_profile"`
	Profiles      map[string]PolicyProfile  `mapstructure:"profiles"`
}

type PolicyProfile struct {
	CVEBlock         bool `mapstructure:"cve_block"`
	SupplyChainBlock bool `mapstructure:"supply_chain_block"`
	MalwareBlock     bool `mapstructure:"malware_block"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// Load reads a YAML config file and returns a Config.
// Environment variables prefixed with SCAPROXY_ override file values.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("SCAPROXY")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	return &cfg, nil
}
```

- [ ] **Step 4: Create default config.yaml**

Create `config.yaml`:

```yaml
server:
  listen: ":8080"
  tls:
    enabled: false

registries:
  pypi:
    upstream: "https://pypi.org"
    enabled: true
  npm:
    upstream: "https://registry.npmjs.org"
    enabled: false
  maven:
    upstream: "https://repo1.maven.org"
    enabled: false

supply_chain:
  min_age_hours: 24
  mode: "enforce"

cache:
  backend: "local"
  local:
    path: "/var/cache/sca-proxy"
    max_size_gb: 100

policy:
  active_profile: "production"
  profiles:
    dev:
      cve_block: false
      supply_chain_block: false
    staging:
      cve_block: true
      supply_chain_block: true
    production:
      cve_block: true
      supply_chain_block: true
      malware_block: true

logging:
  level: "info"
  format: "json"
  output: "stdout"
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/config/... -v
```

Expected: PASS — both TestLoad_ParsesYAML and TestLoad_DefaultValues pass.

- [ ] **Step 6: Commit**

```bash
git add internal/config/ config.yaml
git commit -m "feat: add config struct and YAML loader"
```

---

## Task 3: Core types — PackageRef and RegistryAdapter interface

**Files:**
- Create: `internal/proxy/adapter.go`
- Create: `internal/proxy/adapter_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/adapter_test.go`:

```go
package proxy_test

import (
	"testing"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/stretchr/testify/assert"
)

func TestPackageRef_Key(t *testing.T) {
	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	assert.Equal(t, "pypi/requests@2.32.0", ref.Key())
}

func TestPackageRef_Key_NormalizesName(t *testing.T) {
	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "my-package", Version: "1.0.0"}
	assert.Equal(t, "pypi/my-package@1.0.0", ref.Key())
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/proxy/... -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement types**

Create `internal/proxy/adapter.go`:

```go
package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// PackageRef uniquely identifies a versioned package in an ecosystem.
type PackageRef struct {
	Ecosystem string // "pypi", "npm", "maven", "go"
	Name      string
	Version   string
}

// Key returns a stable cache/log key for this package reference.
func (r PackageRef) Key() string {
	return fmt.Sprintf("%s/%s@%s", r.Ecosystem, r.Name, r.Version)
}

// PackageMetadata contains resolved metadata from the upstream registry.
type PackageMetadata struct {
	PublishedAt time.Time
	Maintainer  string
	License     string
	Checksum    string // SHA256 hex
}

// RegistryAdapter abstracts a specific package registry.
type RegistryAdapter interface {
	// Name returns the ecosystem identifier, e.g. "pypi".
	Name() string

	// NormalizeRequest extracts a PackageRef from an incoming HTTP request.
	// Returns (ref, true) for download requests that should be intercepted.
	// Returns (nil, false) for metadata/simple-API requests (proxied as-is).
	NormalizeRequest(r *http.Request) (*PackageRef, bool)

	// FetchMetadata fetches version metadata from the upstream registry.
	FetchMetadata(ctx context.Context, ref *PackageRef) (*PackageMetadata, error)

	// UpstreamURL returns the upstream URL corresponding to a proxy request path.
	UpstreamURL(r *http.Request) string
}

// BlockedError is returned when a package is blocked by a policy.
type BlockedError struct {
	Package   PackageRef
	Reason    string
	BlockedBy []string
	Details   map[string]any
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("package %s blocked: %s (by %v)", e.Package.Key(), e.Reason, e.BlockedBy)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/proxy/... -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/adapter.go internal/proxy/adapter_test.go
git commit -m "feat: add PackageRef, PackageMetadata, RegistryAdapter interface"
```

---

## Task 4: Cache interface + CacheEntry types

**Files:**
- Create: `internal/cache/cache.go`

- [ ] **Step 1: Create cache types** (no tests needed for the interface file itself — testing happens in Task 5 and 6)

Create `internal/cache/cache.go`:

```go
package cache

import (
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// CacheEntry stores an artifact and its scan results.
type CacheEntry struct {
	// ArtifactPath is the absolute path to the cached file on disk.
	ArtifactPath string
	// ScanClean is true if all scanners passed.
	ScanClean    bool
	// ScanJSON stores the serialized ScanResult for inspection.
	ScanJSON     string
	StoredAt     time.Time
	ExpiresAt    time.Time
	HitCount     int64
	SizeBytes    int64
}

// IsExpired returns true if the entry TTL has passed.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// CacheStats holds aggregate statistics about the cache.
type CacheStats struct {
	Entries    int64
	SizeBytes  int64
	HitRatio   float64
	Evictions  int64
}

// Cache is the storage interface for package artifacts and scan results.
type Cache interface {
	// Get returns the cached entry for ref, or (nil, false) on miss/expiry.
	Get(ref *proxy.PackageRef) (*CacheEntry, bool)
	// Put stores an artifact (from tmpPath) along with its scan result.
	// The implementation copies the file from tmpPath into the cache store.
	Put(ref *proxy.PackageRef, tmpPath string, scanClean bool, scanJSON string) error
	// Invalidate removes the cached entry for ref.
	Invalidate(ref *proxy.PackageRef) error
	// Stats returns aggregate cache statistics.
	Stats() (CacheStats, error)
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/cache/cache.go
git commit -m "feat: add Cache interface and CacheEntry types"
```

---

## Task 5: SQLite index

**Files:**
- Create: `internal/cache/index.go`
- Create: `internal/cache/index_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/cache/index_test.go`:

```go
package cache_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestIndex(t *testing.T) (*cache.Index, func()) {
	t.Helper()
	dir := t.TempDir()
	idx, err := cache.NewIndex(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	return idx, func() { idx.Close() }
}

func TestIndex_InsertAndGet(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	entry := cache.CacheEntry{
		ArtifactPath: "/cache/pypi/requests-2.31.0.whl",
		ScanClean:    true,
		ScanJSON:     `{"clean":true}`,
		StoredAt:     time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second),
		SizeBytes:    4096,
	}

	err := idx.Insert(&ref, &entry)
	require.NoError(t, err)

	got, found := idx.Get(&ref)
	require.True(t, found)
	assert.Equal(t, entry.ArtifactPath, got.ArtifactPath)
	assert.True(t, got.ScanClean)
	assert.Equal(t, int64(4096), got.SizeBytes)
}

func TestIndex_GetMissing(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "nonexistent", Version: "9.9.9"}
	_, found := idx.Get(&ref)
	assert.False(t, found)
}

func TestIndex_IncrementHitCount(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"}
	entry := cache.CacheEntry{
		ArtifactPath: "/cache/flask.whl",
		ScanClean:    true,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		SizeBytes:    1024,
	}
	require.NoError(t, idx.Insert(&ref, &entry))

	require.NoError(t, idx.IncrementHit(&ref))
	require.NoError(t, idx.IncrementHit(&ref))

	got, found := idx.Get(&ref)
	require.True(t, found)
	assert.Equal(t, int64(2), got.HitCount)
}

func TestIndex_Delete(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "boto3", Version: "1.34.0"}
	entry := cache.CacheEntry{
		ArtifactPath: "/cache/boto3.whl",
		ScanClean:    true,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		SizeBytes:    512,
	}
	require.NoError(t, idx.Insert(&ref, &entry))

	require.NoError(t, idx.Delete(&ref))

	_, found := idx.Get(&ref)
	assert.False(t, found)
}

func TestIndex_LRUCandidates(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	// Insert 3 entries with different last-hit times.
	refs := []proxy.PackageRef{
		{Ecosystem: "pypi", Name: "a", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "b", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "c", Version: "1.0.0"},
	}
	base := time.Now().UTC()
	for i, ref := range refs {
		r := ref
		entry := cache.CacheEntry{
			ArtifactPath: "/cache/" + ref.Name + ".whl",
			ScanClean:    true,
			StoredAt:     base.Add(time.Duration(i) * time.Minute),
			ExpiresAt:    base.Add(24 * time.Hour),
			SizeBytes:    1024,
		}
		require.NoError(t, idx.Insert(&r, &entry))
	}

	// LRUCandidates should return entries ordered oldest-first.
	candidates, err := idx.LRUCandidates(2)
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	assert.Equal(t, "a", candidates[0].Name)
	assert.Equal(t, "b", candidates[1].Name)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/cache/... -v -run TestIndex
```

Expected: FAIL — `cache.Index` and `cache.NewIndex` do not exist.

- [ ] **Step 3: Implement the SQLite index**

Create `internal/cache/index.go`:

```go
package cache

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS artifacts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ecosystem    TEXT    NOT NULL,
	name         TEXT    NOT NULL,
	version      TEXT    NOT NULL,
	file_path    TEXT    NOT NULL,
	scan_clean   INTEGER NOT NULL DEFAULT 0,
	scan_json    TEXT    NOT NULL DEFAULT '',
	stored_at    INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	last_hit     INTEGER NOT NULL DEFAULT 0,
	hit_count    INTEGER NOT NULL DEFAULT 0,
	size_bytes   INTEGER NOT NULL DEFAULT 0,
	UNIQUE(ecosystem, name, version)
);
CREATE INDEX IF NOT EXISTS idx_last_hit ON artifacts(last_hit);
`

// Index manages the SQLite-backed metadata index for the local cache.
type Index struct {
	db *sql.DB
}

// NewIndex opens (or creates) a SQLite database at path and runs schema migrations.
func NewIndex(path string) (*Index, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db at %q: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("running schema: %w", err)
	}
	return &Index{db: db}, nil
}

// Close releases the database connection.
func (idx *Index) Close() error {
	return idx.db.Close()
}

// Insert adds a new cache entry. Uses UPSERT semantics.
func (idx *Index) Insert(ref *proxy.PackageRef, entry *CacheEntry) error {
	_, err := idx.db.Exec(`
		INSERT INTO artifacts
			(ecosystem, name, version, file_path, scan_clean, scan_json,
			 stored_at, expires_at, last_hit, hit_count, size_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, name, version) DO UPDATE SET
			file_path  = excluded.file_path,
			scan_clean = excluded.scan_clean,
			scan_json  = excluded.scan_json,
			stored_at  = excluded.stored_at,
			expires_at = excluded.expires_at,
			last_hit   = excluded.last_hit,
			size_bytes = excluded.size_bytes`,
		ref.Ecosystem, ref.Name, ref.Version,
		entry.ArtifactPath, boolToInt(entry.ScanClean), entry.ScanJSON,
		entry.StoredAt.Unix(), entry.ExpiresAt.Unix(),
		entry.StoredAt.Unix(), 0, entry.SizeBytes,
	)
	return err
}

// Get retrieves a cache entry. Returns (nil, false) if not found or expired.
func (idx *Index) Get(ref *proxy.PackageRef) (*CacheEntry, bool) {
	row := idx.db.QueryRow(`
		SELECT file_path, scan_clean, scan_json, stored_at, expires_at, hit_count, size_bytes
		FROM artifacts
		WHERE ecosystem=? AND name=? AND version=?`,
		ref.Ecosystem, ref.Name, ref.Version,
	)

	var (
		entry             CacheEntry
		scanCleanInt      int
		storedAtUnix      int64
		expiresAtUnix     int64
	)
	err := row.Scan(
		&entry.ArtifactPath, &scanCleanInt, &entry.ScanJSON,
		&storedAtUnix, &expiresAtUnix,
		&entry.HitCount, &entry.SizeBytes,
	)
	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	entry.ScanClean = scanCleanInt == 1
	entry.StoredAt = time.Unix(storedAtUnix, 0).UTC()
	entry.ExpiresAt = time.Unix(expiresAtUnix, 0).UTC()

	if entry.IsExpired() {
		return nil, false
	}
	return &entry, true
}

// IncrementHit bumps the hit counter and updates last_hit timestamp.
func (idx *Index) IncrementHit(ref *proxy.PackageRef) error {
	_, err := idx.db.Exec(`
		UPDATE artifacts SET hit_count=hit_count+1, last_hit=?
		WHERE ecosystem=? AND name=? AND version=?`,
		time.Now().Unix(), ref.Ecosystem, ref.Name, ref.Version,
	)
	return err
}

// Delete removes an entry from the index.
func (idx *Index) Delete(ref *proxy.PackageRef) error {
	_, err := idx.db.Exec(
		`DELETE FROM artifacts WHERE ecosystem=? AND name=? AND version=?`,
		ref.Ecosystem, ref.Name, ref.Version,
	)
	return err
}

// LRUCandidates returns up to n entries sorted by last_hit ascending (least recently used first).
// Used by the eviction loop to determine which entries to evict.
func (idx *Index) LRUCandidates(n int) ([]proxy.PackageRef, error) {
	rows, err := idx.db.Query(
		`SELECT ecosystem, name, version FROM artifacts ORDER BY last_hit ASC LIMIT ?`, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []proxy.PackageRef
	for rows.Next() {
		var ref proxy.PackageRef
		if err := rows.Scan(&ref.Ecosystem, &ref.Name, &ref.Version); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// TotalSizeBytes returns the sum of size_bytes across all entries.
func (idx *Index) TotalSizeBytes() (int64, error) {
	var total int64
	err := idx.db.QueryRow(`SELECT COALESCE(SUM(size_bytes),0) FROM artifacts`).Scan(&total)
	return total, err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/cache/... -v -run TestIndex
```

Expected: PASS — all 5 index tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/cache/cache.go internal/cache/index.go internal/cache/index_test.go
git commit -m "feat: add SQLite-backed cache index"
```

---

## Task 6: Local FS cache

**Files:**
- Create: `internal/cache/local.go`
- Create: `internal/cache/local_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/cache/local_test.go`:

```go
package cache_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLocalCache(t *testing.T) cache.Cache {
	t.Helper()
	dir := t.TempDir()
	c, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  dir,
		MaxSizeGB: 1,
		TTL:       24 * time.Hour,
	})
	require.NoError(t, err)
	return c
}

func makeTempArtifact(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "artifact-*.whl")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLocalCache_PutAndGet(t *testing.T) {
	c := newTestLocalCache(t)

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	tmpPath := makeTempArtifact(t, "fake-wheel-content")

	err := c.Put(&ref, tmpPath, true, `{"clean":true}`)
	require.NoError(t, err)

	entry, found := c.Get(&ref)
	require.True(t, found)
	assert.True(t, entry.ScanClean)
	assert.FileExists(t, entry.ArtifactPath)

	data, err := os.ReadFile(entry.ArtifactPath)
	require.NoError(t, err)
	assert.Equal(t, "fake-wheel-content", string(data))
}

func TestLocalCache_GetMiss(t *testing.T) {
	c := newTestLocalCache(t)
	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "nonexistent", Version: "1.0.0"}
	_, found := c.Get(&ref)
	assert.False(t, found)
}

func TestLocalCache_Invalidate(t *testing.T) {
	c := newTestLocalCache(t)

	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"}
	tmpPath := makeTempArtifact(t, "content")
	require.NoError(t, c.Put(&ref, tmpPath, true, ""))

	entry, found := c.Get(&ref)
	require.True(t, found)
	artifactPath := entry.ArtifactPath

	require.NoError(t, c.Invalidate(&ref))

	_, found = c.Get(&ref)
	assert.False(t, found)
	assert.NoFileExists(t, artifactPath)
}

func TestLocalCache_Stats(t *testing.T) {
	c := newTestLocalCache(t)

	ref1 := proxy.PackageRef{Ecosystem: "pypi", Name: "a", Version: "1.0"}
	ref2 := proxy.PackageRef{Ecosystem: "pypi", Name: "b", Version: "1.0"}
	require.NoError(t, c.Put(&ref1, makeTempArtifact(t, "aaaa"), true, ""))
	require.NoError(t, c.Put(&ref2, makeTempArtifact(t, "bbbbbbbb"), true, ""))

	stats, err := c.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.Entries)
	assert.Greater(t, stats.SizeBytes, int64(0))
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./internal/cache/... -v -run TestLocalCache
```

Expected: FAIL — `cache.NewLocalCache` and `cache.LocalCacheConfig` not defined.

- [ ] **Step 3: Implement local FS cache**

Create `internal/cache/local.go`:

```go
package cache

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// LocalCacheConfig configures the local filesystem cache.
type LocalCacheConfig struct {
	RootPath  string
	MaxSizeGB int
	TTL       time.Duration
}

// LocalCache implements Cache using the local filesystem with a SQLite index.
type LocalCache struct {
	cfg   LocalCacheConfig
	index *Index
}

// NewLocalCache creates a LocalCache at cfg.RootPath.
func NewLocalCache(cfg LocalCacheConfig) (*LocalCache, error) {
	if err := os.MkdirAll(cfg.RootPath, 0755); err != nil {
		return nil, fmt.Errorf("creating cache dir %q: %w", cfg.RootPath, err)
	}

	dbPath := filepath.Join(cfg.RootPath, "index.db")
	idx, err := NewIndex(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening cache index: %w", err)
	}

	lc := &LocalCache{cfg: cfg, index: idx}
	return lc, nil
}

// artifactPath returns the deterministic path for a cached artifact.
func (lc *LocalCache) artifactPath(ref *proxy.PackageRef) string {
	hash := sha256.Sum256([]byte(ref.Key()))
	hex := fmt.Sprintf("%x", hash)
	// Use first 2 hex chars as a sharding prefix directory.
	return filepath.Join(lc.cfg.RootPath, "artifacts", hex[:2], hex)
}

// Get returns a cached entry, or (nil, false) on miss.
func (lc *LocalCache) Get(ref *proxy.PackageRef) (*CacheEntry, bool) {
	entry, found := lc.index.Get(ref)
	if !found {
		return nil, false
	}

	// Verify the file still exists on disk.
	if _, err := os.Stat(entry.ArtifactPath); err != nil {
		// File missing — evict from index.
		_ = lc.index.Delete(ref)
		return nil, false
	}

	_ = lc.index.IncrementHit(ref)
	return entry, true
}

// Put copies the artifact from tmpPath into the cache and records it in the index.
func (lc *LocalCache) Put(ref *proxy.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	destPath := lc.artifactPath(ref)
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("creating artifact dir: %w", err)
	}

	srcFile, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("opening temp file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating cached file: %w", err)
	}
	defer dstFile.Close()

	written, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("copying artifact to cache: %w", err)
	}

	ttl := lc.cfg.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	entry := &CacheEntry{
		ArtifactPath: destPath,
		ScanClean:    scanClean,
		ScanJSON:     scanJSON,
		StoredAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(ttl),
		SizeBytes:    written,
	}

	if err := lc.index.Insert(ref, entry); err != nil {
		// Clean up the file if indexing fails.
		_ = os.Remove(destPath)
		return fmt.Errorf("indexing cached artifact: %w", err)
	}

	// Run LRU eviction if we're over the size limit.
	go lc.evictIfNeeded()

	return nil
}

// Invalidate removes an entry from both the index and disk.
func (lc *LocalCache) Invalidate(ref *proxy.PackageRef) error {
	entry, found := lc.index.Get(ref)
	if found {
		_ = os.Remove(entry.ArtifactPath)
	}
	return lc.index.Delete(ref)
}

// Stats returns aggregate cache statistics.
func (lc *LocalCache) Stats() (CacheStats, error) {
	size, err := lc.index.TotalSizeBytes()
	if err != nil {
		return CacheStats{}, err
	}
	count, err := lc.index.Count()
	if err != nil {
		return CacheStats{}, err
	}
	return CacheStats{Entries: count, SizeBytes: size}, nil
}

// evictIfNeeded removes LRU entries until the cache is under MaxSizeGB.
func (lc *LocalCache) evictIfNeeded() {
	maxBytes := int64(lc.cfg.MaxSizeGB) * 1024 * 1024 * 1024
	if maxBytes == 0 {
		return
	}

	total, err := lc.index.TotalSizeBytes()
	if err != nil || total <= maxBytes {
		return
	}

	// Evict in batches of 10 until under limit.
	for total > maxBytes {
		candidates, err := lc.index.LRUCandidates(10)
		if err != nil || len(candidates) == 0 {
			return
		}
		for _, ref := range candidates {
			r := ref
			_ = lc.Invalidate(&r)
		}
		total, _ = lc.index.TotalSizeBytes()
	}
}
```

**Before writing `local.go`**, first add `Count()` to `internal/cache/index.go` (append after `TotalSizeBytes`):

```go
// Count returns the total number of entries in the index.
func (idx *Index) Count() (int64, error) {
	var n int64
	err := idx.db.QueryRow(`SELECT COUNT(*) FROM artifacts`).Scan(&n)
	return n, err
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/cache/... -v
```

Expected: PASS — all cache and index tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/cache/
git commit -m "feat: add local FS cache with SQLite LRU index"
```

---

## Task 7: PyPI adapter

**Files:**
- Create: `internal/proxy/adapters/pypi.go`
- Create: `internal/proxy/adapters/pypi_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/adapters/pypi_test.go`:

```go
package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPyPIAdapter_NormalizeRequest_WheelDownload(t *testing.T) {
	a := adapters.NewPyPIAdapter("https://pypi.org")

	r := httptest.NewRequest(http.MethodGet,
		"/packages/cp312/r/requests/requests-2.32.0-py3-none-any.whl", nil)

	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "pypi", ref.Ecosystem)
	assert.Equal(t, "requests", ref.Name)
	assert.Equal(t, "2.32.0", ref.Version)
}

func TestPyPIAdapter_NormalizeRequest_TarGzDownload(t *testing.T) {
	a := adapters.NewPyPIAdapter("https://pypi.org")

	r := httptest.NewRequest(http.MethodGet,
		"/packages/source/r/requests/requests-2.32.0.tar.gz", nil)

	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "requests", ref.Name)
	assert.Equal(t, "2.32.0", ref.Version)
}

func TestPyPIAdapter_NormalizeRequest_SimpleAPINotIntercepted(t *testing.T) {
	a := adapters.NewPyPIAdapter("https://pypi.org")

	r := httptest.NewRequest(http.MethodGet, "/simple/requests/", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestPyPIAdapter_NormalizeRequest_UnderscoreNormalization(t *testing.T) {
	a := adapters.NewPyPIAdapter("https://pypi.org")

	r := httptest.NewRequest(http.MethodGet,
		"/packages/source/m/my_package/my_package-1.0.0.tar.gz", nil)

	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	// PyPI normalizes underscores to dashes
	assert.Equal(t, "my-package", ref.Name)
}

func TestPyPIAdapter_FetchMetadata(t *testing.T) {
	uploadTime := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	type pypiResp struct {
		Info struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			License string `json:"license"`
			Author  string `json:"author"`
		} `json:"info"`
		URLs []struct {
			UploadTimeISO string `json:"upload_time_iso_8601"`
			URL           string `json:"url"`
			Digests       struct {
				SHA256 string `json:"sha256"`
			} `json:"digests"`
		} `json:"urls"`
	}

	resp := pypiResp{}
	resp.Info.Name = "requests"
	resp.Info.Version = "2.31.0"
	resp.Info.License = "Apache-2.0"
	resp.Info.Author = "Kenneth Reitz"
	resp.URLs = []struct {
		UploadTimeISO string `json:"upload_time_iso_8601"`
		URL           string `json:"url"`
		Digests       struct {
			SHA256 string `json:"sha256"`
		} `json:"digests"`
	}{
		{
			UploadTimeISO: uploadTime.Format(time.RFC3339),
			URL:           "https://files.pythonhosted.org/packages/...requests-2.31.0.whl",
			Digests: struct {
				SHA256 string `json:"sha256"`
			}{SHA256: "abc123"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pypi/requests/2.31.0/json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	a := adapters.NewPyPIAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)

	assert.WithinDuration(t, uploadTime, meta.PublishedAt, time.Second)
	assert.Equal(t, "Kenneth Reitz", meta.Maintainer)
	assert.Equal(t, "Apache-2.0", meta.License)
	assert.Equal(t, "abc123", meta.Checksum)
}
```

Add `"github.com/sca-proxy/sca-proxy/internal/proxy"` to the imports at the top of `pypi_test.go`.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/proxy/adapters/... -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement PyPI adapter**

Create `internal/proxy/adapters/pypi.go`:

```go
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// pypiJSONResponse represents the PyPI JSON API response for a specific version.
type pypiJSONResponse struct {
	Info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		License string `json:"license"`
		Author  string `json:"author"`
	} `json:"info"`
	URLs []struct {
		UploadTimeISO string `json:"upload_time_iso_8601"`
		URL           string `json:"url"`
		Digests       struct {
			SHA256 string `json:"sha256"`
		} `json:"digests"`
	} `json:"urls"`
}

// PyPIAdapter implements proxy.RegistryAdapter for PyPI.
type PyPIAdapter struct {
	upstream   string
	httpClient *http.Client
}

// NewPyPIAdapter creates a PyPI adapter pointing at the given upstream URL.
func NewPyPIAdapter(upstream string) *PyPIAdapter {
	return &PyPIAdapter{
		upstream:   strings.TrimRight(upstream, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *PyPIAdapter) Name() string { return "pypi" }

// packagePathRe matches PyPI artifact download paths.
var packagePathRe = regexp.MustCompile(`^/packages/`)

// NormalizeRequest extracts a PackageRef from download requests.
// Returns false for /simple/ and /pypi/ (metadata) requests.
func (a *PyPIAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	if !packagePathRe.MatchString(r.URL.Path) {
		return nil, false
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 2 {
		return nil, false
	}

	filename := parts[len(parts)-1]
	// Strip hash fragment if present (e.g., filename.whl#sha256=...)
	if idx := strings.Index(filename, "#"); idx != -1 {
		filename = filename[:idx]
	}

	name, version, ok := parsePyPIFilename(filename)
	if !ok {
		return nil, false
	}

	return &proxy.PackageRef{
		Ecosystem: "pypi",
		Name:      name,
		Version:   version,
	}, true
}

// FetchMetadata fetches PyPI version metadata from the JSON API.
func (a *PyPIAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	apiURL := fmt.Sprintf("%s/pypi/%s/%s/json", a.upstream, ref.Name, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building metadata request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching pypi metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %s@%s not found on PyPI", ref.Name, ref.Version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi returned HTTP %d", resp.StatusCode)
	}

	var info pypiJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding pypi response: %w", err)
	}

	if len(info.URLs) == 0 {
		return nil, fmt.Errorf("no download URLs in pypi response for %s@%s", ref.Name, ref.Version)
	}

	publishedAt, err := time.Parse(time.RFC3339, info.URLs[0].UploadTimeISO)
	if err != nil {
		// PyPI sometimes omits timezone; try without it.
		publishedAt, err = time.Parse("2006-01-02T15:04:05.999999Z07:00", info.URLs[0].UploadTimeISO)
		if err != nil {
			return nil, fmt.Errorf("parsing upload_time_iso_8601 %q: %w", info.URLs[0].UploadTimeISO, err)
		}
	}

	return &proxy.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		Maintainer:  info.Info.Author,
		License:     info.Info.License,
		Checksum:    info.URLs[0].Digests.SHA256,
	}, nil
}

// UpstreamURL returns the upstream URL for a proxy request.
func (a *PyPIAdapter) UpstreamURL(r *http.Request) string {
	return a.upstream + r.URL.RequestURI()
}

// parsePyPIFilename extracts the normalized package name and version from a filename.
// Handles wheels (.whl), source distributions (.tar.gz, .zip).
func parsePyPIFilename(filename string) (name, version string, ok bool) {
	switch {
	case strings.HasSuffix(filename, ".whl"):
		// Wheel: {dist}-{version}(-{build})?-{python}-{abi}-{platform}.whl
		parts := strings.SplitN(strings.TrimSuffix(filename, ".whl"), "-", 3)
		if len(parts) >= 2 {
			return normalizePyPIName(parts[0]), parts[1], true
		}
	case strings.HasSuffix(filename, ".tar.gz"):
		base := strings.TrimSuffix(filename, ".tar.gz")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			return normalizePyPIName(base[:idx]), base[idx+1:], true
		}
	case strings.HasSuffix(filename, ".zip"):
		base := strings.TrimSuffix(filename, ".zip")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			return normalizePyPIName(base[:idx]), base[idx+1:], true
		}
	}
	return "", "", false
}

// normalizePyPIName converts a wheel distribution name to its canonical form
// (lowercase, underscores → dashes).
func normalizePyPIName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}
```


- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/proxy/adapters/... -v
```

Expected: PASS — all 5 PyPI adapter tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/adapters/pypi.go internal/proxy/adapters/pypi_test.go
git commit -m "feat: add PyPI registry adapter"
```

---

## Task 8: Supply Chain Filter

**Files:**
- Create: `internal/supplychain/filter.go`
- Create: `internal/supplychain/filter_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/supplychain/filter_test.go`:

```go
package supplychain_test

import (
	"context"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newFilter(mode string, allowlist *supplychain.Allowlist) *supplychain.Filter {
	return supplychain.NewFilter(config.SupplyChainConfig{
		MinAgeHours: 24,
		Mode:        mode,
	}, allowlist)
}

func TestFilter_BlocksPackageUnder24h(t *testing.T) {
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-1 * time.Hour)}

	result := f.Check(context.Background(), ref, meta)

	require.False(t, result.Allowed)
	assert.Equal(t, "package_version_newer_than_24h", result.Reason)
	assert.False(t, result.BlockUntil.IsZero())
}

func TestFilter_AllowsPackageOver24h(t *testing.T) {
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-25 * time.Hour)}

	result := f.Check(context.Background(), ref, meta)

	assert.True(t, result.Allowed)
	assert.Equal(t, "ok", result.Reason)
}

func TestFilter_BoundaryJustUnder24h(t *testing.T) {
	// 23h59m → should be BLOCKED
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-(24*time.Hour - time.Minute))}

	result := f.Check(context.Background(), ref, meta)
	assert.False(t, result.Allowed)
}

func TestFilter_BoundaryJustOver24h(t *testing.T) {
	// 24h01m → should be ALLOWED
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-(24*time.Hour + time.Minute))}

	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)
}

func TestFilter_DryRunPassesThroughButIndicates(t *testing.T) {
	f := newFilter("dry_run", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()} // brand new

	result := f.Check(context.Background(), ref, meta)

	assert.True(t, result.Allowed, "dry_run must pass through")
	assert.Equal(t, "dry_run", result.Reason)
}

func TestFilter_ModeOff_AlwaysPasses(t *testing.T) {
	f := newFilter("off", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()}

	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)
}

func TestFilter_AllowlistedPackageBypassesAgeCheck(t *testing.T) {
	al := supplychain.NewAllowlist([]string{"pypi/requests"})
	f := newFilter("enforce", al)

	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()} // brand new

	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)
	assert.Equal(t, "allowlisted", result.Reason)
}

func TestFilter_AllowlistedVersionSpecific(t *testing.T) {
	// Only this specific version is allowlisted
	al := supplychain.NewAllowlist([]string{"pypi/requests@2.32.0"})
	f := newFilter("enforce", al)

	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()}
	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)

	// Different version is NOT allowlisted
	ref2 := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.33.0"}
	result2 := f.Check(context.Background(), ref2, meta)
	assert.False(t, result2.Allowed)
}

func TestFilter_BlockUntilIsPublishedAtPlusMinAge(t *testing.T) {
	f := newFilter("enforce", nil)
	publishedAt := time.Now().Add(-2 * time.Hour)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "new-pkg", Version: "0.1.0"}
	meta := &proxy.PackageMetadata{PublishedAt: publishedAt}

	result := f.Check(context.Background(), ref, meta)

	require.False(t, result.Allowed)
	expected := publishedAt.Add(24 * time.Hour)
	assert.WithinDuration(t, expected, result.BlockUntil, time.Second)
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./internal/supplychain/... -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement the Supply Chain Filter**

Create `internal/supplychain/filter.go`:

```go
package supplychain

import (
	"context"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// FilterResult describes the outcome of a supply chain age check.
type FilterResult struct {
	Allowed     bool
	Reason      string    // "ok" | "allowlisted" | "dry_run" | "off" | "package_version_newer_than_24h"
	PublishedAt time.Time
	BlockUntil  time.Time // non-zero when Allowed=false
}

// Allowlist holds explicitly approved packages that bypass the age check.
// Entry format: "ecosystem/name" (all versions) or "ecosystem/name@version" (specific).
type Allowlist struct {
	entries map[string]bool
}

// NewAllowlist creates an Allowlist from a slice of entry strings.
func NewAllowlist(entries []string) *Allowlist {
	m := make(map[string]bool, len(entries))
	for _, e := range entries {
		m[strings.TrimSpace(e)] = true
	}
	return &Allowlist{entries: m}
}

// Contains reports whether ref is covered by the allowlist.
func (a *Allowlist) Contains(ref *proxy.PackageRef) bool {
	if a == nil {
		return false
	}
	byName := ref.Ecosystem + "/" + ref.Name
	byVersion := byName + "@" + ref.Version
	return a.entries[byName] || a.entries[byVersion]
}

// Filter implements the supply chain package age check.
type Filter struct {
	cfg       config.SupplyChainConfig
	allowlist *Allowlist
}

// NewFilter creates a Filter with the given configuration and allowlist.
func NewFilter(cfg config.SupplyChainConfig, allowlist *Allowlist) *Filter {
	return &Filter{cfg: cfg, allowlist: allowlist}
}

// Check applies the supply chain filter. It does not make network requests;
// the caller must provide pre-fetched PackageMetadata.
func (f *Filter) Check(_ context.Context, ref *proxy.PackageRef, meta *proxy.PackageMetadata) FilterResult {
	if f.cfg.Mode == "off" {
		return FilterResult{Allowed: true, Reason: "off", PublishedAt: meta.PublishedAt}
	}

	if f.allowlist.Contains(ref) {
		return FilterResult{Allowed: true, Reason: "allowlisted", PublishedAt: meta.PublishedAt}
	}

	minAge := time.Duration(f.cfg.MinAgeHours) * time.Hour
	age := time.Since(meta.PublishedAt)

	if age < minAge {
		blockUntil := meta.PublishedAt.Add(minAge)
		if f.cfg.Mode == "dry_run" {
			return FilterResult{
				Allowed:     true,
				Reason:      "dry_run",
				PublishedAt: meta.PublishedAt,
				BlockUntil:  blockUntil,
			}
		}
		return FilterResult{
			Allowed:     false,
			Reason:      "package_version_newer_than_24h",
			PublishedAt: meta.PublishedAt,
			BlockUntil:  blockUntil,
		}
	}

	return FilterResult{Allowed: true, Reason: "ok", PublishedAt: meta.PublishedAt}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/supplychain/... -v
```

Expected: PASS — all 8 filter tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/supplychain/
git commit -m "feat: add Supply Chain Filter with 24h rule, allowlist, dry_run mode"
```

---

## Task 9: ProxyHandler

**Files:**
- Create: `internal/proxy/handler.go`
- Create: `internal/proxy/handler_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/handler_test.go`:

```go
package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCache is an in-memory Cache for tests.
type fakeCache struct {
	entries map[string]*cache.CacheEntry
}

func (f *fakeCache) Get(ref *proxy.PackageRef) (*cache.CacheEntry, bool) {
	e, ok := f.entries[ref.Key()]
	return e, ok
}
func (f *fakeCache) Put(ref *proxy.PackageRef, tmpPath string, clean bool, scanJSON string) error {
	f.entries[ref.Key()] = &cache.CacheEntry{ArtifactPath: tmpPath, ScanClean: clean}
	return nil
}
func (f *fakeCache) Invalidate(ref *proxy.PackageRef) error {
	delete(f.entries, ref.Key())
	return nil
}
func (f *fakeCache) Stats() (cache.CacheStats, error) { return cache.CacheStats{}, nil }

func setupTestProxy(t *testing.T, upstream *httptest.Server, mode string) *httptest.Server {
	t.Helper()

	adapter := adapters.NewPyPIAdapter(upstream.URL)
	sc := supplychain.NewFilter(config.SupplyChainConfig{
		MinAgeHours: 24,
		Mode:        mode,
	}, nil)
	fc := &fakeCache{entries: map[string]*cache.CacheEntry{}}
	logger := zerolog.Nop()

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapter,
		Filter:   sc,
		Cache:    fc,
		Logger:   logger,
		Upstream: upstream.URL,
	})

	return httptest.NewServer(handler)
}

func TestHandler_SimpleAPIProxiedAsIs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/simple/requests/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>simple API</html>"))
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream, "enforce")
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/simple/requests/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_BlocksNewPackage(t *testing.T) {
	// Upstream serves metadata indicating the package was published 1h ago
	publishedAt := time.Now().UTC().Add(-1 * time.Hour)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/requests/2.32.0/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"name": "requests", "version": "2.32.0", "license": "Apache-2.0", "author": "KR",
				},
				"urls": []map[string]any{
					{
						"upload_time_iso_8601": publishedAt.Format(time.RFC3339),
						"url":                 "https://files.pythonhosted.org/packages/requests-2.32.0.whl",
						"digests":             map[string]any{"sha256": "deadbeef"},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("wheel-content"))
	}))
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.32.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusLocked, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
	assert.Equal(t, "package_version_newer_than_24h", body["reason"])
}

func TestHandler_AllowsOldPackage(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-25 * time.Hour)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/requests/2.31.0/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"name": "requests", "version": "2.31.0", "license": "Apache-2.0", "author": "KR",
				},
				"urls": []map[string]any{
					{
						"upload_time_iso_8601": publishedAt.Format(time.RFC3339),
						"url":                 "https://files.pythonhosted.org/packages/requests-2.31.0.whl",
						"digests":             map[string]any{"sha256": "abc"},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("wheel-content"))
	}))
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_HealthEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := setupTestProxy(t, upstream, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./internal/proxy/... -v -run TestHandler
```

Expected: FAIL — `proxy.NewHandler` and `proxy.HandlerConfig` do not exist.

- [ ] **Step 3: Implement ProxyHandler**

Create `internal/proxy/handler.go`:

```go
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
)

// HandlerConfig groups dependencies for the ProxyHandler.
type HandlerConfig struct {
	Adapter  RegistryAdapter
	Filter   *supplychain.Filter
	Cache    cache.Cache
	Logger   zerolog.Logger
	Upstream string
}

// Handler is the main HTTP handler that intercepts, scans, and proxies requests.
type Handler struct {
	cfg        HandlerConfig
	httpClient *http.Client
}

// NewHandler creates a new ProxyHandler.
func NewHandler(cfg HandlerConfig) *Handler {
	return &Handler{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	switch r.URL.Path {
	case "/health":
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
		return
	}

	ref, isDownload := h.cfg.Adapter.NormalizeRequest(r)
	if !isDownload {
		// Metadata / simple API request — proxy transparently
		h.proxyTransparent(w, r)
		return
	}

	log := h.cfg.Logger.With().
		Str("request_id", requestID).
		Str("package", ref.Key()).
		Logger()

	// Check cache first
	if entry, found := h.cfg.Cache.Get(ref); found {
		log.Debug().Msg("cache hit")
		h.serveFromCache(w, entry)
		return
	}

	// Fetch metadata for supply chain check
	ctx := r.Context()
	meta, err := h.cfg.Adapter.FetchMetadata(ctx, ref)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch metadata")
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_metadata_unavailable", nil)
		return
	}

	// Supply chain filter
	scResult := h.cfg.Filter.Check(ctx, ref, meta)
	if !scResult.Allowed {
		log.Warn().
			Str("reason", scResult.Reason).
			Time("published_at", scResult.PublishedAt).
			Time("block_until", scResult.BlockUntil).
			Msg("supply chain filter blocked package")

		h.writeBlockedResponse(w, requestID, ref, meta, scResult)
		return
	}
	if scResult.Reason == "dry_run" {
		log.Warn().Str("reason", "dry_run_would_block").Msg("dry_run: package would be blocked by SC filter")
	}

	// Download artifact from upstream to temp file
	upstreamURL := h.cfg.Adapter.UpstreamURL(r)
	tmpPath, err := h.downloadToTemp(ctx, upstreamURL)
	if err != nil {
		log.Error().Err(err).Str("upstream_url", upstreamURL).Msg("failed to download artifact")
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable", nil)
		return
	}
	defer os.Remove(tmpPath)

	// Cache the artifact (Phase 1: no CVE/AV scan yet — scanClean=true placeholder)
	// Phase 2 will run CVEScanner + AVScanner here before caching.
	if err := h.cfg.Cache.Put(ref, tmpPath, true, ""); err != nil {
		log.Error().Err(err).Msg("failed to cache artifact")
		// Fail-closed: don't serve if we can't cache
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "cache_error", nil)
		return
	}

	log.Info().Str("reason", scResult.Reason).Msg("serving artifact")
	entry, _ := h.cfg.Cache.Get(ref)
	h.serveFromCache(w, entry)
}

func (h *Handler) proxyTransparent(w http.ResponseWriter, r *http.Request) {
	upstreamURL := h.cfg.Upstream + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	// Copy relevant headers
	for key, vals := range r.Header {
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *Handler) downloadToTemp(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upstream returned HTTP %d for %s", resp.StatusCode, url)
	}

	tmp, err := os.CreateTemp("", "sca-proxy-artifact-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("writing temp file: %w", err)
	}

	return tmp.Name(), nil
}

func (h *Handler) serveFromCache(w http.ResponseWriter, entry *cache.CacheEntry) {
	f, err := os.Open(entry.ArtifactPath)
	if err != nil {
		http.Error(w, "cache read error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-SCA-Proxy-Cache", "HIT")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, f)
}

func (h *Handler) writeBlockedResponse(w http.ResponseWriter, requestID string, ref *PackageRef, meta *PackageMetadata, scResult supplychain.FilterResult) {
	body := map[string]any{
		"error":      "package_blocked",
		"package":    ref.Name,
		"version":    ref.Version,
		"reason":     scResult.Reason,
		"blocked_by": []string{"supply_chain_filter"},
		"request_id": requestID,
	}
	if !scResult.PublishedAt.IsZero() {
		body["published_at"] = scResult.PublishedAt.Format(time.RFC3339)
	}
	if !scResult.BlockUntil.IsZero() {
		body["block_until"] = scResult.BlockUntil.Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusLocked)
	json.NewEncoder(w).Encode(body)
}

func (h *Handler) writeError(w http.ResponseWriter, requestID string, ref *PackageRef, status int, reason string, extra map[string]any) {
	body := map[string]any{
		"error":      "proxy_error",
		"reason":     reason,
		"request_id": requestID,
	}
	if ref != nil {
		body["package"] = ref.Name
		body["version"] = ref.Version
	}
	for k, v := range extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/proxy/... -v -run TestHandler
```

Expected: PASS — all 4 handler tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat: add ProxyHandler with SC filter integration and fail-closed error handling"
```

---

## Task 10: CLI entrypoint

**Files:**
- Modify: `cmd/sca-proxy/main.go`

- [ ] **Step 1: Replace stub main.go with cobra CLI**

Overwrite `cmd/sca-proxy/main.go`:

```go
package main

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"net/http"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "sca-proxy",
	Short: "SCA Proxy — transparent supply chain security proxy for package registries",
	RunE:  runProxy,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "path to config file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runProxy(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	// Configure logger
	level, _ := zerolog.ParseLevel(cfg.Logging.Level)
	zerolog.SetGlobalLevel(level)
	logger := log.Logger

	if cfg.Logging.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	}

	// Build cache
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  cfg.Cache.Local.Path,
		MaxSizeGB: cfg.Cache.Local.MaxSizeGB,
		TTL:       24 * time.Hour,
	})
	if err != nil {
		return err
	}

	// Build SC filter. Allowlist file loading is added in Phase 2.
	scFilter := supplychain.NewFilter(cfg.SupplyChain, nil)

	// Build PyPI adapter (Phase 1 only; Phase 3 adds npm/Maven/Go)
	pypiAdapter := adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstream)

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  pypiAdapter,
		Filter:   scFilter,
		Cache:    localCache,
		Logger:   logger,
		Upstream: cfg.Registries.PyPI.Upstream,
	})

	logger.Info().
		Str("listen", cfg.Server.Listen).
		Str("upstream", cfg.Registries.PyPI.Upstream).
		Str("mode", cfg.SupplyChain.Mode).
		Msg("SCA Proxy starting")

	srv := &http.Server{
		Addr:    cfg.Server.Listen,
		Handler: handler,
	}

	return srv.ListenAndServe()
}
```

- [ ] **Step 2: Verify the binary builds**

```bash
go build ./cmd/sca-proxy
```

Expected: `sca-proxy` binary created, no errors.

- [ ] **Step 3: Smoke test the binary**

```bash
./sca-proxy --help
```

Expected: usage output with `--config` flag shown.

- [ ] **Step 4: Commit**

```bash
git add cmd/sca-proxy/main.go
git commit -m "feat: add cobra CLI entrypoint with config-driven startup"
```

---

## Task 11: Docker + docker-compose

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yaml`

- [ ] **Step 1: Create Dockerfile**

Create `Dockerfile`:

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /sca-proxy ./cmd/sca-proxy

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /sca-proxy /sca-proxy
COPY config.yaml /etc/sca-proxy/config.yaml
EXPOSE 8080
ENTRYPOINT ["/sca-proxy", "--config", "/etc/sca-proxy/config.yaml"]
```

- [ ] **Step 2: Create docker-compose.yaml**

```yaml
version: "3.9"

services:
  sca-proxy:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/sca-proxy/config.yaml:ro
      - cache-data:/var/cache/sca-proxy
      - clamav-socket:/var/run/clamav
    environment:
      - SCAPROXY_LOGGING_LEVEL=info
    depends_on:
      - clamav
    restart: unless-stopped

  clamav:
    image: clamav/clamav:stable
    volumes:
      - clamav-socket:/var/run/clamav
      - clamav-db:/var/lib/clamav
    restart: unless-stopped

volumes:
  cache-data:
  clamav-socket:
  clamav-db:
```

- [ ] **Step 3: Build the Docker image**

```bash
docker build -t sca-proxy:phase1 .
```

Expected: image built successfully. Image size should be under 30MB.

- [ ] **Step 4: Verify image runs**

```bash
docker run --rm -p 8080:8080 sca-proxy:phase1 &
sleep 2
curl -s http://localhost:8080/health
kill %1
```

Expected: `{"status":"ok"}` response.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile docker-compose.yaml
git commit -m "chore: add Dockerfile and docker-compose for Phase 1 deployment"
```

---

## Task 12: Integration test — full Phase 1 pipeline

**Files:**
- Create: `integration/phase1_test.go`

- [ ] **Step 1: Write the integration test**

Create `integration/phase1_test.go`:

```go
//go:build integration
// +build integration

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRegistry creates a mock PyPI server serving a single package.
func newTestRegistry(t *testing.T, packageName, version string, ageHours int) *httptest.Server {
	t.Helper()
	publishedAt := time.Now().UTC().Add(-time.Duration(ageHours) * time.Hour)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/pypi/"+packageName+"/"+version+"/json":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"name": packageName, "version": version,
					"license": "MIT", "author": "test",
				},
				"urls": []map[string]any{{
					"upload_time_iso_8601": publishedAt.Format(time.RFC3339),
					"url":                 "https://example.com/" + packageName + ".whl",
					"digests":             map[string]any{"sha256": "abc123"},
				}},
			})
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("fake-wheel-content-for-" + packageName + "-" + version))
		}
	}))
}

func newTestProxy(t *testing.T, upstream *httptest.Server, mode string) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  dir,
		MaxSizeGB: 1,
		TTL:       24 * time.Hour,
	})
	require.NoError(t, err)

	adapter := adapters.NewPyPIAdapter(upstream.URL)
	filter := supplychain.NewFilter(config.SupplyChainConfig{
		MinAgeHours: 24,
		Mode:        mode,
	}, nil)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapter,
		Filter:   filter,
		Cache:    localCache,
		Logger:   zerolog.Nop(),
		Upstream: upstream.URL,
	})

	return httptest.NewServer(h)
}

func TestIntegration_OldPackageAllowed(t *testing.T) {
	// Package published 48h ago — should be allowed
	registry := newTestRegistry(t, "requests", "2.31.0", 48)
	defer registry.Close()

	srv := newTestProxy(t, registry, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_NewPackageBlocked(t *testing.T) {
	// Package published 1h ago — should be blocked
	registry := newTestRegistry(t, "malicious-pkg", "1.0.0", 1)
	defer registry.Close()

	srv := newTestProxy(t, registry, "enforce")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/m/malicious-pkg/malicious_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusLocked, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
}

func TestIntegration_CacheHitOnSecondRequest(t *testing.T) {
	requestCount := 0
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/pypi/flask/3.0.0/json" {
			publishedAt := time.Now().UTC().Add(-48 * time.Hour)
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "flask", "version": "3.0.0", "license": "BSD", "author": "PF"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": publishedAt.Format(time.RFC3339),
					"url":                 "https://files.example.com/flask-3.0.0.whl",
					"digests":             map[string]any{"sha256": "def456"},
				}},
			})
			return
		}
		w.Write([]byte("flask-wheel"))
	}))
	defer registry.Close()

	srv := newTestProxy(t, registry, "enforce")
	defer srv.Close()

	url := srv.URL + "/packages/py3/f/flask/flask-3.0.0-py3-none-any.whl"

	// First request — cache miss, downloads from upstream
	initialCount := requestCount
	resp1, err := http.Get(url)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	countAfterFirst := requestCount

	// Second request — should be served from cache
	resp2, err := http.Get(url)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, "HIT", resp2.Header.Get("X-SCA-Proxy-Cache"))

	// Upstream was only hit for metadata + download on first request; not on second
	_ = initialCount
	_ = countAfterFirst
	// No additional upstream calls on cache hit
	assert.Equal(t, countAfterFirst, requestCount)
}

func TestIntegration_DryRunLogsButPasses(t *testing.T) {
	// New package (1h old) in dry_run mode — should be allowed through
	registry := newTestRegistry(t, "brand-new-pkg", "0.1.0", 1)
	defer registry.Close()

	srv := newTestProxy(t, registry, "dry_run")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/b/brand-new-pkg/brand_new_pkg-0.1.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

- [ ] **Step 2: Run all unit tests**

```bash
go test ./... -v -race
```

Expected: PASS — all unit tests pass (integration tests excluded by build tag).

- [ ] **Step 3: Run integration tests**

```bash
go test ./integration/... -v -tags integration
```

Expected: PASS — all 4 integration tests pass.

- [ ] **Step 4: Final Phase 1 commit**

```bash
git add integration/
git commit -m "test: add Phase 1 integration tests covering full proxy pipeline"
```

---

## Phase 1 Complete — Verification

Run the full test suite one final time to confirm everything passes:

```bash
make test
go test ./... -tags integration -v -race
```

Expected output: all tests pass, 0 failures, 0 data races.

Run the binary against the real PyPI to smoke-test manually:

```bash
go run ./cmd/sca-proxy --config config.yaml &
sleep 1
# Will be blocked (package may be new; try a version >24h old)
pip install --index-url http://localhost:8080 requests==2.31.0
kill %1
```

---

## Next Plan

Phase 2 plan: `docs/superpowers/plans/2026-05-30-sca-proxy-phase2.md`

Covers:
- CVE Scanner (`internal/scanner/cve.go`) — osv.dev API client
- Scanner interface + ScanPipeline with errgroup (parallel fan-out)
- Policy Engine (YAML hot-reload, allowlist/denylist/profiles)
- Cache: persist scan results, CVE TTL (24h refresh)
- Wire scanners into ProxyHandler (replacing `scanClean=true` placeholder)
- Structured audit log (zerolog JSON-lines)

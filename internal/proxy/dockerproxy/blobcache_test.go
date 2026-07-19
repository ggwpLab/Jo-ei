package dockerproxy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// fakeCache is a minimal in-memory cache.Cache for tests.
//
// mu guards entries: TestGateCoalesce_ParallelEvaluateSingleScan drives this
// fake from several goroutines, so Get/Put/Invalidate/Mark* race against each
// other unless serialized. Tests that peek at c.entries directly do so only
// outside any concurrent phase, so no lock is needed there.
type fakeCache struct {
	mu      sync.Mutex
	entries map[string]*cache.CacheEntry
}

func newFakeCache() *fakeCache { return &fakeCache{entries: map[string]*cache.CacheEntry{}} }

// Get returns a shallow copy of the stored entry, mirroring the production
// cache (which builds a fresh entry per Get). Returning the map's own pointer
// would let every concurrent caller alias one struct, so a follower's
// unlocked read of a field could race the flight leader's locked-but-aliased
// write in MarkCVEChecked/MarkMalwareChecked — the mutex here only
// serializes map access, not field access through a pointer a caller has
// already taken out of the lock.
func (f *fakeCache) Get(ref *gate.PackageRef) (*cache.CacheEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[ref.Key()]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}
func (f *fakeCache) Put(ref *gate.PackageRef, tmpPath string, clean bool, scanJSON string) error {
	// Copy the file so the entry survives the caller's defer os.Remove.
	now := time.Now()
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		// Allow os.DevNull or missing files (e.g. oversized-layer sentinel).
		f.mu.Lock()
		f.entries[ref.Key()] = &cache.CacheEntry{
			ArtifactPath: tmpPath, ScanClean: clean, ScanJSON: scanJSON,
			LastCVECheck: now, LastMalwareCheck: now,
		}
		f.mu.Unlock()
		return nil
	}
	dst, err := os.CreateTemp("", "fakecache-*")
	if err != nil {
		return err
	}
	if _, err := dst.Write(data); err != nil {
		dst.Close()
		return err
	}
	dst.Close()
	f.mu.Lock()
	f.entries[ref.Key()] = &cache.CacheEntry{
		ArtifactPath: dst.Name(), ScanClean: clean, ScanJSON: scanJSON,
		LastCVECheck: now, LastMalwareCheck: now,
	}
	f.mu.Unlock()
	return nil
}
func (f *fakeCache) Invalidate(ref *gate.PackageRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, ref.Key())
	return nil
}

func (f *fakeCache) MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastCVECheck = ts
	}
	return nil
}

func (f *fakeCache) MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastMalwareCheck = ts
	}
	return nil
}

func (f *fakeCache) Stats() (cache.CacheStats, error) { return cache.CacheStats{}, nil }
func (f *fakeCache) Close() error                     { return nil }

func TestVerdictStoreBlobRoundTrip(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "layer")
	if err := os.WriteFile(tmp, []byte("layerdata"), 0o600); err != nil {
		t.Fatal(err)
	}
	vs := newVerdictStore(newFakeCache())

	if _, _, found := vs.GetBlob("sha256:l1"); found {
		t.Fatal("blob should be absent initially")
	}
	if err := vs.PutBlob("sha256:l1", tmp, true); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	_, clean, found := vs.GetBlob("sha256:l1")
	if !found || !clean {
		t.Errorf("GetBlob = found:%v clean:%v", found, clean)
	}
}

func TestVerdictStoreImageVerdict(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "manifest")
	if err := os.WriteFile(tmp, []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vs := newVerdictStore(newFakeCache())
	if err := vs.PutImageVerdict("library/nginx", "sha256:img", tmp, false, "cve_found"); err != nil {
		t.Fatalf("PutImageVerdict: %v", err)
	}
	clean, reason, _, found := vs.GetImageVerdict("library/nginx", "sha256:img")
	if !found || clean || reason != "cve_found" {
		t.Errorf("verdict = clean:%v reason:%q found:%v", clean, reason, found)
	}
}

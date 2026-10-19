package metrics

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

const (
	alertsPath    = "../../examples/monitoring/alerts.yml"
	dashboardPath = "../../examples/monitoring/grafana/jo-ei-dashboard.json"
)

// metricNameRe matches metric identifiers without matching inside longer ones.
var metricNameRe = regexp.MustCompile(`\b(?:jo_ei|process|go)_[a-z0-9_]+\b`)

func readAsset(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err, path)
	return string(b)
}

// registeredNames returns every series name a scrape of m can expose,
// including the _bucket/_sum/_count series of histograms.
func registeredNames(t *testing.T, m *Metrics) map[string]bool {
	t.Helper()
	mfs, err := m.Registry.Gather()
	require.NoError(t, err)
	known := map[string]bool{}
	for _, mf := range mfs {
		n := mf.GetName()
		known[n] = true
		if mf.GetType() == dto.MetricType_HISTOGRAM {
			for _, s := range []string{"_bucket", "_sum", "_count"} {
				known[n+s] = true
			}
		}
	}
	return known
}

func TestAssetsReferenceOnlyRegisteredMetrics(t *testing.T) {
	m := newFullyWired(t)
	known := registeredNames(t, m)
	known["up"] = true
	// The process collector is a no-op off Linux; whitelist what the assets use.
	for _, n := range []string{
		"process_cpu_seconds_total", "process_resident_memory_bytes",
		"process_open_fds", "process_max_fds", "process_start_time_seconds",
	} {
		known[n] = true
	}
	for _, f := range []string{alertsPath, dashboardPath} {
		names := metricNameRe.FindAllString(readAsset(t, f), -1)
		assert.NotEmpty(t, names, f)
		for _, name := range names {
			assert.True(t, known[name], "%s references unregistered metric %s", f, name)
		}
	}
}

func TestAlertsYAMLParses(t *testing.T) {
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert       string            `yaml:"alert"`
				Expr        string            `yaml:"expr"`
				For         string            `yaml:"for"`
				Labels      map[string]string `yaml:"labels"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(readAsset(t, alertsPath)), &doc))
	require.Len(t, doc.Groups, 1)
	assert.Equal(t, "jo-ei", doc.Groups[0].Name)
	require.Len(t, doc.Groups[0].Rules, 11)
	for _, r := range doc.Groups[0].Rules {
		assert.NotEmpty(t, r.Alert)
		assert.NotEmpty(t, strings.TrimSpace(r.Expr), r.Alert)
		assert.NotEmpty(t, r.For, r.Alert)
		assert.NotEmpty(t, r.Labels["severity"], r.Alert)
		assert.NotEmpty(t, r.Annotations["summary"], r.Alert)
		assert.NotEmpty(t, r.Annotations["description"], r.Alert)
	}
}

func TestDashboardJSONParses(t *testing.T) {
	var d struct {
		UID    string `json:"uid"`
		Inputs []struct {
			Name string `json:"name"`
		} `json:"__inputs"`
		Panels []json.RawMessage `json:"panels"`
	}
	require.NoError(t, json.Unmarshal([]byte(readAsset(t, dashboardPath)), &d))
	assert.Equal(t, "jo-ei-overview", d.UID)
	require.Len(t, d.Inputs, 1)
	assert.Equal(t, "DS_PROMETHEUS", d.Inputs[0].Name)
	assert.NotEmpty(t, d.Panels)
}

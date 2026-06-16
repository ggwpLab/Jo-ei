//go:build integration

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestOverview_ReflectsDownScanner(t *testing.T) {
	// A clamd scanner pointed at a closed port: its active probe must fail,
	// surfacing status "down" in the overview.
	sc, err := scanner.NewClamAVScanner("tcp:127.0.0.1:1", time.Second)
	require.NoError(t, err)

	mon := health.NewMonitor(20*time.Millisecond, 2*time.Second)
	mon.AddActive("clamav", "tcp:127.0.0.1:1", true, sc.Probe)
	mon.Start()
	defer mon.Close()

	store := newTelemetryStore(t)
	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce"},
		config.CVEConfig{},
		config.PolicyProfile{},
		nil,
	)
	h := console.NewHandler(console.Config{
		Store:       store,
		Broadcaster: telemetry.NewBroadcaster(),
		Policy:      runtime,
		Health:      mon,
		Logger:      zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	require.Eventually(t, func() bool {
		resp, err := http.Get(srv.URL + "/api/overview")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var body struct {
			Scanners []health.ScannerHealth `json:"scanners"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) != nil || len(body.Scanners) != 1 {
			return false
		}
		return body.Scanners[0].Status == health.StatusDown
	}, 2*time.Second, 25*time.Millisecond)
}

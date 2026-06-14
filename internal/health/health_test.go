package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClassify(t *testing.T) {
	slow := 2 * time.Second
	cases := []struct {
		name     string
		sample   Sample
		wantStat Status
		wantMS   int64
	}{
		{"no data is unknown", Sample{HasData: false}, StatusUnknown, 0},
		{"no data ignores latency", Sample{HasData: false, Latency: 5 * time.Second}, StatusUnknown, 0},
		{"error is down", Sample{HasData: true, OK: false, Latency: 50 * time.Millisecond}, StatusDown, 0},
		{"slow is warn", Sample{HasData: true, OK: true, Latency: 3 * time.Second}, StatusWarn, 3000},
		{"fast is ok", Sample{HasData: true, OK: true, Latency: 40 * time.Millisecond}, StatusOK, 40},
		{"at threshold is ok", Sample{HasData: true, OK: true, Latency: 2 * time.Second}, StatusOK, 2000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStat, gotMS := classify(tc.sample, slow)
			assert.Equal(t, tc.wantStat, gotStat)
			assert.Equal(t, tc.wantMS, gotMS)
		})
	}
}

func TestClassify_NoThresholdNeverWarns(t *testing.T) {
	got, _ := classify(Sample{HasData: true, OK: true, Latency: time.Hour}, 0)
	assert.Equal(t, StatusOK, got)
}

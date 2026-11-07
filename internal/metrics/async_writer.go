package metrics

import (
	"errors"

	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
)

type asyncSeries struct {
	name, help string
	kind       prometheus.ValueType
	value      func(storage.WriterStats) float64
}

var asyncSeriesList = []asyncSeries{
	{"capacity", "Pending buffer capacity in events or distinct usage rows.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return float64(s.Capacity) }},
	{"queue_depth", "Pending events or distinct usage rows.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return float64(s.Queued) }},
	{"inflight_items", "In-flight events or distinct usage rows.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return float64(s.InFlight) }},
	{"unsaved_items", "Admitted events or original hits awaiting confirmed commit.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return float64(s.UnsavedItems) }},
	{"oldest_age_seconds", "Age of the oldest admitted unsaved observation.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return s.OldestAge.Seconds() }},
	{"last_success_age_seconds", "Time since last confirmed commit, or writer start before its first success.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return s.LastSuccessAge.Seconds() }},
	{"attempted_items_total", "Events or original hits offered to the writer.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return float64(s.AttemptedItems) }},
	{"accepted_items_total", "Events or original hits admitted by the writer.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return float64(s.AcceptedItems) }},
	{"committed_items_total", "Admitted events or original hits with confirmed commit.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return float64(s.CommittedItems) }},
	{"abandoned_items_total", "Admitted events or original hits unconfirmed at forced shutdown.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return float64(s.AbandonedItems) }},
	{"batches_total", "Batches with confirmed commit.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return float64(s.Batches) }},
	{"failures_total", "Failed or unconfirmed batch attempts.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return float64(s.Failures) }},
	{"retries_total", "Repeated attempts of an unconfirmed batch.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return float64(s.Retries) }},
	{"commit_seconds_total", "Time spent attempting batch transactions, including failures.", prometheus.CounterValue, func(s storage.WriterStats) float64 { return s.CommitTimeTotal.Seconds() }},
	{"last_batch_size", "Events or distinct usage rows in the last confirmed batch.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return float64(s.LastBatchSize) }},
	{"last_commit_seconds", "Duration of the last confirmed transaction attempt.", prometheus.GaugeValue, func(s storage.WriterStats) float64 { return s.LastCommitDuration.Seconds() }},
}

type asyncWriterCollector struct {
	snapshot    func() storage.WriterStats
	descriptors []*prometheus.Desc
	drops       *prometheus.Desc
}

// RegisterAsyncWriter exposes in-memory snapshots for the two bounded component
// names. Snapshot callbacks must never query storage or request a flush.
func (m *Metrics) RegisterAsyncWriter(component string, snapshot func() storage.WriterStats) {
	if m == nil || snapshot == nil || (component != "telemetry" && component != "cache_usage") {
		return
	}
	labels := prometheus.Labels{"component": component}
	c := &asyncWriterCollector{snapshot: snapshot}
	for _, series := range asyncSeriesList {
		c.descriptors = append(c.descriptors, prometheus.NewDesc("jo_ei_async_write_"+series.name, series.help, nil, labels))
	}
	c.drops = prometheus.NewDesc("jo_ei_async_write_dropped_items_total", "Incoming events or original hits rejected at admission.", []string{"reason"}, labels)
	if err := m.Registry.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if !errors.As(err, &already) {
			m.log.Error().Err(err).Msg("register async writer collector")
		}
	}
}

func (c *asyncWriterCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descriptors {
		ch <- d
	}
	ch <- c.drops
}
func (c *asyncWriterCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.snapshot()
	for i, series := range asyncSeriesList {
		ch <- prometheus.MustNewConstMetric(c.descriptors[i], series.kind, series.value(s))
	}
	ch <- prometheus.MustNewConstMetric(c.drops, prometheus.CounterValue, float64(s.DroppedFullItems), "queue_full")
	ch <- prometheus.MustNewConstMetric(c.drops, prometheus.CounterValue, float64(s.DroppedClosedItems), "closed")
}

package pgsql

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const histogramBuckets = 64

const maxFingerprintInput = 64 << 10

type latencyHistogram [histogramBuckets]uint64

func (h *latencyHistogram) add(duration time.Duration) {
	microseconds := uint64(max(duration.Microseconds(), 0))
	bucket := bits.Len64(microseconds)
	if bucket >= len(h) {
		bucket = len(h) - 1
	}
	h[bucket]++
}

func (h latencyHistogram) quantile(q float64, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	target := uint64(float64(count)*q + 0.999999)
	if target < 1 {
		target = 1
	}
	var seen uint64
	for bucket, bucketCount := range h {
		seen += bucketCount
		if seen >= target {
			if bucket == 0 {
				return 0
			}
			upperMicroseconds := (uint64(1) << bucket) - 1
			return time.Duration(upperMicroseconds) * time.Microsecond
		}
	}
	return 0
}

type queryStats struct {
	fingerprint string
	example     string
	count       uint64
	errors      uint64
	incomplete  uint64
	total       time.Duration
	min         time.Duration
	max         time.Duration
	histogram   latencyHistogram
}

// Summary is an immutable statistics snapshot suitable for table or JSON output.
type Summary struct {
	Fingerprint string
	Example     string
	Count       uint64
	Errors      uint64
	Incomplete  uint64
	Average     time.Duration
	Min         time.Duration
	Max         time.Duration
	P95         time.Duration
	P99         time.Duration
	Total       time.Duration
}

type latencyMilliseconds struct {
	Average float64 `json:"average"`
	Min     float64 `json:"min"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
	Max     float64 `json:"max"`
	Total   float64 `json:"total"`
}

type summaryJSON struct {
	Fingerprint string              `json:"fingerprint"`
	Example     string              `json:"example,omitempty"`
	Calls       uint64              `json:"calls"`
	Errors      uint64              `json:"errors"`
	Incomplete  uint64              `json:"incomplete"`
	Latency     latencyMilliseconds `json:"latency_ms"`
}

func (s Summary) MarshalJSON() ([]byte, error) {
	return json.Marshal(summaryJSON{
		Fingerprint: s.Fingerprint, Example: s.Example, Calls: s.Count,
		Errors: s.Errors, Incomplete: s.Incomplete,
		Latency: latencyMilliseconds{
			Average: durationMilliseconds(s.Average), Min: durationMilliseconds(s.Min),
			P95: durationMilliseconds(s.P95), P99: durationMilliseconds(s.P99),
			Max: durationMilliseconds(s.Max), Total: durationMilliseconds(s.Total),
		},
	})
}

func (s *Summary) UnmarshalJSON(data []byte) error {
	var value summaryJSON
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*s = Summary{
		Fingerprint: value.Fingerprint, Example: value.Example, Count: value.Calls,
		Errors: value.Errors, Incomplete: value.Incomplete,
		Average: millisecondsDuration(value.Latency.Average), Min: millisecondsDuration(value.Latency.Min),
		P95: millisecondsDuration(value.Latency.P95), P99: millisecondsDuration(value.Latency.P99),
		Max: millisecondsDuration(value.Latency.Max), Total: millisecondsDuration(value.Latency.Total),
	}
	return nil
}

func durationMilliseconds(duration time.Duration) float64 {
	milliseconds := float64(duration) / float64(time.Millisecond)
	return math.Round(milliseconds*1000) / 1000
}

func millisecondsDuration(milliseconds float64) time.Duration {
	return time.Duration(math.Round(milliseconds * float64(time.Millisecond)))
}

type Report struct {
	GeneratedAt       time.Time `json:"generated_at"`
	Queries           []Summary `json:"queries"`
	EncryptedSessions uint64    `json:"encrypted_sessions"`
	DecodeErrors      uint64    `json:"decode_errors"`
	DroppedKeys       uint64    `json:"dropped_query_keys"`
}

// Collector keeps bounded aggregate state. It never stores individual latency
// samples and caps the number of distinct SQL fingerprints.
type Collector struct {
	mu sync.RWMutex

	queries      map[string]*queryStats
	maxQueries   int
	showExamples bool

	encryptedSessions uint64
	decodeErrors      uint64
	droppedKeys       uint64
}

func NewCollector(maxQueries int, showExamples bool) *Collector {
	if maxQueries <= 0 {
		maxQueries = 10000
	}
	return &Collector{
		queries: make(map[string]*queryStats), maxQueries: maxQueries,
		showExamples: showExamples,
	}
}

func (c *Collector) Add(event Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if event.Encrypted {
		c.encryptedSessions++
		return
	}
	if event.Query == "" {
		return
	}
	query := event.Query
	truncated := false
	if len(query) > maxFingerprintInput {
		query = query[:maxFingerprintInput]
		truncated = true
	}
	fingerprint := Fingerprint(query)
	if truncated {
		fingerprint += " …[truncated]"
	}
	if fingerprint == "" {
		return
	}
	stats, found := c.queries[fingerprint]
	if !found {
		if len(c.queries) >= c.maxQueries {
			c.droppedKeys++
			fingerprint = "[other fingerprints]"
			stats = c.queries[fingerprint]
		}
		if stats == nil {
			stats = &queryStats{fingerprint: fingerprint}
			if c.showExamples && fingerprint != "[other fingerprints]" {
				stats.example = query
				if truncated {
					stats.example += " …[truncated]"
				}
			}
			c.queries[fingerprint] = stats
		}
	}

	stats.count++
	stats.total += event.Duration
	if stats.count == 1 || event.Duration < stats.min {
		stats.min = event.Duration
	}
	if event.Duration > stats.max {
		stats.max = event.Duration
	}
	if event.ErrorCode != "" || event.ErrorInfo != "" {
		stats.errors++
	}
	if event.Incomplete {
		stats.incomplete++
	}
	stats.histogram.add(event.Duration)
}

func (c *Collector) AddDecodeError() {
	c.mu.Lock()
	c.decodeErrors++
	c.mu.Unlock()
}

func (c *Collector) Snapshot(sortBy string, topN int) Report {
	c.mu.RLock()
	defer c.mu.RUnlock()

	report := Report{
		GeneratedAt: time.Now(), EncryptedSessions: c.encryptedSessions,
		DecodeErrors: c.decodeErrors, DroppedKeys: c.droppedKeys,
		Queries: make([]Summary, 0, len(c.queries)),
	}
	for _, stats := range c.queries {
		average := time.Duration(0)
		if stats.count > 0 {
			average = stats.total / time.Duration(stats.count)
		}
		p95 := min(stats.histogram.quantile(.95, stats.count), stats.max)
		p99 := min(stats.histogram.quantile(.99, stats.count), stats.max)
		report.Queries = append(report.Queries, Summary{
			Fingerprint: stats.fingerprint, Example: stats.example,
			Count: stats.count, Errors: stats.errors, Incomplete: stats.incomplete,
			Average: average, Min: stats.min, Max: stats.max,
			P95: p95, P99: p99, Total: stats.total,
		})
	}
	sort.Slice(report.Queries, func(i, j int) bool {
		left, right := report.Queries[i], report.Queries[j]
		switch sortBy {
		case "count":
			return left.Count > right.Count
		case "total":
			return left.Total > right.Total
		case "p95":
			return left.P95 > right.P95
		default:
			return left.Max > right.Max
		}
	})
	if topN > 0 && len(report.Queries) > topN {
		report.Queries = report.Queries[:topN]
	}
	return report
}

func WriteTable(w io.Writer, report Report) error {
	if _, err := fmt.Fprintf(w, "queries=%d encrypted_sessions=%d decode_errors=%d dropped_keys=%d\n",
		len(report.Queries), report.EncryptedSessions, report.DecodeErrors, report.DroppedKeys); err != nil {
		return err
	}
	if len(report.Queries) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CALLS\tERRORS\tINCOMPLETE\tAVG\tP95\tP99\tMAX\tSQL"); err != nil {
		return err
	}
	for _, summary := range report.Queries {
		query := summary.Fingerprint
		if summary.Example != "" {
			query = strings.ReplaceAll(summary.Example, "\n", " ")
		}
		if _, err := fmt.Fprintf(tw, "%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
			summary.Count, summary.Errors, summary.Incomplete, formatDuration(summary.Average),
			formatDuration(summary.P95), formatDuration(summary.P99),
			formatDuration(summary.Max), query); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func WriteJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func WritePrometheus(w io.Writer, report Report) error {
	if _, err := fmt.Fprintln(w, "# HELP pgsniffer_query_calls_total Observed PostgreSQL query executions.\n# TYPE pgsniffer_query_calls_total counter"); err != nil {
		return err
	}
	for _, summary := range report.Queries {
		label := prometheusLabel(summary.Fingerprint)
		if _, err := fmt.Fprintf(w, "pgsniffer_query_calls_total{query=\"%s\"} %d\n", label, summary.Count); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_errors_total{query=\"%s\"} %d\n", label, summary.Errors); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_seconds_total{query=\"%s\"} %.9f\n", label, summary.Total.Seconds()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_seconds{query=\"%s\",quantile=\"0.95\"} %.9f\n", label, summary.P95.Seconds()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_seconds{query=\"%s\",quantile=\"0.99\"} %.9f\n", label, summary.P99.Seconds()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_max_seconds{query=\"%s\"} %.9f\n", label, summary.Max.Seconds()); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "pgsniffer_encrypted_sessions_total %d\npgsniffer_decode_errors_total %d\npgsniffer_overflow_events_total %d\n",
		report.EncryptedSessions, report.DecodeErrors, report.DroppedKeys)
	return err
}

func prometheusLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func formatDuration(duration time.Duration) string {
	if duration < time.Microsecond {
		return duration.String()
	}
	if duration < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(duration)/float64(time.Microsecond))
	}
	if duration < time.Second {
		return fmt.Sprintf("%.2fms", float64(duration)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2fs", float64(duration)/float64(time.Second))
}

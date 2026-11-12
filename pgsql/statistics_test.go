package pgsql

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCollectorAggregatesFingerprintsAndBoundsCardinality(t *testing.T) {
	collector := NewCollector(2, false)
	collector.Add(Event{Query: "SELECT * FROM users WHERE id = 1", Duration: time.Millisecond})
	collector.Add(Event{Query: "SELECT * FROM users WHERE id = 2", Duration: 3 * time.Millisecond, ErrorCode: "XX000"})
	collector.Add(Event{Query: "SELECT * FROM teams", Duration: 2 * time.Millisecond})
	collector.Add(Event{Query: "DELETE FROM audit", Duration: 4 * time.Millisecond})
	collector.Add(Event{Encrypted: true})
	collector.AddDecodeError()

	report := collector.Snapshot("count", 0)
	if len(report.Queries) != 3 { // two admitted keys plus the bounded overflow bucket
		t.Fatalf("got %d summaries", len(report.Queries))
	}
	if report.EncryptedSessions != 1 || report.DecodeErrors != 1 || report.DroppedKeys != 1 {
		t.Fatalf("report counters = %+v", report)
	}
	if report.Queries[0].Count != 2 || report.Queries[0].Errors != 1 {
		t.Fatalf("first summary = %+v", report.Queries[0])
	}
}

func TestCollectorTopNAndWriters(t *testing.T) {
	collector := NewCollector(10, true)
	collector.Add(Event{Query: "SELECT 1", Duration: time.Millisecond})
	collector.Add(Event{Query: "SELECT 2", Duration: 2 * time.Millisecond})
	collector.Add(Event{Query: "SELECT pg_sleep(1)", Duration: time.Second})
	report := collector.Snapshot("max", 1)
	if len(report.Queries) != 1 || !strings.Contains(report.Queries[0].Fingerprint, "pg_sleep") {
		t.Fatalf("report = %+v", report)
	}

	var table bytes.Buffer
	if err := WriteTable(&table, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table.String(), "CALLS") || !strings.Contains(table.String(), "pg_sleep") {
		t.Fatalf("table = %q", table.String())
	}

	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, report); err != nil {
		t.Fatal(err)
	}
	if output := encoded.String(); !strings.Contains(output, `"calls"`) || !strings.Contains(output, `"latency_ms"`) || strings.Contains(output, `"average_ns"`) {
		t.Fatalf("unexpected JSON schema: %s", output)
	}
	var decoded Report
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Queries) != 1 || decoded.Queries[0].Count != 1 || decoded.Queries[0].Max != time.Second {
		t.Fatalf("decoded report = %+v", decoded)
	}

	var metrics bytes.Buffer
	if err := WritePrometheus(&metrics, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metrics.String(), "pgsniffer_query_calls_total") || !strings.Contains(metrics.String(), "pg_sleep") {
		t.Fatalf("metrics = %q", metrics.String())
	}
}

func TestQuantilesNeverExceedObservedMaximum(t *testing.T) {
	collector := NewCollector(10, false)
	for i := 0; i < 56; i++ {
		collector.Add(Event{Query: "SELECT 1", Duration: time.Duration(i+1) * time.Millisecond})
	}
	collector.Add(Event{Query: "SELECT 1", Duration: 156734 * time.Microsecond})
	summary := collector.Snapshot("max", 0).Queries[0]
	if summary.P95 > summary.Max || summary.P99 > summary.Max {
		t.Fatalf("quantiles exceed max: p95=%s p99=%s max=%s", summary.P95, summary.P99, summary.Max)
	}
}

func TestJSONDurationUsesReadableMilliseconds(t *testing.T) {
	if got := durationMilliseconds(11642982 * time.Nanosecond); got != 11.643 {
		t.Fatalf("milliseconds = %v", got)
	}
}

func TestCollectorTruncatesVeryLongFingerprints(t *testing.T) {
	collector := NewCollector(10, true)
	collector.Add(Event{Query: "SELECT '" + strings.Repeat("x", maxFingerprintInput*2) + "'", Duration: time.Millisecond})
	report := collector.Snapshot("max", 0)
	if len(report.Queries) != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Queries[0].Fingerprint) > maxFingerprintInput+100 || len(report.Queries[0].Example) > maxFingerprintInput+100 {
		t.Fatalf("long query was not bounded: fingerprint=%d example=%d", len(report.Queries[0].Fingerprint), len(report.Queries[0].Example))
	}
}

package pgsql

import (
	"bytes"
	"encoding/json"
	"slices"
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
	if len(report.Queries) != 1 || !strings.Contains(report.Queries[0].Query, "pg_sleep") || report.Queries[0].Fingerprint != "" {
		t.Fatalf("report = %+v", report)
	}
	if report.SchemaVersion != ReportSchemaVersion {
		t.Fatalf("schema version = %d", report.SchemaVersion)
	}

	var table bytes.Buffer
	if err := WriteTable(&table, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table.String(), "LATENCY_SAMPLES") || !strings.Contains(table.String(), "pg_sleep") {
		t.Fatalf("table = %q", table.String())
	}

	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, report); err != nil {
		t.Fatal(err)
	}
	if output := encoded.String(); !strings.Contains(output, `"schema_version": 3`) || !strings.Contains(output, `"query": "SELECT pg_sleep(1)"`) || strings.Contains(output, `"fingerprint"`) || !strings.Contains(output, `"calls"`) || !strings.Contains(output, `"latency_ms"`) || strings.Contains(output, `"average_ns"`) {
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
	if !strings.Contains(metrics.String(), "pgsniffer_query_calls_total") ||
		!strings.Contains(metrics.String(), "pgsniffer_query_duration_observations_total") ||
		!strings.Contains(metrics.String(), "pg_sleep") {
		t.Fatalf("metrics = %q", metrics.String())
	}
}

func TestCollectorReportsDimensionAvailability(t *testing.T) {
	collector := NewCollector(10, false)
	collector.Add(Event{Query: "SELECT 1", Duration: time.Millisecond, Metadata: Metadata{ClientAddress: "127.0.0.1"}})
	collector.Add(Event{Query: "SELECT 1", Duration: time.Millisecond, Metadata: Metadata{
		User: "alice", Database: "app", ClientAddress: "127.0.0.1", StartupObserved: true,
	}})

	report := collector.Snapshot("max", 0)
	if len(report.Queries) != 2 {
		t.Fatalf("queries = %+v", report.Queries)
	}
	var missing, complete *Summary
	for index := range report.Queries {
		if report.Queries[index].DimensionStatus.StartupObserved {
			complete = &report.Queries[index]
		} else {
			missing = &report.Queries[index]
		}
	}
	if missing == nil || !slices.Equal(missing.DimensionStatus.Missing, []string{"user", "database"}) {
		t.Fatalf("missing dimensions = %+v", missing)
	}
	if complete == nil || len(complete.DimensionStatus.Missing) != 0 || complete.Dimensions.User != "alice" || complete.Dimensions.Database != "app" {
		t.Fatalf("complete dimensions = %+v", complete)
	}
	data, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if output := string(data); !strings.Contains(output, `"user":""`) || !strings.Contains(output, `"database":""`) ||
		!strings.Contains(output, `"dimension_status":{"startup_observed":false,"missing":["user","database"]}`) {
		t.Fatalf("dimension JSON = %s", output)
	}
	completeData, err := json.Marshal(complete)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Summary
	if err := json.Unmarshal(completeData, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.DimensionStatus.StartupObserved || !decoded.Dimensions.StartupObserved {
		t.Fatalf("decoded dimensions = %+v", decoded)
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

func TestCollectorAggregatesLatencyPhases(t *testing.T) {
	collector := NewCollector(10, false)
	collector.Add(Event{
		Query: "SELECT 1", Duration: 10 * time.Millisecond,
		FirstResponse: 8 * time.Millisecond, ResponseTransfer: 2 * time.Millisecond, PhaseObserved: true,
	})
	collector.Add(Event{
		Query: "SELECT 1", Duration: 20 * time.Millisecond,
		FirstResponse: 15 * time.Millisecond, ResponseTransfer: 5 * time.Millisecond, PhaseObserved: true,
	})
	collector.Add(Event{Query: "SELECT 1", Duration: 30 * time.Millisecond, Incomplete: true, IncompleteReason: "tcp_gap"})

	summary := collector.Snapshot("max", 0).Queries[0]
	if summary.Count != 3 || summary.Incomplete != 1 || summary.LatencyObservations != 2 ||
		summary.Average != 15*time.Millisecond || summary.Total != 30*time.Millisecond || summary.Max != 20*time.Millisecond {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.IncompleteObservedDuration.Observations != 1 || summary.IncompleteObservedDuration.Average != 30*time.Millisecond ||
		summary.IncompleteObservedDuration.Max != 30*time.Millisecond || summary.IncompleteObservedDuration.Total != 30*time.Millisecond {
		t.Fatalf("incomplete duration = %+v", summary.IncompleteObservedDuration)
	}
	if summary.FirstResponse.Observations != 2 || summary.FirstResponse.Average != 11500*time.Microsecond ||
		summary.FirstResponse.Max != 15*time.Millisecond || summary.FirstResponse.Total != 23*time.Millisecond {
		t.Fatalf("first response = %+v", summary.FirstResponse)
	}
	if summary.ResponseTransfer.Observations != 2 || summary.ResponseTransfer.Average != 3500*time.Microsecond ||
		summary.ResponseTransfer.Max != 5*time.Millisecond || summary.ResponseTransfer.Total != 7*time.Millisecond {
		t.Fatalf("response transfer = %+v", summary.ResponseTransfer)
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"first_response":{"observations":2`) ||
		!strings.Contains(string(data), `"response_transfer":{"observations":2`) ||
		!strings.Contains(string(data), `"latency_ms":{"observations":2`) ||
		!strings.Contains(string(data), `"incomplete_observed_duration_ms":{"observations":1`) {
		t.Fatalf("phase JSON = %s", data)
	}
	var decoded Summary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.LatencyObservations != summary.LatencyObservations || decoded.FirstResponse != summary.FirstResponse ||
		decoded.ResponseTransfer != summary.ResponseTransfer || decoded.IncompleteObservedDuration != summary.IncompleteObservedDuration {
		t.Fatalf("decoded durations = %+v", decoded)
	}

	var metrics bytes.Buffer
	if err := WritePrometheus(&metrics, Report{Queries: []Summary{summary}}); err != nil {
		t.Fatal(err)
	}
	if output := metrics.String(); !strings.Contains(output, "pgsniffer_query_duration_observations_total{query=\"select ?\"") ||
		!strings.Contains(output, "} 2\n") || !strings.Contains(output, "pgsniffer_query_duration_seconds_total{query=\"select ?\"") ||
		!strings.Contains(output, "} 0.030000000\n") {
		t.Fatalf("completed-only latency metrics = %s", output)
	}
}

func TestSummaryUnmarshalAcceptsReportsWithoutLatencyPhases(t *testing.T) {
	var summary Summary
	if err := json.Unmarshal([]byte(`{"fingerprint":"select ?","calls":2,"incomplete":1,"latency_ms":{"average":1,"min":1,"p95":1,"p99":1,"max":1,"total":2}}`), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Average != time.Millisecond || summary.LatencyObservations != 2 ||
		summary.FirstResponse.Observations != 0 || summary.ResponseTransfer.Observations != 0 || summary.IncompleteObservedDuration.Observations != 0 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestIncompleteQueriesDoNotAffectLatencyOrSorting(t *testing.T) {
	collector := NewCollector(10, false)
	collector.Add(Event{Query: "SELECT fast", Duration: time.Millisecond})
	collector.Add(Event{Query: "SELECT incomplete", Duration: 10 * time.Second, Incomplete: true, IncompleteReason: "tcp_gap"})

	report := collector.Snapshot("max", 0)
	if len(report.Queries) != 2 || report.Queries[0].Fingerprint != "select fast" {
		t.Fatalf("queries sorted by completed latency = %+v", report.Queries)
	}
	incomplete := report.Queries[1]
	if incomplete.LatencyObservations != 0 || incomplete.Average != 0 || incomplete.Max != 0 || incomplete.Total != 0 {
		t.Fatalf("incomplete query polluted latency = %+v", incomplete)
	}
	if incomplete.IncompleteObservedDuration.Observations != 1 || incomplete.IncompleteObservedDuration.Max != 10*time.Second {
		t.Fatalf("incomplete duration = %+v", incomplete.IncompleteObservedDuration)
	}
}

func TestCollectorRawSQLUsesExactQueriesAndBoundsLength(t *testing.T) {
	collector := NewCollector(10, true)
	collector.Add(Event{Query: "SELECT 1", Duration: time.Millisecond})
	collector.Add(Event{Query: "SELECT 2", Duration: time.Millisecond})
	collector.Add(Event{Query: "SELECT '" + strings.Repeat("x", maxSQLInput*2) + "'", Duration: time.Millisecond})
	report := collector.Snapshot("max", 0)
	if len(report.Queries) != 3 {
		t.Fatalf("report = %+v", report)
	}
	for _, summary := range report.Queries {
		if summary.Fingerprint != "" || summary.Query == "" || len(summary.Query) > maxSQLInput+100 {
			t.Fatalf("raw SQL summary = %+v", summary)
		}
	}
}

func TestCollectorFingerprintModeOmitsRawSQL(t *testing.T) {
	collector := NewCollector(10, false)
	collector.Add(Event{Query: "SELECT * FROM users WHERE token = 'super-secret-1'", Duration: time.Millisecond})
	collector.Add(Event{Query: "SELECT * FROM users WHERE token = 'super-secret-2'", Duration: time.Millisecond})
	report := collector.Snapshot("max", 0)
	if len(report.Queries) != 1 || report.Queries[0].Fingerprint == "" || report.Queries[0].Query != "" || report.Queries[0].Count != 2 {
		t.Fatalf("report = %+v", report)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "super-secret") || strings.Contains(string(data), `"query"`) {
		t.Fatalf("raw SQL leaked in fingerprint mode: %s", data)
	}
}

func TestCollectorGroupsDimensionsAndReportsExecutionDetails(t *testing.T) {
	collector := NewCollector(10, false)
	collector.Add(Event{
		Query: "UPDATE jobs SET done = true", Duration: 2 * time.Millisecond,
		Metadata: Metadata{User: "worker", Database: "queue", ApplicationName: "scheduler", ClientAddress: "10.0.0.2"},
		Commands: []Command{{Tag: "UPDATE", RowsAffected: 4}}, TransactionStatus: "idle",
	})
	collector.Add(Event{
		Query: "UPDATE jobs SET done = true", Duration: 3 * time.Millisecond,
		Metadata:  Metadata{User: "admin", Database: "queue", ApplicationName: "console", ClientAddress: "10.0.0.3"},
		ErrorCode: "42501", ErrorInfo: "permission denied", Severity: "ERROR", TransactionStatus: "in_transaction",
	})
	collector.ObservePacket(100, 120, true)
	collector.SetKernelCaptureStatistics(10, 2, 1)
	collector.AddTCPGap(64)
	collector.AddMidstreamConnection()

	report := collector.Snapshot("count", 0)
	if len(report.Queries) != 2 {
		t.Fatalf("queries = %+v", report.Queries)
	}
	if report.Capture.PacketsSeen != 1 || report.Capture.PacketsMatched != 1 || report.Capture.TruncatedPackets != 1 ||
		report.Capture.KernelPacketsDropped != 2 || report.Capture.InterfacePacketsDropped != 1 ||
		report.Capture.TCPGapEvents != 1 || report.Capture.TCPBytesSkipped != 64 || report.Capture.MidstreamConnections != 1 {
		t.Fatalf("capture = %+v", report.Capture)
	}
	for _, summary := range report.Queries {
		switch summary.Dimensions.User {
		case "worker":
			if summary.RowsAffected != 4 || summary.CommandTags["UPDATE"] != 1 || summary.TransactionStatuses["idle"] != 1 {
				t.Fatalf("worker summary = %+v", summary)
			}
		case "admin":
			if summary.Errors != 1 || summary.SQLStates["42501"] != 1 || summary.Severities["ERROR"] != 1 || summary.TransactionStatuses["in_transaction"] != 1 {
				t.Fatalf("admin summary = %+v", summary)
			}
		default:
			t.Fatalf("unexpected dimensions: %+v", summary.Dimensions)
		}
	}
}

func TestCollectorReportsConnectionAndDataQualityDiagnostics(t *testing.T) {
	collector := NewCollector(10, false)
	collector.AddObservedConnection()
	collector.AddStartupObservedConnection()
	collector.AddMidstreamConnection()
	collector.AddProtocolStateLossConnection()
	collector.AddTCPGap(64)
	collector.AddTCPGap(maxReliableTCPGapBytes + 1)
	collector.Add(Event{
		Query: "SELECT 1", Duration: time.Millisecond,
		Metadata: Metadata{User: "alice", Database: "app", StartupObserved: true},
	})
	collector.Add(Event{
		Query: "SELECT 2", Duration: time.Millisecond, Incomplete: true,
		IncompleteReason: "command_tag_mismatch", ProtocolIssue: "execute_command_tag_mismatch",
		ExpectedCommand: "SELECT", ActualCommand: "UPDATE",
	})
	collector.Add(Event{ProtocolIssue: "execute_unknown_portal"})

	report := collector.Snapshot("max", 0)
	if report.DataQuality.CompletedQueries != 1 || report.DataQuality.ExcludedQueries != 1 ||
		report.DataQuality.ExcludedPercentage != 50 || report.DataQuality.MetadataMissingQueries != 1 {
		t.Fatalf("data quality = %+v", report.DataQuality)
	}
	if report.ProtocolIssues["execute_command_tag_mismatch_expected_SELECT_actual_UPDATE"] != 1 ||
		report.ProtocolIssues["execute_unknown_portal"] != 1 {
		t.Fatalf("protocol issues = %+v", report.ProtocolIssues)
	}
	if report.Capture.ConnectionsObserved != 1 || report.Capture.StartupObservedConnections != 1 ||
		report.Capture.MidstreamConnections != 1 || report.Capture.ProtocolStateLossConnections != 1 ||
		report.Capture.TCPGapEvents != 2 || report.Capture.TCPBytesSkipped != 64 ||
		report.Capture.TCPSequenceDiscontinuities != 1 || report.Capture.LargestTCPGapBytes != maxReliableTCPGapBytes+1 {
		t.Fatalf("capture diagnostics = %+v", report.Capture)
	}
}

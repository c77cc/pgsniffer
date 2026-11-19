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

const maxSQLInput = 64 << 10

// ReportSchemaVersion identifies the JSON report contract.
const ReportSchemaVersion = 2

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

type durationStats struct {
	count     uint64
	total     time.Duration
	min       time.Duration
	max       time.Duration
	histogram latencyHistogram
}

func (s *durationStats) add(duration time.Duration) {
	s.count++
	s.total += duration
	if s.count == 1 || duration < s.min {
		s.min = duration
	}
	if duration > s.max {
		s.max = duration
	}
	s.histogram.add(duration)
}

func (s durationStats) summary() LatencyPhase {
	if s.count == 0 {
		return LatencyPhase{}
	}
	return LatencyPhase{
		Observations: s.count, Average: s.total / time.Duration(s.count), Min: s.min,
		P95: min(s.histogram.quantile(.95, s.count), s.max),
		P99: min(s.histogram.quantile(.99, s.count), s.max),
		Max: s.max, Total: s.total,
	}
}

type queryStats struct {
	sql                 string
	dimensions          Metadata
	count               uint64
	errors              uint64
	incomplete          uint64
	rowsAffected        uint64
	latency             durationStats
	incompleteDuration  durationStats
	firstResponse       durationStats
	responseTransfer    durationStats
	commandTags         map[string]uint64
	sqlstates           map[string]uint64
	severities          map[string]uint64
	transactionStatuses map[string]uint64
	incompleteReasons   map[string]uint64
}

type queryKey struct {
	sql             string
	user            string
	database        string
	applicationName string
	clientAddress   string
	startupObserved bool
}

// Summary is an immutable statistics snapshot suitable for table or JSON output.
type Summary struct {
	Fingerprint                string
	Query                      string
	Dimensions                 Metadata
	Count                      uint64
	Errors                     uint64
	Incomplete                 uint64
	RowsAffected               uint64
	CommandTags                map[string]uint64
	SQLStates                  map[string]uint64
	Severities                 map[string]uint64
	TransactionStatuses        map[string]uint64
	IncompleteReasons          map[string]uint64
	Average                    time.Duration
	Min                        time.Duration
	Max                        time.Duration
	P95                        time.Duration
	P99                        time.Duration
	Total                      time.Duration
	LatencyObservations        uint64
	FirstResponse              LatencyPhase
	ResponseTransfer           LatencyPhase
	IncompleteObservedDuration LatencyPhase
	DimensionStatus            DimensionStatus
}

// DimensionStatus explains whether connection startup metadata was available.
type DimensionStatus struct {
	StartupObserved bool     `json:"startup_observed"`
	Missing         []string `json:"missing,omitempty"`
}

// LatencyPhase contains aggregate timings for a response phase or observed duration.
type LatencyPhase struct {
	Observations uint64
	Average      time.Duration
	Min          time.Duration
	P95          time.Duration
	P99          time.Duration
	Max          time.Duration
	Total        time.Duration
}

type latencyMilliseconds struct {
	Observations     uint64                   `json:"observations"`
	Average          float64                  `json:"average"`
	Min              float64                  `json:"min"`
	P95              float64                  `json:"p95"`
	P99              float64                  `json:"p99"`
	Max              float64                  `json:"max"`
	Total            float64                  `json:"total"`
	FirstResponse    phaseLatencyMilliseconds `json:"first_response"`
	ResponseTransfer phaseLatencyMilliseconds `json:"response_transfer"`
}

type phaseLatencyMilliseconds struct {
	Observations uint64  `json:"observations"`
	Average      float64 `json:"average"`
	Min          float64 `json:"min"`
	P95          float64 `json:"p95"`
	P99          float64 `json:"p99"`
	Max          float64 `json:"max"`
	Total        float64 `json:"total"`
}

type summaryJSON struct {
	Fingerprint                string                    `json:"fingerprint,omitempty"`
	Query                      string                    `json:"query,omitempty"`
	Dimensions                 Metadata                  `json:"dimensions,omitempty"`
	DimensionStatus            *DimensionStatus          `json:"dimension_status,omitempty"`
	Calls                      uint64                    `json:"calls"`
	Errors                     uint64                    `json:"errors"`
	Incomplete                 uint64                    `json:"incomplete"`
	RowsAffected               uint64                    `json:"rows_affected"`
	CommandTags                map[string]uint64         `json:"command_tags,omitempty"`
	SQLStates                  map[string]uint64         `json:"sqlstates,omitempty"`
	Severities                 map[string]uint64         `json:"error_severities,omitempty"`
	TransactionStatuses        map[string]uint64         `json:"transaction_status_before,omitempty"`
	IncompleteReasons          map[string]uint64         `json:"incomplete_reasons,omitempty"`
	Latency                    latencyMilliseconds       `json:"latency_ms"`
	IncompleteObservedDuration *phaseLatencyMilliseconds `json:"incomplete_observed_duration_ms,omitempty"`
}

func (s Summary) MarshalJSON() ([]byte, error) {
	return json.Marshal(summaryJSON{
		Fingerprint: s.Fingerprint, Query: s.Query, Dimensions: s.Dimensions, Calls: s.Count,
		Errors: s.Errors, Incomplete: s.Incomplete, RowsAffected: s.RowsAffected,
		CommandTags: s.CommandTags, SQLStates: s.SQLStates, Severities: s.Severities,
		TransactionStatuses: s.TransactionStatuses, IncompleteReasons: s.IncompleteReasons,
		Latency: latencyMilliseconds{
			Observations: s.LatencyObservations,
			Average:      durationMilliseconds(s.Average), Min: durationMilliseconds(s.Min),
			P95: durationMilliseconds(s.P95), P99: durationMilliseconds(s.P99),
			Max: durationMilliseconds(s.Max), Total: durationMilliseconds(s.Total),
			FirstResponse:    phaseMilliseconds(s.FirstResponse),
			ResponseTransfer: phaseMilliseconds(s.ResponseTransfer),
		},
		IncompleteObservedDuration: optionalPhaseMilliseconds(s.IncompleteObservedDuration),
		DimensionStatus:            &s.DimensionStatus,
	})
}

func optionalPhaseMilliseconds(phase LatencyPhase) *phaseLatencyMilliseconds {
	if phase.Observations == 0 {
		return nil
	}
	value := phaseMilliseconds(phase)
	return &value
}

func phaseMilliseconds(phase LatencyPhase) phaseLatencyMilliseconds {
	return phaseLatencyMilliseconds{
		Observations: phase.Observations, Average: durationMilliseconds(phase.Average),
		Min: durationMilliseconds(phase.Min), P95: durationMilliseconds(phase.P95),
		P99: durationMilliseconds(phase.P99), Max: durationMilliseconds(phase.Max),
		Total: durationMilliseconds(phase.Total),
	}
}

func (s *Summary) UnmarshalJSON(data []byte) error {
	var value summaryJSON
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	observations := value.Latency.Observations
	if observations == 0 && value.Calls > 0 {
		// Reports written before observations were added included every call in
		// latency_ms, including incomplete calls. Preserve that historical sample
		// count; the completed-only rule applies to newly collected reports.
		observations = value.Calls
	}
	*s = Summary{
		Fingerprint: value.Fingerprint, Query: value.Query, Dimensions: value.Dimensions, Count: value.Calls,
		Errors: value.Errors, Incomplete: value.Incomplete, RowsAffected: value.RowsAffected,
		CommandTags: value.CommandTags, SQLStates: value.SQLStates, Severities: value.Severities,
		TransactionStatuses: value.TransactionStatuses, IncompleteReasons: value.IncompleteReasons,
		Average: millisecondsDuration(value.Latency.Average), Min: millisecondsDuration(value.Latency.Min),
		P95: millisecondsDuration(value.Latency.P95), P99: millisecondsDuration(value.Latency.P99),
		Max: millisecondsDuration(value.Latency.Max), Total: millisecondsDuration(value.Latency.Total),
		LatencyObservations: observations,
		FirstResponse:       phaseDuration(value.Latency.FirstResponse),
		ResponseTransfer:    phaseDuration(value.Latency.ResponseTransfer),
	}
	if value.DimensionStatus != nil {
		s.DimensionStatus = *value.DimensionStatus
		s.Dimensions.StartupObserved = s.DimensionStatus.StartupObserved
	} else {
		s.DimensionStatus = dimensionStatus(s.Dimensions)
	}
	if value.IncompleteObservedDuration != nil {
		s.IncompleteObservedDuration = phaseDuration(*value.IncompleteObservedDuration)
	}
	return nil
}

func phaseDuration(phase phaseLatencyMilliseconds) LatencyPhase {
	return LatencyPhase{
		Observations: phase.Observations, Average: millisecondsDuration(phase.Average),
		Min: millisecondsDuration(phase.Min), P95: millisecondsDuration(phase.P95),
		P99: millisecondsDuration(phase.P99), Max: millisecondsDuration(phase.Max),
		Total: millisecondsDuration(phase.Total),
	}
}

func durationMilliseconds(duration time.Duration) float64 {
	milliseconds := float64(duration) / float64(time.Millisecond)
	return math.Round(milliseconds*1000) / 1000
}

func millisecondsDuration(milliseconds float64) time.Duration {
	return time.Duration(math.Round(milliseconds * float64(time.Millisecond)))
}

type Report struct {
	SchemaVersion     int               `json:"schema_version"`
	Build             *BuildInformation `json:"build,omitempty"`
	GeneratedAt       time.Time         `json:"generated_at"`
	Queries           []Summary         `json:"queries"`
	Capture           CaptureStatistics `json:"capture"`
	EncryptedSessions uint64            `json:"encrypted_sessions"`
	DecodeErrors      uint64            `json:"decode_errors"`
	DroppedKeys       uint64            `json:"dropped_query_keys"`
}

// BuildInformation identifies the executable that produced a report.
type BuildInformation struct {
	Version    string `json:"version"`
	Revision   string `json:"revision,omitempty"`
	CommitTime string `json:"commit_time,omitempty"`
}

// CaptureStatistics exposes whether packet loss or stream gaps can affect the
// completeness of a report.
type CaptureStatistics struct {
	PacketsSeen             uint64 `json:"packets_seen"`
	PacketsMatched          uint64 `json:"packets_matched"`
	BytesCaptured           uint64 `json:"bytes_captured"`
	TruncatedPackets        uint64 `json:"truncated_packets"`
	KernelPacketsReceived   uint64 `json:"kernel_packets_received"`
	KernelPacketsDropped    uint64 `json:"kernel_packets_dropped"`
	InterfacePacketsDropped uint64 `json:"interface_packets_dropped"`
	TCPGapEvents            uint64 `json:"tcp_gap_events"`
	TCPBytesSkipped         uint64 `json:"tcp_bytes_skipped"`
	MidstreamConnections    uint64 `json:"midstream_connections"`
	StatisticsErrors        uint64 `json:"statistics_errors"`
}

// Collector keeps bounded aggregate state. It never stores individual latency
// samples and caps the number of distinct SQL aggregation keys.
type Collector struct {
	mu sync.RWMutex

	queries    map[queryKey]*queryStats
	maxQueries int
	rawSQL     bool

	encryptedSessions uint64
	decodeErrors      uint64
	droppedKeys       uint64
	capture           CaptureStatistics
}

func NewCollector(maxQueries int, rawSQL bool) *Collector {
	if maxQueries <= 0 {
		maxQueries = 10000
	}
	return &Collector{
		queries: make(map[queryKey]*queryStats), maxQueries: maxQueries, rawSQL: rawSQL,
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
	if len(query) > maxSQLInput {
		query = query[:maxSQLInput]
		truncated = true
	}
	aggregationSQL := query
	if !c.rawSQL {
		aggregationSQL = Fingerprint(query)
	}
	if truncated {
		aggregationSQL += " …[truncated]"
	}
	if aggregationSQL == "" {
		return
	}
	dimensions := aggregateDimensions(event.Metadata)
	key := queryKey{
		sql: aggregationSQL, user: dimensions.User, database: dimensions.Database,
		applicationName: dimensions.ApplicationName, clientAddress: dimensions.ClientAddress,
		startupObserved: dimensions.StartupObserved,
	}
	stats, found := c.queries[key]
	if !found {
		if len(c.queries) >= c.maxQueries {
			c.droppedKeys++
			overflowKey := "[other fingerprints]"
			if c.rawSQL {
				overflowKey = "[other queries]"
			}
			key = queryKey{sql: overflowKey}
			stats = c.queries[key]
		}
		if stats == nil {
			stats = &queryStats{
				sql: key.sql, dimensions: dimensions,
				commandTags: make(map[string]uint64), sqlstates: make(map[string]uint64),
				severities: make(map[string]uint64), transactionStatuses: make(map[string]uint64),
				incompleteReasons: make(map[string]uint64),
			}
			c.queries[key] = stats
		}
	}

	stats.count++
	if event.Incomplete {
		stats.incomplete++
		stats.incompleteDuration.add(event.Duration)
	} else {
		stats.latency.add(event.Duration)
		if event.PhaseObserved {
			stats.firstResponse.add(event.FirstResponse)
			stats.responseTransfer.add(event.ResponseTransfer)
		}
	}
	if event.ErrorCode != "" || event.ErrorInfo != "" {
		stats.errors++
	}
	if event.ErrorCode != "" {
		stats.sqlstates[event.ErrorCode]++
	}
	if event.Severity != "" {
		stats.severities[event.Severity]++
	}
	if event.IncompleteReason != "" {
		stats.incompleteReasons[event.IncompleteReason]++
	}
	if event.TransactionStatus != "" {
		stats.transactionStatuses[event.TransactionStatus]++
	}
	for _, command := range event.Commands {
		if command.Tag != "" {
			stats.commandTags[command.Tag]++
		}
		stats.rowsAffected += command.RowsAffected
	}
}

func aggregateDimensions(metadata Metadata) Metadata {
	return Metadata{
		User: metadata.User, Database: metadata.Database, ApplicationName: metadata.ApplicationName,
		ClientAddress: metadata.ClientAddress, StartupObserved: metadata.StartupObserved,
	}
}

func dimensionStatus(metadata Metadata) DimensionStatus {
	status := DimensionStatus{StartupObserved: metadata.StartupObserved}
	if metadata.User == "" {
		status.Missing = append(status.Missing, "user")
	}
	if metadata.Database == "" {
		status.Missing = append(status.Missing, "database")
	}
	return status
}

func (c *Collector) AddDecodeError() {
	c.mu.Lock()
	c.decodeErrors++
	c.mu.Unlock()
}

func (c *Collector) ObservePacket(captureLength, originalLength int, matched bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capture.PacketsSeen++
	if captureLength > 0 {
		c.capture.BytesCaptured += uint64(captureLength)
	}
	if originalLength > captureLength {
		c.capture.TruncatedPackets++
	}
	if matched {
		c.capture.PacketsMatched++
	}
}

func (c *Collector) SetKernelCaptureStatistics(received, dropped, interfaceDropped uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capture.KernelPacketsReceived = received
	c.capture.KernelPacketsDropped = dropped
	c.capture.InterfacePacketsDropped = interfaceDropped
}

func (c *Collector) AddCaptureStatisticsError() {
	c.mu.Lock()
	c.capture.StatisticsErrors++
	c.mu.Unlock()
}

func (c *Collector) AddTCPGap(skipped int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capture.TCPGapEvents++
	if skipped > 0 {
		c.capture.TCPBytesSkipped += uint64(skipped)
	}
}

func (c *Collector) AddMidstreamConnection() {
	c.mu.Lock()
	c.capture.MidstreamConnections++
	c.mu.Unlock()
}

func (c *Collector) Snapshot(sortBy string, topN int) Report {
	c.mu.RLock()
	defer c.mu.RUnlock()

	report := Report{
		SchemaVersion: ReportSchemaVersion, GeneratedAt: time.Now(), EncryptedSessions: c.encryptedSessions,
		DecodeErrors: c.decodeErrors, DroppedKeys: c.droppedKeys, Capture: c.capture,
		Queries: make([]Summary, 0, len(c.queries)),
	}
	for _, stats := range c.queries {
		latency := stats.latency.summary()
		summary := Summary{Dimensions: stats.dimensions,
			Count: stats.count, Errors: stats.errors, Incomplete: stats.incomplete,
			RowsAffected: stats.rowsAffected, CommandTags: cloneCounts(stats.commandTags),
			SQLStates: cloneCounts(stats.sqlstates), Severities: cloneCounts(stats.severities),
			TransactionStatuses: cloneCounts(stats.transactionStatuses),
			IncompleteReasons:   cloneCounts(stats.incompleteReasons),
			Average:             latency.Average, Min: latency.Min, Max: latency.Max,
			P95: latency.P95, P99: latency.P99, Total: latency.Total,
			LatencyObservations: latency.Observations,
			FirstResponse:       stats.firstResponse.summary(), ResponseTransfer: stats.responseTransfer.summary(),
			IncompleteObservedDuration: stats.incompleteDuration.summary(),
			DimensionStatus:            dimensionStatus(stats.dimensions)}
		if c.rawSQL {
			summary.Query = stats.sql
		} else {
			summary.Fingerprint = stats.sql
		}
		report.Queries = append(report.Queries, summary)
	}
	sort.Slice(report.Queries, func(i, j int) bool {
		left, right := report.Queries[i], report.Queries[j]
		var leftValue, rightValue time.Duration
		switch sortBy {
		case "count":
			if left.Count != right.Count {
				return left.Count > right.Count
			}
		case "total":
			leftValue, rightValue = left.Total, right.Total
		case "p95":
			leftValue, rightValue = left.P95, right.P95
		default:
			leftValue, rightValue = left.Max, right.Max
		}
		if leftValue != rightValue {
			return leftValue > rightValue
		}
		if left.SQL() != right.SQL() {
			return left.SQL() < right.SQL()
		}
		return dimensionsKey(left.Dimensions) < dimensionsKey(right.Dimensions)
	})
	if topN > 0 && len(report.Queries) > topN {
		report.Queries = report.Queries[:topN]
	}
	return report
}

// SQL returns the raw query in raw SQL mode or the normalized fingerprint.
func (s Summary) SQL() string {
	if s.Query != "" {
		return s.Query
	}
	return s.Fingerprint
}

func dimensionsKey(metadata Metadata) string {
	startup := "0"
	if metadata.StartupObserved {
		startup = "1"
	}
	return strings.Join([]string{metadata.User, metadata.Database, metadata.ApplicationName, metadata.ClientAddress, startup}, "\x00")
}

func cloneCounts(source map[string]uint64) map[string]uint64 {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]uint64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func WriteTable(w io.Writer, report Report) error {
	if _, err := fmt.Fprintf(w, "queries=%d packets=%d matched=%d kernel_drops=%d interface_drops=%d tcp_gaps=%d truncated=%d encrypted_sessions=%d decode_errors=%d dropped_keys=%d\n",
		len(report.Queries), report.Capture.PacketsSeen, report.Capture.PacketsMatched,
		report.Capture.KernelPacketsDropped, report.Capture.InterfacePacketsDropped,
		report.Capture.TCPGapEvents, report.Capture.TruncatedPackets,
		report.EncryptedSessions, report.DecodeErrors, report.DroppedKeys); err != nil {
		return err
	}
	if len(report.Queries) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CALLS\tLATENCY_SAMPLES\tERRORS\tINCOMPLETE\tROWS\tAVG\tP95\tP99\tMAX\tCONTEXT\tSQL"); err != nil {
		return err
	}
	for _, summary := range report.Queries {
		query := strings.ReplaceAll(summary.SQL(), "\n", " ")
		context := fmt.Sprintf("%s/%s/%s@%s", summary.Dimensions.User, summary.Dimensions.Database,
			summary.Dimensions.ApplicationName, summary.Dimensions.ClientAddress)
		if _, err := fmt.Fprintf(tw, "%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			summary.Count, summary.LatencyObservations, summary.Errors, summary.Incomplete, summary.RowsAffected, formatDuration(summary.Average),
			formatDuration(summary.P95), formatDuration(summary.P99),
			formatDuration(summary.Max), context, query); err != nil {
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

// WriteJSONLine writes one compact report for append-only periodic reporting.
func WriteJSONLine(w io.Writer, report Report) error {
	return json.NewEncoder(w).Encode(report)
}

func WritePrometheus(w io.Writer, report Report) error {
	if _, err := fmt.Fprintln(w, "# HELP pgsniffer_query_calls_total Observed PostgreSQL query executions.\n# TYPE pgsniffer_query_calls_total counter\n# HELP pgsniffer_query_duration_observations_total Completed query executions included in latency metrics.\n# TYPE pgsniffer_query_duration_observations_total counter"); err != nil {
		return err
	}
	for _, summary := range report.Queries {
		label := prometheusLabel(summary.SQL())
		dimensions := fmt.Sprintf("query=\"%s\",user=\"%s\",database=\"%s\",application=\"%s\",client=\"%s\"",
			label, prometheusLabel(summary.Dimensions.User), prometheusLabel(summary.Dimensions.Database),
			prometheusLabel(summary.Dimensions.ApplicationName), prometheusLabel(summary.Dimensions.ClientAddress))
		if _, err := fmt.Fprintf(w, "pgsniffer_query_calls_total{%s} %d\n", dimensions, summary.Count); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_errors_total{%s} %d\n", dimensions, summary.Errors); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_observations_total{%s} %d\n", dimensions, summary.LatencyObservations); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_seconds_total{%s} %.9f\n", dimensions, summary.Total.Seconds()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_seconds{%s,quantile=\"0.95\"} %.9f\n", dimensions, summary.P95.Seconds()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_seconds{%s,quantile=\"0.99\"} %.9f\n", dimensions, summary.P99.Seconds()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "pgsniffer_query_duration_max_seconds{%s} %.9f\n", dimensions, summary.Max.Seconds()); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "pgsniffer_capture_packets_total %d\npgsniffer_capture_matched_packets_total %d\npgsniffer_capture_kernel_drops_total %d\npgsniffer_capture_interface_drops_total %d\npgsniffer_tcp_gap_events_total %d\npgsniffer_tcp_skipped_bytes_total %d\npgsniffer_encrypted_sessions_total %d\npgsniffer_decode_errors_total %d\npgsniffer_overflow_events_total %d\n",
		report.Capture.PacketsSeen, report.Capture.PacketsMatched, report.Capture.KernelPacketsDropped,
		report.Capture.InterfacePacketsDropped, report.Capture.TCPGapEvents, report.Capture.TCPBytesSkipped,
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

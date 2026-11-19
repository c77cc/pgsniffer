package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
)

func TestCaptureStatusMessages(t *testing.T) {
	var output bytes.Buffer
	writeCaptureStarted(&output, config{interfaceName: "eth0", server: "10.0.0.8:5432"})
	writeCaptureWarning(&output, 10*time.Second, false)
	writeCaptureWarning(&output, 10*time.Second, true)

	collector := pgsql.NewCollector(10, false)
	collector.ObservePacket(128, 128, true)
	collector.SetKernelCaptureStatistics(1, 2, 3)
	collector.Add(pgsql.Event{Query: "SELECT 1", Duration: time.Millisecond})
	collector.Add(pgsql.Event{Query: "SELECT 2", Duration: time.Millisecond, Incomplete: true, IncompleteReason: "connection_closed"})
	collector.Add(pgsql.Event{Encrypted: true})
	writeCaptureStopped(&output, collector)

	text := output.String()
	for _, expected := range []string{
		`capture started interface="eth0" server="10.0.0.8:5432" filter="host 10.0.0.8 and tcp port 5432"`,
		"press Ctrl+C to stop and print the report",
		"no matching PostgreSQL traffic detected after 10s",
		"traffic was detected, but no complete SQL was decoded after 10s",
		"capture stopped packets=1 matched=1 queries=2 incomplete=1 encrypted_sessions=1 capture_drops=5",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("status output does not contain %q:\n%s", expected, text)
		}
	}
}

func TestCaptureStatusForOfflineAnalysis(t *testing.T) {
	var output bytes.Buffer
	writeCaptureStarted(&output, config{readPCAP: "traffic.pcap", server: "10.0.0.8:5432"})
	if got := output.String(); !strings.Contains(got, `PCAP analysis started file="traffic.pcap" server="10.0.0.8:5432"`) || strings.Contains(got, "Ctrl+C") {
		t.Fatalf("offline status = %q", got)
	}
}

func TestObservabilityHandlers(t *testing.T) {
	collector := pgsql.NewCollector(10, false)
	collector.Add(pgsql.Event{Query: "SELECT 1", Duration: 2 * time.Millisecond})

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		contentType string
		contains    string
	}{
		{name: "health", handler: healthHandler, contentType: "text/plain", contains: "ok"},
		{name: "report", handler: reportHandler(collector, 10), contentType: "application/json", contains: `"fingerprint"`},
		{name: "metrics", handler: metricsHandler(collector), contentType: "text/plain", contains: "pgsniffer_query_calls_total"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			response := httptest.NewRecorder()
			methodGET(test.handler)(response, request)
			if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) || !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("response = code %d headers %v body %q", response.Code, response.Header(), response.Body.String())
			}
		})
	}

	request := httptest.NewRequest(http.MethodPost, "/", nil)
	response := httptest.NewRecorder()
	methodGET(healthHandler)(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", response.Code)
	}
}

func TestPeriodicJSONLReports(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "reports.jsonl")
	collector := pgsql.NewCollector(10, false)
	collector.Add(pgsql.Event{Query: "SELECT 1", Duration: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	services, err := startRuntimeServices(ctx, cancel, config{
		reportInterval: 10 * time.Millisecond,
		reportFile:     reportPath,
		topN:           10,
	}, collector)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if info, statErr := os.Stat(reportPath); statErr == nil && info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic report was not written")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := services.close(); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("missing JSONL report: %v", scanner.Err())
	}
	var report pgsql.Report
	if err := json.Unmarshal(scanner.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSONL report: %v", err)
	}
	if len(report.Queries) != 1 || report.Queries[0].Count != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestObservabilityHTTPServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	services, err := startRuntimeServices(ctx, cancel, config{listen: "127.0.0.1:0", topN: 10}, pgsql.NewCollector(10, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := services.close(); err != nil {
			t.Errorf("close services: %v", err)
		}
	})

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + services.listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}
}

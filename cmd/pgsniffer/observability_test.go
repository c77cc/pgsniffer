package main

import (
	"bufio"
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

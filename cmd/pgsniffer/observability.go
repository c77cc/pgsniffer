package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
)

const noTrafficWarningDelay = 10 * time.Second

type captureEventKind uint8

const (
	captureEventReady captureEventKind = iota
	captureEventTraffic
	captureEventSQL
	captureEventEncrypted
)

type runtimeServices struct {
	cancel   context.CancelFunc
	server   *http.Server
	listener net.Listener
	file     *os.File
	errors   chan error
	wg       sync.WaitGroup
}

func runCaptureWithServices(parent context.Context, cfg config, collector *pgsql.Collector) error {
	return runCaptureWithStatus(parent, cfg, collector, os.Stderr, noTrafficWarningDelay)
}

func runCaptureWithStatus(parent context.Context, cfg config, collector *pgsql.Collector, status io.Writer, warningDelay time.Duration) error {
	ctx, cancel := context.WithCancel(parent)
	services, err := startRuntimeServices(ctx, cancel, cfg, collector)
	if err != nil {
		cancel()
		return err
	}

	events := make(chan captureEventKind, 8)
	notify := func(kind captureEventKind) {
		select {
		case events <- kind:
		default:
		}
	}
	captureErrors := make(chan error, 1)
	go func() { captureErrors <- runCaptureObserved(ctx, cfg, collector, notify) }()

	var result error
	var warningTimer *time.Timer
	var warning <-chan time.Time
	ready, traffic, sql, encrypted := false, false, false, false
	handleEvent := func(kind captureEventKind) {
		switch kind {
		case captureEventReady:
			if ready {
				return
			}
			ready = true
			writeCaptureStarted(status, cfg)
			if cfg.readPCAP == "" && warningDelay > 0 {
				warningTimer = time.NewTimer(warningDelay)
				warning = warningTimer.C
			}
		case captureEventTraffic:
			if !traffic {
				traffic = true
				_, _ = fmt.Fprintln(status, "pgsniffer: PostgreSQL traffic detected")
			}
		case captureEventSQL:
			if !sql {
				sql = true
				_, _ = fmt.Fprintln(status, "pgsniffer: SQL capture is working")
				stopTimer(warningTimer)
				warning = nil
			}
		case captureEventEncrypted:
			if !encrypted {
				encrypted = true
				_, _ = fmt.Fprintln(status, "pgsniffer: encrypted PostgreSQL session detected; TLS/GSS SQL cannot be decoded")
				stopTimer(warningTimer)
				warning = nil
			}
		}
	}

captureLoop:
	for {
		select {
		case kind := <-events:
			handleEvent(kind)
		case <-warning:
		drainWarningEvents:
			for {
				select {
				case kind := <-events:
					handleEvent(kind)
				default:
					break drainWarningEvents
				}
			}
			if !sql && !encrypted {
				writeCaptureWarning(status, warningDelay, traffic)
			}
			warning = nil
		case result = <-captureErrors:
			select {
			case serviceErr := <-services.errors:
				result = serviceErr
			default:
			}
			break captureLoop
		case result = <-services.errors:
			cancel()
			captureErr := <-captureErrors
			if result == nil {
				result = captureErr
			}
			break captureLoop
		case <-parent.Done():
			cancel()
			result = <-captureErrors
			break captureLoop
		}
	}
	stopTimer(warningTimer)
	for {
		select {
		case kind := <-events:
			handleEvent(kind)
		default:
			goto eventsDrained
		}
	}

eventsDrained:
	cancel()
	if closeErr := services.close(); result == nil {
		result = closeErr
	}
	if ready {
		writeCaptureStopped(status, collector)
	}
	return result
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func writeCaptureStarted(w io.Writer, cfg config) {
	if cfg.readPCAP != "" {
		_, _ = fmt.Fprintf(w, "pgsniffer: PCAP analysis started file=%q server=%q\n", cfg.readPCAP, cfg.server)
		return
	}
	server, _ := parseServerEndpoint(cfg.server)
	_, _ = fmt.Fprintf(w, "pgsniffer: capture started interface=%q server=%q filter=%q\n", cfg.interfaceName, cfg.server, serverBPFFilter(server))
	_, _ = fmt.Fprintln(w, "pgsniffer: waiting for PostgreSQL traffic; press Ctrl+C to stop and print the report")
}

func writeCaptureWarning(w io.Writer, delay time.Duration, traffic bool) {
	if traffic {
		_, _ = fmt.Fprintf(w, "pgsniffer: PostgreSQL traffic was detected, but no complete SQL was decoded after %s\n", delay)
		_, _ = fmt.Fprintln(w, "pgsniffer: capture may have started mid-connection; wait for a new query or connection")
		return
	}
	_, _ = fmt.Fprintf(w, "pgsniffer: no matching PostgreSQL traffic detected after %s\n", delay)
	_, _ = fmt.Fprintln(w, "pgsniffer: check --interface, --server, active connections, and VM/container network routing")
}

func writeCaptureStopped(w io.Writer, collector *pgsql.Collector) {
	report := collector.Snapshot("max", 0)
	var calls, incomplete uint64
	for _, query := range report.Queries {
		calls += query.Count
		incomplete += query.Incomplete
	}
	drops := report.Capture.KernelPacketsDropped + report.Capture.InterfacePacketsDropped
	_, _ = fmt.Fprintf(w, "pgsniffer: capture stopped packets=%d matched=%d queries=%d incomplete=%d encrypted_sessions=%d capture_drops=%d\n",
		report.Capture.PacketsSeen, report.Capture.PacketsMatched, calls, incomplete, report.EncryptedSessions, drops)
}

func startRuntimeServices(ctx context.Context, cancel context.CancelFunc, cfg config, collector *pgsql.Collector) (*runtimeServices, error) {
	services := &runtimeServices{cancel: cancel, errors: make(chan error, 1)}
	if cfg.listen != "" {
		listener, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			return nil, fmt.Errorf("listen on %q: %w", cfg.listen, err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", methodGET(healthHandler))
		mux.HandleFunc("/report", methodGET(reportHandler(collector, cfg.topN)))
		mux.HandleFunc("/metrics", methodGET(metricsHandler(collector)))
		services.server = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		services.listener = listener
		services.wg.Add(1)
		go func() {
			defer services.wg.Done()
			if err := services.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				services.fail(fmt.Errorf("serve observability HTTP: %w", err))
			}
		}()
	}

	if cfg.reportInterval > 0 {
		file, err := os.OpenFile(cfg.reportFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			services.close()
			return nil, fmt.Errorf("open report file %q: %w", cfg.reportFile, err)
		}
		services.file = file
		services.wg.Add(1)
		go func() {
			defer services.wg.Done()
			ticker := time.NewTicker(cfg.reportInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := pgsql.WriteJSONLine(file, snapshotReport(collector, cfg.topN)); err != nil {
						services.fail(fmt.Errorf("write periodic report: %w", err))
						return
					}
				}
			}
		}()
	}
	return services, nil
}

func (s *runtimeServices) fail(err error) {
	select {
	case s.errors <- err:
	default:
	}
	s.cancel()
}

func (s *runtimeServices) close() error {
	s.cancel()
	var result error
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result = s.server.Shutdown(ctx)
		cancel()
	}
	s.wg.Wait()
	if s.file != nil {
		if err := s.file.Close(); result == nil {
			result = err
		}
	}
	return result
}

func methodGET(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func reportHandler(collector *pgsql.Collector, topN int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := pgsql.WriteJSON(w, snapshotReport(collector, topN)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func metricsHandler(collector *pgsql.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := pgsql.WritePrometheus(w, collector.Snapshot("max", 0)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

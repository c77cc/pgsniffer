package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
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
	ctx, cancel := context.WithCancel(parent)
	services, err := startRuntimeServices(ctx, cancel, cfg, collector)
	if err != nil {
		cancel()
		return err
	}

	captureErrors := make(chan error, 1)
	go func() { captureErrors <- runCapture(ctx, cfg, collector) }()

	var result error
	select {
	case result = <-captureErrors:
		select {
		case serviceErr := <-services.errors:
			result = serviceErr
		default:
		}
	case result = <-services.errors:
		cancel()
		captureErr := <-captureErrors
		if result == nil {
			result = captureErr
		}
	case <-parent.Done():
		cancel()
		result = <-captureErrors
	}

	cancel()
	if closeErr := services.close(); result == nil {
		result = closeErr
	}
	return result
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
					if err := pgsql.WriteJSONLine(file, collector.Snapshot("max", cfg.topN)); err != nil {
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
		if err := pgsql.WriteJSON(w, collector.Snapshot("max", topN)); err != nil {
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

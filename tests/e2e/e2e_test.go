//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
)

const commandTimeout = 45 * time.Second

type harness struct {
	t         *testing.T
	repo      string
	artifacts string
	binary    string
	tcpdump   string
	image     string
	iface     string
	prefix    string
	retain    bool
	resources []dockerResource
}

type dockerResource struct {
	kind string
	name string
}

type report struct {
	GeneratedAt       time.Time `json:"generated_at"`
	Queries           []summary `json:"queries"`
	EncryptedSessions uint64    `json:"encrypted_sessions"`
	DecodeErrors      uint64    `json:"decode_errors"`
	DroppedKeys       uint64    `json:"dropped_query_keys"`
}

type summary struct {
	Fingerprint string      `json:"fingerprint"`
	Count       uint64      `json:"calls"`
	Errors      uint64      `json:"errors"`
	Incomplete  uint64      `json:"incomplete"`
	Latency     latencyJSON `json:"latency_ms"`
}

type latencyJSON struct {
	Average float64 `json:"average"`
	Min     float64 `json:"min"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
	Max     float64 `json:"max"`
	Total   float64 `json:"total"`
}

type capture struct {
	cmd          *exec.Cmd
	cmdDone      chan error
	stdout       bytes.Buffer
	stderr       bytes.Buffer
	packetCmd    *exec.Cmd
	packetDone   chan error
	packetStdout bytes.Buffer
	packetStderr bytes.Buffer
	reportPath   string
	pcapPath     string
}

func TestDockerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Docker end-to-end test is disabled by -short")
	}
	h := newHarness(t)
	defer h.cleanup()
	h.requireDocker()
	h.build()

	t.Run("plain_extended_concurrent_and_replay", h.testPlainAndReplay)
	t.Run("tls_detection_and_replay", h.testTLS)
	t.Run("server_interruption", h.testInterruption)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("PGSNIFFER_E2E_ARTIFACTS")
	retain := base != ""
	if base == "" {
		base = os.TempDir()
	} else if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("create artifact directory: %v", err)
	}
	runDir, err := os.MkdirTemp(base, "run-")
	if err != nil {
		t.Fatal(err)
	}
	iface := os.Getenv("PGSNIFFER_E2E_INTERFACE")
	if iface == "" {
		iface = "lo"
		if runtime.GOOS == "darwin" {
			iface = "lo0"
		}
	}
	image := os.Getenv("PGSNIFFER_POSTGRES_IMAGE")
	if image == "" {
		image = "postgres:16-alpine"
	}
	return &harness{
		t: t, repo: repo, artifacts: runDir, image: image, iface: iface,
		binary: filepath.Join(runDir, "pgsniffer"),
		prefix: fmt.Sprintf("pgsniffer-e2e-%d-%d", os.Getpid(), time.Now().UnixNano()),
		retain: retain,
	}
}

func (h *harness) requireDocker() {
	h.t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		h.dockerUnavailable("docker is not installed")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		h.dockerUnavailable(fmt.Sprintf("docker daemon is unavailable: %v: %s", err, output))
	}
}

func (h *harness) dockerUnavailable(message string) {
	h.t.Helper()
	if os.Getenv("PGSNIFFER_E2E_REQUIRED") == "1" {
		h.t.Fatal(message)
	}
	h.t.Skip(message)
}

func (h *harness) build() {
	h.t.Helper()
	h.run(h.repo, "go", "build", "-trimpath", "-o", h.binary, "./cmd/pgsniffer")
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		h.t.Fatalf("tcpdump is required for E2E PCAP replay: %v", err)
	}
	h.tcpdump = tcpdump
	if os.Getenv("PGSNIFFER_E2E_SETCAP") == "1" {
		h.run(h.repo, "sudo", "-n", "setcap", "cap_net_raw,cap_net_admin=eip", h.binary)
		h.run(h.repo, "sudo", "-n", "setcap", "cap_net_raw,cap_net_admin=eip", h.tcpdump)
	}
	list := h.runOutput(h.repo, h.binary, "-l")
	if !strings.Contains(list, h.iface) {
		h.t.Fatalf("capture interface %q not found in:\n%s", h.iface, list)
	}
}

func (h *harness) testPlainAndReplay(t *testing.T) {
	container, port := h.startPostgres(t, false)
	cap := h.startCapture(t, "plain", port)

	client := dialPostgres(t, port, false)
	client.simple(t, "SELECT 42")
	client.simple(t, "SELECT pg_sleep(0.03)")
	client.simpleError(t, "SELECT 1 / 0", "22012")
	client.simple(t, "BEGIN; UPDATE e2e_account SET balance = balance + 1 WHERE id = 1; COMMIT")
	client.simple(t, "COPY (SELECT generate_series(1, 3)) TO STDOUT")
	if err := client.sendMessage('Q', cstring("SELECT pg_sleep(10)")); err != nil {
		t.Fatal(err)
	}
	cancelResult := make(chan error, 1)
	go func() { cancelResult <- client.readUntilReady("57014") }()
	time.Sleep(200 * time.Millisecond)
	client.cancel(t, port)
	if err := <-cancelResult; err != nil {
		t.Fatalf("cancel query: %v", err)
	}
	client.close()

	client = dialPostgres(t, port, false)
	for i := 0; i < 8; i++ {
		client.extended(t, fmt.Sprintf("add_one_%d", i), fmt.Sprintf("add_portal_%d", i), "SELECT $1::int + 1", []string{strconv.Itoa(i)})
	}
	client.extendedError(t, "bad_math", "bad_math_portal", "SELECT $1::int / 0", []string{"1"}, "22012")
	client.pipeline(t, []string{"SELECT lower('PIPELINE')", "SELECT upper('pipeline')"})
	client.close()

	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := connectPostgres(port, false)
			if err != nil {
				errCh <- err
				return
			}
			defer c.close()
			for i := 0; i < 5; i++ {
				if err := c.extendedQuery(fmt.Sprintf("db_name_%d", i), fmt.Sprintf("db_portal_%d", i), "SELECT current_database()", nil, ""); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent workload: %v", err)
	}

	live := h.stopCapture(t, cap)
	h.assertHealthy(t, live)
	want := map[string]struct {
		count  uint64
		errors uint64
	}{
		pgsql.Fingerprint("SELECT 42"):             {1, 0},
		pgsql.Fingerprint("SELECT pg_sleep(0.03)"): {2, 1},
		pgsql.Fingerprint("SELECT 1 / 0"):          {1, 1},
		pgsql.Fingerprint("BEGIN; UPDATE e2e_account SET balance = balance + 1 WHERE id = 1; COMMIT"): {1, 0},
		pgsql.Fingerprint("COPY (SELECT generate_series(1, 3)) TO STDOUT"):                            {1, 0},
		pgsql.Fingerprint("SELECT $1::int + 1"):                                                       {8, 0},
		pgsql.Fingerprint("SELECT $1::int / 0"):                                                       {1, 1},
		pgsql.Fingerprint("SELECT current_database()"):                                                {20, 0},
		pgsql.Fingerprint("SELECT lower('PIPELINE')"):                                                 {1, 0},
		pgsql.Fingerprint("SELECT upper('pipeline')"):                                                 {1, 0},
	}
	h.assertQueries(t, live, want)

	offline := h.replay(t, cap.pcapPath, port, "plain-replay.json")
	h.assertReportsEqual(t, live, offline)
	h.docker(t, "stop", "--time", "2", container)
}

func (h *harness) testTLS(t *testing.T) {
	container, port := h.startPostgres(t, true)
	cap := h.startCapture(t, "tls", port)
	for i := 0; i < 3; i++ {
		client := dialPostgres(t, port, true)
		client.simple(t, "SELECT 1")
		client.close()
	}
	live := h.stopCapture(t, cap)
	if live.EncryptedSessions != 3 || len(live.Queries) != 0 || live.DecodeErrors != 0 {
		t.Fatalf("unexpected TLS report: %+v", live)
	}
	offline := h.replay(t, cap.pcapPath, port, "tls-replay.json")
	h.assertReportsEqual(t, live, offline)
	h.docker(t, "stop", "--time", "2", container)
}

func (h *harness) testInterruption(t *testing.T) {
	container, port := h.startPostgres(t, false)
	cap := h.startCapture(t, "interrupted", port)
	client := dialPostgres(t, port, false)
	if err := client.sendMessage('Q', cstring("SELECT pg_sleep(10)")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	h.docker(t, "kill", container)
	client.close()
	live := h.stopCapture(t, cap)
	h.assertHealthy(t, live)
	fingerprint := pgsql.Fingerprint("SELECT pg_sleep(10)")
	if len(live.Queries) != 1 || live.Queries[0].Fingerprint != fingerprint || live.Queries[0].Incomplete != 1 {
		t.Fatalf("unexpected interrupted report: %+v", live)
	}
	if live.Queries[0].Latency.Max < 200 {
		t.Fatalf("interrupted duration is too short: %.3fms", live.Queries[0].Latency.Max)
	}
	offline := h.replay(t, cap.pcapPath, port, "interrupted-replay.json")
	h.assertReportsEqual(t, live, offline)
}

func (h *harness) startPostgres(t *testing.T, tlsEnabled bool) (string, int) {
	t.Helper()
	name := h.prefix + "-" + strings.ReplaceAll(t.Name(), "/", "-")
	args := []string{"run", "-d", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-P"}
	if tlsEnabled {
		volume := name + "-certs"
		h.docker(t, "volume", "create", volume)
		h.resources = append(h.resources, dockerResource{kind: "volume", name: volume})
		h.docker(t, "run", "--rm", "--entrypoint", "sh", "-v", volume+":/certs", h.image, "-ceu",
			"openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -keyout /certs/server.key -out /certs/server.crt >/dev/null 2>&1; chown postgres:postgres /certs/server.key /certs/server.crt; chmod 600 /certs/server.key")
		args = append(args, "-v", volume+":/certs:ro")
	}
	args = append(args, h.image, "postgres")
	if tlsEnabled {
		args = append(args, "-c", "ssl=on", "-c", "ssl_cert_file=/certs/server.crt", "-c", "ssl_key_file=/certs/server.key")
	} else {
		args = append(args, "-c", "ssl=off")
	}
	h.docker(t, args...)
	h.resources = append(h.resources, dockerResource{kind: "container", name: name})
	port := h.publishedPort(t, name)
	h.waitForPostgres(t, port, tlsEnabled, name)
	client := dialPostgres(t, port, tlsEnabled)
	client.simple(t, "CREATE TABLE IF NOT EXISTS e2e_account (id integer PRIMARY KEY, balance integer NOT NULL)")
	client.simple(t, "INSERT INTO e2e_account VALUES (1, 100) ON CONFLICT (id) DO UPDATE SET balance = EXCLUDED.balance")
	client.close()
	return name, port
}

func (h *harness) publishedPort(t *testing.T, container string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output, err := h.dockerOutput(t, "port", container, "5432/tcp")
		if err == nil {
			line := strings.Split(strings.TrimSpace(output), "\n")[0]
			if _, portText, splitErr := net.SplitHostPort(line); splitErr == nil {
				port, parseErr := strconv.Atoi(portText)
				if parseErr == nil {
					return port
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("PostgreSQL port was not published for %s", container)
	return 0
}

func (h *harness) waitForPostgres(t *testing.T, port int, tlsEnabled bool, container string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := connectPostgres(port, tlsEnabled)
		if err == nil {
			client.close()
			return
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	logs, _ := h.dockerOutput(t, "logs", container)
	t.Fatalf("PostgreSQL did not become ready: %v\n%s", lastErr, logs)
}

func (h *harness) startCapture(t *testing.T, label string, port int) *capture {
	t.Helper()
	cap := &capture{
		reportPath: filepath.Join(h.artifacts, label+"-live.json"),
		pcapPath:   filepath.Join(h.artifacts, label+".pcap"),
	}
	packetArgs := []string{h.tcpdump, "-i", h.iface, "-U", "-s", "0", "-w", cap.pcapPath, fmt.Sprintf("tcp port %d", port)}
	if os.Getenv("PGSNIFFER_E2E_SUDO") == "1" {
		packetArgs = append([]string{"sudo", "-n"}, packetArgs...)
	}
	cap.packetCmd = exec.Command(packetArgs[0], packetArgs[1:]...)
	cap.packetCmd.Dir = h.repo
	cap.packetCmd.Stdout = &cap.packetStdout
	cap.packetCmd.Stderr = &cap.packetStderr
	if err := cap.packetCmd.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}
	cap.packetDone = make(chan error, 1)
	go func() { cap.packetDone <- cap.packetCmd.Wait() }()
	waitForPCAPHeader(t, cap)

	args := []string{h.binary, "-i", h.iface, "--server", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "-n", "0"}
	if os.Getenv("PGSNIFFER_E2E_SUDO") == "1" {
		args = append([]string{"sudo", "-n"}, args...)
	}
	cap.cmd = exec.Command(args[0], args[1:]...)
	cap.cmd.Dir = h.repo
	cap.cmd.Stdout = &cap.stdout
	cap.cmd.Stderr = &cap.stderr
	if err := cap.cmd.Start(); err != nil {
		stopProcess(cap.packetCmd, cap.packetDone)
		t.Fatalf("start pgsniffer: %v", err)
	}
	cap.cmdDone = make(chan error, 1)
	go func() { cap.cmdDone <- cap.cmd.Wait() }()
	select {
	case err := <-cap.cmdDone:
		stopProcess(cap.packetCmd, cap.packetDone)
		t.Fatalf("pgsniffer exited during startup: %v; stderr=%s", err, cap.stderr.String())
	case <-time.After(150 * time.Millisecond):
		return cap
	}
	return cap
}

func waitForPCAPHeader(t *testing.T, cap *capture) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case err := <-cap.packetDone:
			t.Fatalf("tcpdump exited during startup: %v; stderr=%s", err, cap.packetStderr.String())
		case <-ticker.C:
			if info, err := os.Stat(cap.pcapPath); err == nil && info.Size() >= 24 {
				select {
				case err := <-cap.packetDone:
					t.Fatalf("tcpdump exited during startup: %v; stderr=%s", err, cap.packetStderr.String())
				case <-time.After(750 * time.Millisecond):
					return
				}
			}
		case <-deadline.C:
			stopProcess(cap.packetCmd, cap.packetDone)
			t.Fatalf("tcpdump did not create a PCAP header; stderr=%s", cap.packetStderr.String())
		}
	}
}

func (h *harness) stopCapture(t *testing.T, cap *capture) report {
	t.Helper()
	// BSD BPF and tcpdump may buffer a partially filled block for about one
	// second. Let tcpdump drain it before sending SIGINT, otherwise the live
	// decoder can see packets that are still absent from the replay PCAP.
	time.Sleep(2 * time.Second)
	if err := cap.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("stop capture: %v", err)
	}
	select {
	case err := <-cap.cmdDone:
		if err != nil {
			t.Fatalf("capture exited unsuccessfully: %v\nstdout=%s\nstderr=%s", err, cap.stdout.String(), cap.stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cap.cmd.Process.Kill()
		t.Fatal("capture did not stop within 10 seconds")
	}
	stopProcess(cap.packetCmd, cap.packetDone)
	logPath := cap.pcapPath + ".tcpdump.log"
	if err := os.WriteFile(logPath, cap.packetStderr.Bytes(), 0o600); err != nil {
		t.Fatalf("retain tcpdump log: %v", err)
	}
	if info, err := os.Stat(cap.pcapPath); err != nil || info.Size() <= 24 {
		t.Fatalf("tcpdump captured no packets: stat=%v err=%v; log=%s", info, err, cap.packetStderr.String())
	}
	if err := os.WriteFile(cap.reportPath, cap.stdout.Bytes(), 0o600); err != nil {
		t.Fatalf("retain live report: %v", err)
	}
	return decodeReport(t, cap.stdout.Bytes(), cap.reportPath)
}

func (h *harness) replay(t *testing.T, pcapPath string, port int, name string) report {
	t.Helper()
	path := filepath.Join(h.artifacts, name)
	data := []byte(h.runOutput(h.repo, h.binary, "--read-pcap", pcapPath,
		"--server", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "-n", "0"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("retain replay report: %v", err)
	}
	return decodeReport(t, data, path)
}

func stopProcess(cmd *exec.Cmd, done <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func (h *harness) assertHealthy(t *testing.T, got report) {
	t.Helper()
	if got.DecodeErrors != 0 || got.DroppedKeys != 0 || got.EncryptedSessions != 0 {
		t.Fatalf("unhealthy report: %+v", got)
	}
}

func (h *harness) assertQueries(t *testing.T, got report, want map[string]struct{ count, errors uint64 }) {
	t.Helper()
	if len(got.Queries) != len(want) {
		t.Fatalf("query group count=%d, want %d: %+v", len(got.Queries), len(want), got.Queries)
	}
	for _, query := range got.Queries {
		expected, ok := want[query.Fingerprint]
		if !ok {
			t.Errorf("unexpected fingerprint %q", query.Fingerprint)
			continue
		}
		if query.Count != expected.count || query.Errors != expected.errors || query.Incomplete != 0 {
			t.Errorf("summary for %q = %+v, want count=%d errors=%d incomplete=0", query.Fingerprint, query, expected.count, expected.errors)
		}
		if query.Latency.Min < 0 || query.Latency.Max < query.Latency.Min || query.Latency.Total < query.Latency.Max {
			t.Errorf("invalid duration aggregate for %q: %+v", query.Fingerprint, query)
		}
	}
}

func (h *harness) assertReportsEqual(t *testing.T, live, offline report) {
	t.Helper()
	live.GeneratedAt = time.Time{}
	offline.GeneratedAt = time.Time{}
	sort.Slice(live.Queries, func(i, j int) bool { return live.Queries[i].Fingerprint < live.Queries[j].Fingerprint })
	sort.Slice(offline.Queries, func(i, j int) bool { return offline.Queries[i].Fingerprint < offline.Queries[j].Fingerprint })
	liveTimes := stripReportLatencies(&live)
	offlineTimes := stripReportLatencies(&offline)
	if !reflect.DeepEqual(live, offline) {
		t.Fatalf("live/offline reports differ\nlive:    %+v\noffline: %+v", live, offline)
	}
	for i := range liveTimes {
		for field := range liveTimes[i] {
			if delta := absFloat(liveTimes[i][field] - offlineTimes[i][field]); delta > 2 {
				t.Fatalf("live/offline duration differs for %q field %d by %.3fms", live.Queries[i].Fingerprint, field, delta)
			}
		}
	}
}

func stripReportLatencies(value *report) [][6]float64 {
	result := make([][6]float64, len(value.Queries))
	for i := range value.Queries {
		query := &value.Queries[i]
		result[i] = [6]float64{query.Latency.Average, query.Latency.Min, query.Latency.Max, query.Latency.P95, query.Latency.P99, query.Latency.Total}
		query.Latency = latencyJSON{}
	}
	return result
}

func absFloat(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

func decodeReport(t *testing.T, data []byte, source string) report {
	t.Helper()
	var result report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode report %s: %v\n%s", source, err, data)
	}
	return result
}

func (h *harness) cleanup() {
	for i := len(h.resources) - 1; i >= 0; i-- {
		resource := h.resources[i]
		args := []string{resource.kind, "rm", "-f", resource.name}
		if resource.kind == "volume" {
			args = []string{"volume", "rm", "-f", resource.name}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = exec.CommandContext(ctx, "docker", args...).Run()
		cancel()
	}
	if h.t.Failed() || h.retain {
		h.t.Logf("E2E artifacts retained at %s", h.artifacts)
	} else if err := os.RemoveAll(h.artifacts); err != nil {
		h.t.Logf("remove successful E2E artifacts: %v", err)
	}
}

func (h *harness) docker(t *testing.T, args ...string) { t.Helper(); h.run(h.repo, "docker", args...) }

func (h *harness) dockerOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(output), err
}

func (h *harness) run(dir, name string, args ...string) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
}

func (h *harness) runOutput(dir, name string, args ...string) string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

type pgClient struct {
	conn      net.Conn
	read      *bufio.Reader
	backendID int32
	secretKey int32
}

func dialPostgres(t *testing.T, port int, useTLS bool) *pgClient {
	t.Helper()
	client, err := connectPostgres(port, useTLS)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	return client
}

func connectPostgres(port int, useTLS bool) (*pgClient, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return nil, err
	}
	if useTLS {
		request := make([]byte, 8)
		binary.BigEndian.PutUint32(request, 8)
		binary.BigEndian.PutUint32(request[4:], 80877103)
		if _, err := conn.Write(request); err != nil {
			conn.Close()
			return nil, err
		}
		response := []byte{0}
		if _, err := io.ReadFull(conn, response); err != nil || response[0] != 'S' {
			conn.Close()
			return nil, fmt.Errorf("server rejected TLS: response=%q err=%v", response, err)
		}
		conn = tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost", InsecureSkipVerify: true}) // local ephemeral test certificate
	}
	client := &pgClient{conn: conn, read: bufio.NewReader(conn)}
	startupPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(startupPayload, 196608)
	startupPayload = append(startupPayload, cstring("user")...)
	startupPayload = append(startupPayload, cstring("postgres")...)
	startupPayload = append(startupPayload, cstring("database")...)
	startupPayload = append(startupPayload, cstring("postgres")...)
	startupPayload = append(startupPayload, cstring("application_name")...)
	startupPayload = append(startupPayload, cstring("pgsniffer-e2e")...)
	startupPayload = append(startupPayload, 0)
	packet := make([]byte, 4)
	binary.BigEndian.PutUint32(packet, uint32(len(startupPayload)+4))
	packet = append(packet, startupPayload...)
	if _, err := conn.Write(packet); err != nil {
		conn.Close()
		return nil, err
	}
	if err := client.readUntilReady(""); err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

func (c *pgClient) close() { _ = c.conn.Close() }

func (c *pgClient) cancel(t *testing.T, port int) {
	t.Helper()
	if c.backendID == 0 || c.secretKey == 0 {
		t.Fatal("server did not provide a BackendKeyData message")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("open cancel connection: %v", err)
	}
	defer conn.Close()
	packet := make([]byte, 16)
	binary.BigEndian.PutUint32(packet, 16)
	binary.BigEndian.PutUint32(packet[4:], 80877102)
	binary.BigEndian.PutUint32(packet[8:], uint32(c.backendID))
	binary.BigEndian.PutUint32(packet[12:], uint32(c.secretKey))
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("send CancelRequest: %v", err)
	}
}

func (c *pgClient) simple(t *testing.T, query string) {
	t.Helper()
	if err := c.simpleQuery(query, ""); err != nil {
		t.Fatalf("simple query %q: %v", query, err)
	}
}

func (c *pgClient) simpleError(t *testing.T, query, code string) {
	t.Helper()
	if err := c.simpleQuery(query, code); err != nil {
		t.Fatalf("simple error query %q: %v", query, err)
	}
}

func (c *pgClient) simpleQuery(query, wantCode string) error {
	if err := c.sendMessage('Q', cstring(query)); err != nil {
		return err
	}
	return c.readUntilReady(wantCode)
}

func (c *pgClient) extended(t *testing.T, statement, portal, query string, params []string) {
	t.Helper()
	if err := c.extendedQuery(statement, portal, query, params, ""); err != nil {
		t.Fatalf("extended query %q: %v", query, err)
	}
}

func (c *pgClient) extendedError(t *testing.T, statement, portal, query string, params []string, code string) {
	t.Helper()
	if err := c.extendedQuery(statement, portal, query, params, code); err != nil {
		t.Fatalf("extended error query %q: %v", query, err)
	}
}

func (c *pgClient) extendedQuery(statement, portal, query string, params []string, wantCode string) error {
	batch := c.extendedCycle(statement, portal, query, params)
	batch = append(batch, frame('S', nil)...)
	if _, err := c.conn.Write(batch); err != nil {
		return err
	}
	return c.readUntilReady(wantCode)
}

func (c *pgClient) pipeline(t *testing.T, queries []string) {
	t.Helper()
	var batch []byte
	for i, query := range queries {
		batch = append(batch, c.extendedCycle(fmt.Sprintf("pipeline_%d", i), fmt.Sprintf("pipeline_portal_%d", i), query, nil)...)
	}
	batch = append(batch, frame('S', nil)...)
	if _, err := c.conn.Write(batch); err != nil {
		t.Fatalf("write pipeline: %v", err)
	}
	if err := c.readUntilReady(""); err != nil {
		t.Fatalf("read pipeline: %v", err)
	}
}

func (c *pgClient) extendedCycle(statement, portal, query string, params []string) []byte {
	parse := append(cstring(statement), cstring(query)...)
	parse = appendInt16(parse, int16(len(params)))
	for range params {
		parse = appendInt32(parse, 23)
	}
	bind := append(cstring(portal), cstring(statement)...)
	bind = appendInt16(bind, 0)
	bind = appendInt16(bind, int16(len(params)))
	for _, param := range params {
		bind = appendInt32(bind, int32(len(param)))
		bind = append(bind, param...)
	}
	bind = appendInt16(bind, 0)
	execute := appendInt32(cstring(portal), 0)
	var batch bytes.Buffer
	for _, message := range []struct {
		typ     byte
		payload []byte
	}{{'P', parse}, {'B', bind}, {'E', execute}} {
		batch.Write(frame(message.typ, message.payload))
	}
	return batch.Bytes()
}

func (c *pgClient) sendMessage(typ byte, payload []byte) error {
	_, err := c.conn.Write(frame(typ, payload))
	return err
}

func (c *pgClient) readUntilReady(wantCode string) error {
	_ = c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	foundCode := ""
	for {
		typ, payload, err := c.readMessage()
		if err != nil {
			return err
		}
		switch typ {
		case 'R':
			if len(payload) < 4 || binary.BigEndian.Uint32(payload) != 0 {
				return fmt.Errorf("unsupported authentication response")
			}
		case 'K':
			if len(payload) == 8 {
				c.backendID = int32(binary.BigEndian.Uint32(payload))
				c.secretKey = int32(binary.BigEndian.Uint32(payload[4:]))
			}
		case 'E':
			foundCode = errorField(payload, 'C')
		case 'Z':
			if foundCode != wantCode {
				return fmt.Errorf("SQLSTATE=%q, want %q", foundCode, wantCode)
			}
			return nil
		}
	}
}

func (c *pgClient) readMessage() (byte, []byte, error) {
	typ, err := c.read.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(c.read, lengthBytes); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(lengthBytes))
	if length < 4 || length > 16<<20 {
		return 0, nil, fmt.Errorf("invalid backend message length %d", length)
	}
	payload := make([]byte, length-4)
	_, err = io.ReadFull(c.read, payload)
	return typ, payload, err
}

func frame(typ byte, payload []byte) []byte {
	result := make([]byte, 5, 5+len(payload))
	result[0] = typ
	binary.BigEndian.PutUint32(result[1:], uint32(len(payload)+4))
	return append(result, payload...)
}

func cstring(value string) []byte { return append([]byte(value), 0) }

func appendInt16(dst []byte, value int16) []byte {
	var data [2]byte
	binary.BigEndian.PutUint16(data[:], uint16(value))
	return append(dst, data[:]...)
}

func appendInt32(dst []byte, value int32) []byte {
	var data [4]byte
	binary.BigEndian.PutUint32(data[:], uint32(value))
	return append(dst, data[:]...)
}

func errorField(payload []byte, field byte) string {
	for len(payload) > 1 && payload[0] != 0 {
		typ := payload[0]
		end := bytes.IndexByte(payload[1:], 0)
		if end < 0 {
			return ""
		}
		if typ == field {
			return string(payload[1 : end+1])
		}
		payload = payload[end+2:]
	}
	return ""
}

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/reassembly"
)

func TestBuildVersionUsesReleaseVersion(t *testing.T) {
	previous := releaseVersion
	releaseVersion = "v0.0.1"
	t.Cleanup(func() { releaseVersion = previous })
	if got := buildVersion(); !strings.HasPrefix(got, "pgsniffer v0.0.1") {
		t.Fatalf("buildVersion() = %q", got)
	}
}

func TestRunCaptureOfflinePCAP(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "postgres.pcap")
	file, err := os.Create(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	t0 := time.Unix(1000, 0)
	query := pgMessage('Q', append([]byte("SELECT 123"), 0))
	if err := writer.WritePacket(captureInfo(t0, len(query)), tcpPacket(t, true, 100, query)); err != nil {
		t.Fatal(err)
	}
	response := append(pgMessage('C', append([]byte("SELECT 1"), 0)), pgMessage('Z', []byte{'I'})...)
	if err := writer.WritePacket(captureInfo(t0.Add(20*time.Millisecond), len(response)), tcpPacket(t, false, 500, response)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := config{
		readPCAP: pcapPath, server: "10.0.0.1:5432", topN: 10,
	}
	collector := pgsql.NewCollector(100, false)
	if err := runCapture(context.Background(), cfg, collector); err != nil {
		t.Fatal(err)
	}
	report := collector.Snapshot("max", 10)
	if len(report.Queries) != 1 {
		t.Fatalf("report = %+v", report)
	}
	if report.Queries[0].Fingerprint != "select ?" || report.Queries[0].Max != 20*time.Millisecond {
		t.Fatalf("summary = %+v", report.Queries[0])
	}
	if report.Queries[0].CommandTags["SELECT"] != 1 || report.Queries[0].RowsAffected != 1 || report.Queries[0].Dimensions.ClientAddress != "10.0.0.2" {
		t.Fatalf("query details = %+v", report.Queries[0])
	}
	if report.Capture.PacketsSeen != 2 || report.Capture.PacketsMatched != 2 || report.Capture.BytesCaptured == 0 || report.Capture.TruncatedPackets != 0 {
		t.Fatalf("capture statistics = %+v", report.Capture)
	}
}

func TestOpenOfflinePCAPNG(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "postgres.pcapng")
	file, err := os.Create(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	packet := tcpPacket(t, true, 100, pgMessage('Q', append([]byte("SELECT 1"), 0)))
	if err := writer.WritePacket(captureInfo(time.Unix(1000, 0), len(packet)-54), packet); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	handle, err := openOfflineCapture(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	data, _, err := handle.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != len(packet) {
		t.Fatalf("packet length = %d, want %d", len(data), len(packet))
	}
}

func TestValidateConfig(t *testing.T) {
	valid := config{interfaceName: "lo", server: "127.0.0.1:5432", topN: 10, groupBy: groupByFingerprint}
	if err := validateConfig(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.server = "localhost:5432"
	if err := validateConfig(invalid); err == nil {
		t.Fatal("expected IP literal validation error")
	}
	invalid.server = ""
	if err := validateConfig(invalid); err == nil {
		t.Fatal("expected required server error")
	}
	invalid = valid
	invalid.interfaceName = ""
	if err := validateConfig(invalid); err == nil {
		t.Fatal("expected required interface error")
	}
	invalid.readPCAP = "traffic.pcap"
	if err := validateConfig(invalid); err != nil {
		t.Fatalf("offline capture should not require an interface: %v", err)
	}
	invalid = valid
	invalid.reportInterval = time.Minute
	if err := validateConfig(invalid); err == nil {
		t.Fatal("expected report file validation error")
	}
	invalid = valid
	invalid.reportFile = "reports.jsonl"
	if err := validateConfig(invalid); err == nil {
		t.Fatal("expected report interval validation error")
	}
	invalid = valid
	invalid.groupBy = "query"
	if err := validateConfig(invalid); err == nil {
		t.Fatal("expected group-by validation error")
	}
	if got := serverBPFFilter(mustServerEndpoint(t, "127.0.0.1:55432")); got != "host 127.0.0.1 and tcp port 55432" {
		t.Fatalf("IPv4 filter = %q", got)
	}
	if got := serverBPFFilter(mustServerEndpoint(t, "[::1]:5432")); got != "ip6 and host ::1 and tcp port 5432" {
		t.Fatalf("IPv6 filter = %q", got)
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := parseFlags([]string{"--interface", "lo", "--server", "127.0.0.1:55432", "--max-groups", "0", "--log-queries", "--group-by", "raw-sql", "--listen", "127.0.0.1:9108", "--report-interval", "1m", "--report-file", "reports.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.interfaceName != "lo" || cfg.server != "127.0.0.1:55432" || cfg.topN != 0 || !cfg.logQueries || cfg.groupBy != groupByRawSQL || cfg.listen != "127.0.0.1:9108" || cfg.reportInterval != time.Minute || cfg.reportFile != "reports.jsonl" {
		t.Fatalf("config = %+v", cfg)
	}
	if _, err := parseFlags([]string{"unexpected"}); err == nil {
		t.Fatal("expected positional argument error")
	}
	if _, err := parseFlagsWithOutput([]string{"--show-query-values"}, io.Discard); err == nil {
		t.Fatal("removed --show-query-values flag should be rejected")
	}
	if _, err := parseFlagsWithOutput([]string{"-v"}, io.Discard); err == nil {
		t.Fatal("removed -v flag should be rejected")
	}
	if _, err := parseFlagsWithOutput([]string{"--raw-sql"}, io.Discard); err == nil {
		t.Fatal("removed --raw-sql flag should be rejected")
	}
	for _, removed := range []string{"-i", "-l", "-n"} {
		if _, err := parseFlagsWithOutput([]string{removed}, io.Discard); err == nil {
			t.Errorf("removed %s flag should be rejected", removed)
		}
	}
}

func TestCustomHelp(t *testing.T) {
	var output bytes.Buffer
	if _, err := parseFlagsWithOutput([]string{"--help"}, &output); err != flag.ErrHelp {
		t.Fatalf("--help error = %v, want flag.ErrHelp", err)
	}
	help := output.String()
	for _, expected := range []string{
		"Usage:\n  pgsniffer [options]",
		"Capture options:",
		"SQL output options:",
		"Observability options:",
		"Other options:",
		"--server IP:PORT",
		"--interface INTERFACE",
		"--list-interfaces",
		"--group-by MODE",
		"--log-queries",
		"--max-groups COUNT",
		"-h, --help",
		"requires --report-interval",
	} {
		if !strings.Contains(help, expected) {
			t.Errorf("help is missing %q:\n%s", expected, help)
		}
	}
	if strings.Contains(help, "Usage of pgsniffer") || strings.Contains(help, "-group-by string") {
		t.Fatalf("help contains Go flag defaults:\n%s", help)
	}
}

func TestPrintCaptureDevices(t *testing.T) {
	devices := []captureDevice{
		{
			Name:        `\Device\NPF_{12E1F115-0492-452E-9B70-908F209689E1}`,
			Description: "VMware vmxnet3 virtual network device",
			Addresses:   []string{"10.95.84.119", "fe80::30bd:df0e:d9bc:4cd6"},
		},
		{Name: `\Device\NPF_Loopback`, Description: "Adapter for loopback traffic capture"},
		{Name: "en0", Addresses: []string{"192.0.2.10"}},
	}
	var output bytes.Buffer
	if err := printCaptureDevices(&output, devices); err != nil {
		t.Fatal(err)
	}
	want := `[1] VMware vmxnet3 virtual network device
    Device:    \Device\NPF_{12E1F115-0492-452E-9B70-908F209689E1}
    Addresses:
      - 10.95.84.119
      - fe80::30bd:df0e:d9bc:4cd6
    Usage:     --interface "\Device\NPF_{12E1F115-0492-452E-9B70-908F209689E1}"

[2] Adapter for loopback traffic capture
    Device:    \Device\NPF_Loopback
    Addresses: not reported
    Usage:     --interface "\Device\NPF_Loopback"

[3] en0
    Addresses:
      - 192.0.2.10
    Usage:     --interface "en0"
`
	if output.String() != want {
		t.Fatalf("interface list:\n%s\nwant:\n%s", output.String(), want)
	}

	output.Reset()
	if err := printCaptureDevices(&output, nil); err != nil {
		t.Fatal(err)
	}
	if output.String() != "No capture interfaces found.\n" {
		t.Fatalf("empty interface list = %q", output.String())
	}
}

func TestQueryLogUsesRawSQL(t *testing.T) {
	var output bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})

	logCompletedQuery(pgsql.Event{Query: "SELECT * FROM users WHERE id = 123", Duration: 2 * time.Millisecond})
	if got := output.String(); !strings.Contains(got, `sql="SELECT * FROM users WHERE id = 123"`) || strings.Contains(got, "id = ?") {
		t.Fatalf("query log = %q", got)
	}
}

func mustServerEndpoint(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	endpoint, err := parseServerEndpoint(value)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func TestReassemblyCompleteUsesConnectionCloseTimestamp(t *testing.T) {
	collector := pgsql.NewCollector(10, false)
	t0 := time.Unix(2000, 0)
	session := pgsql.NewSession(1024, pgsql.Metadata{}, collector.Add)
	if err := session.Feed(pgsql.ClientToServer, pgMessage('Q', append([]byte("SELECT pg_sleep(10)"), 0)), t0); err != nil {
		t.Fatal(err)
	}
	stream := &pgStream{session: session, collector: collector, lastSeen: t0}
	closedAt := t0.Add(250 * time.Millisecond)
	start := false
	if !stream.Accept(&layers.TCP{RST: true}, gopacket.CaptureInfo{Timestamp: closedAt}, reassembly.TCPDirServerToClient, 0, &start, captureContext{info: gopacket.CaptureInfo{Timestamp: closedAt}}) {
		t.Fatal("close packet should be accepted")
	}
	if !stream.ReassemblyComplete(nil) {
		t.Fatal("stream should be removable after reassembly completes")
	}
	report := collector.Snapshot("max", 0)
	if len(report.Queries) != 1 || report.Queries[0].Incomplete != 1 || report.Queries[0].Max != 250*time.Millisecond || report.Queries[0].IncompleteReasons["connection_closed"] != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func captureInfo(timestamp time.Time, payloadLength int) gopacket.CaptureInfo {
	packetLength := 14 + 20 + 20 + payloadLength
	return gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: packetLength, Length: packetLength}
}

func tcpPacket(t *testing.T, clientToServer bool, sequence uint32, payload []byte) []byte {
	t.Helper()
	sourceIP, destinationIP := net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1")
	sourcePort, destinationPort := layers.TCPPort(40000), layers.TCPPort(5432)
	sourceMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	destinationMAC := net.HardwareAddr{6, 7, 8, 9, 10, 11}
	if !clientToServer {
		sourceIP, destinationIP = destinationIP, sourceIP
		sourcePort, destinationPort = destinationPort, sourcePort
		sourceMAC, destinationMAC = destinationMAC, sourceMAC
	}
	ethernet := &layers.Ethernet{SrcMAC: sourceMAC, DstMAC: destinationMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: sourceIP, DstIP: destinationIP}
	tcp := &layers.TCP{SrcPort: sourcePort, DstPort: destinationPort, Seq: sequence, ACK: true, PSH: true, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func pgMessage(typ byte, payload []byte) []byte {
	result := make([]byte, 5+len(payload))
	result[0] = typ
	binary.BigEndian.PutUint32(result[1:], uint32(4+len(payload)))
	copy(result[5:], payload)
	return result
}

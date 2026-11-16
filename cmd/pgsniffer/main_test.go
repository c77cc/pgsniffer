package main

import (
	"context"
	"encoding/binary"
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
	valid := config{interfaceName: "lo", server: "127.0.0.1:5432", topN: 10}
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
	if got := serverBPFFilter(mustServerEndpoint(t, "127.0.0.1:55432")); got != "host 127.0.0.1 and tcp port 55432" {
		t.Fatalf("IPv4 filter = %q", got)
	}
	if got := serverBPFFilter(mustServerEndpoint(t, "[::1]:5432")); got != "ip6 and host ::1 and tcp port 5432" {
		t.Fatalf("IPv6 filter = %q", got)
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := parseFlags([]string{"-i", "lo", "--server", "127.0.0.1:55432", "-n", "0", "-v"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.interfaceName != "lo" || cfg.server != "127.0.0.1:55432" || cfg.topN != 0 || !cfg.verbose {
		t.Fatalf("config = %+v", cfg)
	}
	if _, err := parseFlags([]string{"unexpected"}); err == nil {
		t.Fatal("expected positional argument error")
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

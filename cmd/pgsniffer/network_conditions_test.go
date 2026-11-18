package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type timedPacket struct {
	at   time.Time
	data []byte
}

func TestRunCaptureNetworkConditions(t *testing.T) {
	t0 := time.Unix(3000, 0)
	query := pgMessage('Q', append([]byte("SELECT 'network-condition'"), 0))
	response := append(pgMessage('C', append([]byte("SELECT 1"), 0)), pgMessage('Z', []byte{'I'})...)
	clientSYN := conditionTCPPacket(t, true, 99, true, false, nil)
	serverSYN := conditionTCPPacket(t, false, 499, true, false, nil)

	fragmentedQuery := conditionTCPPacket(t, true, 100, false, true, query)
	queryFragmentPayloadLength := len(fragmentedQuery) - 14 - 20
	firstFragmentLength := 24
	fragmentOne := ipv4FragmentPacket(t, fragmentedQuery, 0, firstFragmentLength, true)
	fragmentTwo := ipv4FragmentPacket(t, fragmentedQuery, firstFragmentLength, queryFragmentPayloadLength-firstFragmentLength, false)

	cases := []struct {
		name             string
		packets          []timedPacket
		wantGap          bool
		wantIncomplete   bool
		wantDecodeErrors uint64
	}{
		{
			name: "out_of_order",
			packets: []timedPacket{
				{t0, clientSYN}, {t0.Add(time.Millisecond), serverSYN},
				{t0.Add(3 * time.Millisecond), conditionTCPPacket(t, true, 108, false, true, query[8:])},
				{t0.Add(4 * time.Millisecond), conditionTCPPacket(t, true, 100, false, true, query[:8])},
				{t0.Add(10 * time.Millisecond), conditionTCPPacket(t, false, 500, false, true, response)},
			},
		},
		{
			name: "retransmission",
			packets: []timedPacket{
				{t0, clientSYN}, {t0.Add(time.Millisecond), serverSYN},
				{t0.Add(2 * time.Millisecond), conditionTCPPacket(t, true, 100, false, true, query)},
				{t0.Add(3 * time.Millisecond), conditionTCPPacket(t, true, 100, false, true, query)},
				{t0.Add(10 * time.Millisecond), conditionTCPPacket(t, false, 500, false, true, response)},
			},
		},
		{
			name: "packet_loss",
			packets: []timedPacket{
				{t0, clientSYN}, {t0.Add(time.Millisecond), serverSYN},
				{t0.Add(2 * time.Millisecond), conditionTCPPacket(t, true, 100, false, true, query)},
				{t0.Add(10 * time.Millisecond), conditionTCPPacket(t, false, 500+uint32(len(response)-6), false, true, response[len(response)-6:])},
			},
			wantGap: true, wantIncomplete: true, wantDecodeErrors: 1,
		},
		{
			name: "ipv4_fragmentation",
			packets: []timedPacket{
				{t0, clientSYN}, {t0.Add(time.Millisecond), serverSYN},
				{t0.Add(2 * time.Millisecond), fragmentTwo},
				{t0.Add(3 * time.Millisecond), fragmentOne},
				{t0.Add(10 * time.Millisecond), conditionTCPPacket(t, false, 500, false, true, response)},
			},
		},
		{
			name: "vlan",
			packets: []timedPacket{
				{t0, addTestVLANHeader(conditionTCPPacket(t, true, 100, false, true, query), uint16(layers.EthernetTypeDot1Q), 42)},
				{t0.Add(10 * time.Millisecond), addTestVLANHeader(conditionTCPPacket(t, false, 500, false, true, response), uint16(layers.EthernetTypeDot1Q), 42)},
			},
		},
		{
			name: "qinq",
			packets: []timedPacket{
				{t0, addQinQ(conditionTCPPacket(t, true, 100, false, true, query))},
				{t0.Add(10 * time.Millisecond), addQinQ(conditionTCPPacket(t, false, 500, false, true, response))},
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report := runPacketScenario(t, test.packets)
			if len(report.Queries) != 1 {
				t.Fatalf("queries = %+v", report.Queries)
			}
			summary := report.Queries[0]
			if summary.Fingerprint != pgsql.Fingerprint("SELECT 'network-condition'") || summary.Count != 1 {
				t.Fatalf("summary = %+v", summary)
			}
			if got := summary.Incomplete != 0; got != test.wantIncomplete {
				t.Fatalf("incomplete = %d, want incomplete=%t: %+v", summary.Incomplete, test.wantIncomplete, summary)
			}
			if test.wantIncomplete && summary.IncompleteReasons["tcp_gap"] != 1 {
				t.Fatalf("incomplete reasons = %+v, want one tcp_gap", summary.IncompleteReasons)
			}
			if got := report.Capture.TCPGapEvents != 0; got != test.wantGap {
				t.Fatalf("TCP gaps = %d, want gap=%t: %+v", report.Capture.TCPGapEvents, test.wantGap, report.Capture)
			}
			if report.DecodeErrors != test.wantDecodeErrors {
				t.Fatalf("decode errors = %d, want %d", report.DecodeErrors, test.wantDecodeErrors)
			}
		})
	}
}

func runPacketScenario(t *testing.T, packets []timedPacket) pgsql.Report {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenario.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, packet := range packets {
		info := gopacket.CaptureInfo{Timestamp: packet.at, CaptureLength: len(packet.data), Length: len(packet.data)}
		if err := writer.WritePacket(info, packet.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	collector := pgsql.NewCollector(100, false)
	cfg := config{readPCAP: path, server: "10.0.0.1:5432", topN: 0}
	if err := runCapture(context.Background(), cfg, collector); err != nil {
		t.Fatal(err)
	}
	return collector.Snapshot("max", 0)
}

func conditionTCPPacket(t *testing.T, clientToServer bool, sequence uint32, syn, psh bool, payload []byte) []byte {
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
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Id: 100, Protocol: layers.IPProtocolTCP, SrcIP: sourceIP, DstIP: destinationIP}
	tcp := &layers.TCP{SrcPort: sourcePort, DstPort: destinationPort, Seq: sequence, SYN: syn, ACK: !syn || !clientToServer, PSH: psh, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ipv4, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func ipv4FragmentPacket(t *testing.T, packet []byte, offset, length int, more bool) []byte {
	t.Helper()
	const ethernetLength = 14
	if len(packet) < ethernetLength+20 {
		t.Fatal("packet is too short for Ethernet and IPv4 headers")
	}
	headerLength := int(packet[ethernetLength]&0x0f) * 4
	payload := packet[ethernetLength+headerLength:]
	if offset < 0 || length <= 0 || offset+length > len(payload) || offset%8 != 0 {
		t.Fatalf("invalid fragment offset=%d length=%d payload=%d", offset, length, len(payload))
	}
	flags := layers.IPv4Flag(0)
	if more {
		flags = layers.IPv4MoreFragments
	}
	ethernet := &layers.Ethernet{
		SrcMAC: append(net.HardwareAddr(nil), packet[6:12]...), DstMAC: append(net.HardwareAddr(nil), packet[:6]...),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version: 4, TTL: packet[ethernetLength+8], Id: binary.BigEndian.Uint16(packet[ethernetLength+4 : ethernetLength+6]),
		Protocol: layers.IPProtocolTCP, SrcIP: net.IP(append([]byte(nil), packet[ethernetLength+12:ethernetLength+16]...)),
		DstIP: net.IP(append([]byte(nil), packet[ethernetLength+16:ethernetLength+20]...)), Flags: flags, FragOffset: uint16(offset / 8),
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ipv4, gopacket.Payload(payload[offset:offset+length])); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func addTestVLANHeader(packet []byte, etherType, vlanID uint16) []byte {
	result := make([]byte, 0, len(packet)+4)
	result = append(result, packet[:12]...)
	result = binary.BigEndian.AppendUint16(result, etherType)
	result = binary.BigEndian.AppendUint16(result, vlanID&0x0fff)
	return append(result, packet[12:]...)
}

func addQinQ(packet []byte) []byte {
	inner := addTestVLANHeader(packet, uint16(layers.EthernetTypeDot1Q), 42)
	return addTestVLANHeader(inner, uint16(layers.EthernetTypeQinQ), 84)
}

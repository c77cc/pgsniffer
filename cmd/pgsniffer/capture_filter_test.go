package main

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

func TestServerPortFilter(t *testing.T) {
	filter, err := serverPortFilter(5432)
	if err != nil {
		t.Fatal(err)
	}
	instructions, allDecoded := bpf.Disassemble(filter)
	if !allDecoded {
		t.Fatal("filter contains an unknown instruction")
	}
	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatal(err)
	}

	request := tcpPacket(t, true, 100, []byte("request"))
	response := tcpPacket(t, false, 200, []byte("response"))
	ipv6Request := tcpIPv6Packet(t, true, []byte("request"))
	ipv6Response := tcpIPv6Packet(t, false, []byte("response"))
	ipv6ExtensionRequest := addIPv6HopByHopHeader(ipv6Request)
	vlanRequest := addTestVLANHeader(request, uint16(layers.EthernetTypeDot1Q), 42)
	qinqRequest := addQinQ(request)
	fragment := ipv4FragmentPacket(t, request, 0, 24, true)
	for name, packet := range map[string][]byte{
		"IPv4 destination port": request,
		"IPv4 source port":      response,
		"IPv6 destination port": ipv6Request,
		"IPv6 source port":      ipv6Response,
		"IPv6 extension header": ipv6ExtensionRequest,
		"VLAN":                  vlanRequest,
		"QinQ":                  qinqRequest,
		"IPv4 fragment":         fragment,
	} {
		t.Run(name, func(t *testing.T) {
			accepted, runErr := vm.Run(packet)
			if runErr != nil {
				t.Fatal(runErr)
			}
			if accepted == 0 {
				t.Fatal("packet was rejected")
			}
		})
	}

	otherFilter, err := serverPortFilter(6432)
	if err != nil {
		t.Fatal(err)
	}
	otherInstructions, allDecoded := bpf.Disassemble(otherFilter)
	if !allDecoded {
		t.Fatal("other filter contains an unknown instruction")
	}
	otherVM, err := bpf.NewVM(otherInstructions)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := otherVM.Run(request)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 0 {
		t.Fatal("unrelated port was accepted")
	}
}

func addIPv6HopByHopHeader(packet []byte) []byte {
	const ipv6Offset = 14
	result := make([]byte, 0, len(packet)+8)
	result = append(result, packet[:ipv6Offset+40]...)
	result[ipv6Offset+6] = byte(layers.IPProtocolIPv6HopByHop)
	payloadLength := binary.BigEndian.Uint16(result[ipv6Offset+4 : ipv6Offset+6])
	binary.BigEndian.PutUint16(result[ipv6Offset+4:ipv6Offset+6], payloadLength+8)
	result = append(result, byte(layers.IPProtocolTCP), 0, 0, 0, 0, 0, 0, 0)
	return append(result, packet[ipv6Offset+40:]...)
}

func tcpIPv6Packet(t *testing.T, clientToServer bool, payload []byte) []byte {
	t.Helper()
	sourceIP, destinationIP := net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1")
	sourcePort, destinationPort := layers.TCPPort(40000), layers.TCPPort(5432)
	if !clientToServer {
		sourceIP, destinationIP = destinationIP, sourceIP
		sourcePort, destinationPort = destinationPort, sourcePort
	}
	ethernet := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: sourceIP, DstIP: destinationIP}
	tcp := &layers.TCP{SrcPort: sourcePort, DstPort: destinationPort, Seq: 100, ACK: true, PSH: true, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	linuxCaptureBufferSize = 65536
	linuxCaptureBlockSize  = 1 << 20
	linuxCaptureBlocks     = 64
)

func defaultCaptureInterface() string { return "lo" }

type linuxCapture struct {
	mu        sync.Mutex
	packet    *afpacket.TPacket
	promiscFD int
}

func openLiveCapture(interfaceName string, server netip.AddrPort) (captureHandle, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("open interface %q: %w", interfaceName, err)
	}
	promiscFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("open promiscuous membership socket on %q: %w", interfaceName, err)
	}
	request := &unix.PacketMreq{Ifindex: int32(iface.Index), Type: unix.PACKET_MR_PROMISC}
	if err := unix.SetsockoptPacketMreq(promiscFD, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, request); err != nil {
		_ = unix.Close(promiscFD)
		return nil, fmt.Errorf("enable promiscuous capture on interface %q: %w", interfaceName, err)
	}
	packet, err := afpacket.NewTPacket(
		afpacket.OptInterface(interfaceName),
		afpacket.OptFrameSize(linuxCaptureBufferSize),
		afpacket.OptBlockSize(linuxCaptureBlockSize),
		afpacket.OptNumBlocks(linuxCaptureBlocks),
		afpacket.OptPollTimeout(500*time.Millisecond),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
	)
	if err != nil {
		_ = unix.Close(promiscFD)
		return nil, fmt.Errorf("open TPACKET_V3 ring on interface %q: %w", interfaceName, err)
	}
	capture := &linuxCapture{packet: packet, promiscFD: promiscFD}
	filter, err := serverPortFilter(server.Port())
	if err != nil {
		capture.Close()
		return nil, fmt.Errorf("compile packet filter on interface %q: %w", interfaceName, err)
	}
	if err := packet.SetBPF(filter); err != nil {
		capture.Close()
		return nil, fmt.Errorf("attach packet filter on interface %q: %w", interfaceName, err)
	}
	return capture, nil
}

func (c *linuxCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	c.mu.Lock()
	packet := c.packet
	c.mu.Unlock()
	if packet == nil {
		return nil, gopacket.CaptureInfo{}, net.ErrClosed
	}
	return packet.ReadPacketData()
}

func (c *linuxCapture) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

func (c *linuxCapture) Stats() (captureStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.packet == nil {
		return captureStats{}, net.ErrClosed
	}
	_, stats, err := c.packet.SocketStats()
	if err != nil {
		return captureStats{}, err
	}
	return captureStats{PacketsReceived: uint64(stats.Packets()), PacketsDropped: uint64(stats.Drops())}, nil
}

func (c *linuxCapture) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.packet != nil {
		c.packet.Close()
		c.packet = nil
	}
	if c.promiscFD >= 0 {
		_ = unix.Close(c.promiscFD)
		c.promiscFD = -1
	}
}

func listCaptureDevices() ([]captureDevice, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	devices := make([]captureDevice, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses, addressErr := iface.Addrs()
		if addressErr != nil {
			return nil, fmt.Errorf("list addresses for %q: %w", iface.Name, addressErr)
		}
		devices = append(devices, captureDevice{
			Name: iface.Name, Description: iface.Flags.String(), Addresses: addresses,
		})
	}
	return devices, nil
}

type filterInstruction struct {
	instruction bpf.Instruction
	trueLabel   string
	falseLabel  string
	jumpLabel   string
}

type filterBuilder struct {
	instructions []filterInstruction
	labels       map[string]int
}

func newFilterBuilder() *filterBuilder { return &filterBuilder{labels: make(map[string]int)} }

func (b *filterBuilder) label(name string) { b.labels[name] = len(b.instructions) }

func (b *filterBuilder) add(instruction bpf.Instruction) {
	b.instructions = append(b.instructions, filterInstruction{instruction: instruction})
}

func (b *filterBuilder) jumpIf(value uint32, trueLabel, falseLabel string) {
	b.instructions = append(b.instructions, filterInstruction{
		instruction: bpf.JumpIf{Cond: bpf.JumpEqual, Val: value}, trueLabel: trueLabel, falseLabel: falseLabel,
	})
}

func (b *filterBuilder) jump(label string) {
	b.instructions = append(b.instructions, filterInstruction{instruction: bpf.Jump{}, jumpLabel: label})
}

func (b *filterBuilder) assemble() ([]bpf.RawInstruction, error) {
	instructions := make([]bpf.Instruction, len(b.instructions))
	for index, symbolic := range b.instructions {
		switch instruction := symbolic.instruction.(type) {
		case bpf.JumpIf:
			trueSkip, err := b.skip(index, symbolic.trueLabel, 255)
			if err != nil {
				return nil, err
			}
			falseSkip, err := b.skip(index, symbolic.falseLabel, 255)
			if err != nil {
				return nil, err
			}
			instruction.SkipTrue, instruction.SkipFalse = uint8(trueSkip), uint8(falseSkip)
			instructions[index] = instruction
		case bpf.Jump:
			skip, err := b.skip(index, symbolic.jumpLabel, int(^uint32(0)))
			if err != nil {
				return nil, err
			}
			instruction.Skip = uint32(skip)
			instructions[index] = instruction
		default:
			instructions[index] = symbolic.instruction
		}
	}
	return bpf.Assemble(instructions)
}

func (b *filterBuilder) skip(index int, label string, maximum int) (int, error) {
	target, ok := b.labels[label]
	if !ok {
		return 0, fmt.Errorf("unknown BPF label %q", label)
	}
	skip := target - index - 1
	if skip < 0 || skip > maximum {
		return 0, fmt.Errorf("invalid BPF jump from %d to %d", index, target)
	}
	return skip, nil
}

func serverPortFilter(port uint16) ([]bpf.RawInstruction, error) {
	builder := newFilterBuilder()
	builder.add(bpf.LoadAbsolute{Off: 12, Size: 2})
	builder.jumpIf(uint32(layers.EthernetTypeIPv4), "ipv4", "check_ipv6")
	builder.label("check_ipv6")
	builder.jumpIf(uint32(layers.EthernetTypeIPv6), "ipv6", "check_vlan")
	builder.label("check_vlan")
	builder.jumpIf(uint32(layers.EthernetTypeDot1Q), "vlan", "check_qinq")
	builder.label("check_qinq")
	builder.jumpIf(0x88a8, "vlan", "drop")

	addIPv4PortFilter(builder, "ipv4", 14, port)
	addIPv6PortFilter(builder, "ipv6", 14, port)

	builder.label("vlan")
	builder.add(bpf.LoadAbsolute{Off: 16, Size: 2})
	builder.jumpIf(uint32(layers.EthernetTypeIPv4), "vlan_ipv4", "vlan_check_ipv6")
	builder.label("vlan_check_ipv6")
	builder.jumpIf(uint32(layers.EthernetTypeIPv6), "vlan_ipv6", "drop")
	addIPv4PortFilter(builder, "vlan_ipv4", 18, port)
	addIPv6PortFilter(builder, "vlan_ipv6", 18, port)

	builder.label("accept")
	builder.add(bpf.RetConstant{Val: linuxCaptureBufferSize})
	builder.label("drop")
	builder.add(bpf.RetConstant{Val: 0})
	return builder.assemble()
}

func addIPv4PortFilter(builder *filterBuilder, label string, networkOffset uint32, port uint16) {
	builder.label(label)
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 9, Size: 1})
	builder.jumpIf(uint32(layers.IPProtocolTCP), label+"_ports", "drop")
	builder.label(label + "_ports")
	builder.add(bpf.LoadMemShift{Off: networkOffset})
	builder.add(bpf.LoadIndirect{Off: networkOffset, Size: 2})
	builder.jumpIf(uint32(port), "accept", label+"_destination")
	builder.label(label + "_destination")
	builder.add(bpf.LoadIndirect{Off: networkOffset + 2, Size: 2})
	builder.jumpIf(uint32(port), "accept", "drop")
}

func addIPv6PortFilter(builder *filterBuilder, label string, networkOffset uint32, port uint16) {
	builder.label(label)
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 6, Size: 1})
	// Extension headers make the TCP offset variable. Let those packets reach
	// the protocol decoder and apply the exact endpoint filter in user space.
	builder.jumpIf(uint32(layers.IPProtocolTCP), label+"_source", "accept")
	builder.label(label + "_source")
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 40, Size: 2})
	builder.jumpIf(uint32(port), "accept", label+"_destination")
	builder.label(label + "_destination")
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 42, Size: 2})
	builder.jumpIf(uint32(port), "accept", "drop")
}

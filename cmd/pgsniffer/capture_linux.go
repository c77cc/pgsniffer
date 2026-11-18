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
	"golang.org/x/sys/unix"
)

const (
	linuxCaptureBufferSize = captureFilterSnapshotLength
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
		formattedAddresses := make([]string, 0, len(addresses))
		for _, address := range addresses {
			if ip, _, parseErr := net.ParseCIDR(address.String()); parseErr == nil {
				formattedAddresses = append(formattedAddresses, ip.String())
				continue
			}
			formattedAddresses = append(formattedAddresses, address.String())
		}
		devices = append(devices, captureDevice{
			Name: iface.Name, Description: iface.Flags.String(), Addresses: formattedAddresses,
		})
	}
	return devices, nil
}

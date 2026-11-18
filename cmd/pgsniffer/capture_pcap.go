//go:build !linux

package main

import (
	"fmt"
	"net/netip"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

func defaultCaptureInterface() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "lo0"
}

func openLiveCapture(interfaceName string, server netip.AddrPort) (captureHandle, error) {
	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open interface %q: %w", interfaceName, err)
	}
	filter := serverBPFFilter(server)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set BPF filter %q: %w", filter, err)
	}
	return &pcapCapture{Handle: handle}, nil
}

type pcapCapture struct{ *pcap.Handle }

func (c *pcapCapture) Stats() (captureStats, error) {
	stats, err := c.Handle.Stats()
	if err != nil {
		return captureStats{}, err
	}
	return captureStats{
		PacketsReceived: uint64(stats.PacketsReceived), PacketsDropped: uint64(stats.PacketsDropped),
		InterfaceDropped: uint64(stats.PacketsIfDropped),
	}, nil
}

func listCaptureDevices() ([]captureDevice, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	devices := make([]captureDevice, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses := make([]string, 0, len(iface.Addresses))
		for _, address := range iface.Addresses {
			if len(address.IP) > 0 {
				addresses = append(addresses, address.IP.String())
			}
		}
		devices = append(devices, captureDevice{
			Name: iface.Name, Description: iface.Description, Addresses: addresses,
		})
	}
	return devices, nil
}

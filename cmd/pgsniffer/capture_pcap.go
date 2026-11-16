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
	return handle, nil
}

func listCaptureDevices() ([]captureDevice, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	devices := make([]captureDevice, 0, len(interfaces))
	for _, iface := range interfaces {
		devices = append(devices, captureDevice{
			Name: iface.Name, Description: iface.Description, Addresses: iface.Addresses,
		})
	}
	return devices, nil
}

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type captureHandle interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
	Close()
}

type captureDevice struct {
	Name        string
	Description string
	Addresses   any
}

type offlineCapture struct {
	file     *os.File
	source   gopacket.PacketDataSource
	linkType layers.LinkType
}

func (c *offlineCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return c.source.ReadPacketData()
}

func (c *offlineCapture) LinkType() layers.LinkType { return c.linkType }

func (c *offlineCapture) Close() { _ = c.file.Close() }

func openCapture(cfg config, server netip.AddrPort) (captureHandle, error) {
	if cfg.readPCAP != "" {
		return openOfflineCapture(cfg.readPCAP)
	}
	return openLiveCapture(cfg.interfaceName, server)
}

func openOfflineCapture(path string) (captureHandle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PCAP file %q: %w", path, err)
	}
	reader := bufio.NewReader(file)
	magic, err := reader.Peek(4)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read PCAP header %q: %w", path, err)
	}

	result := &offlineCapture{file: file}
	if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		ngReader, readErr := pcapgo.NewNgReader(reader, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
		if readErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("open PCAPNG file %q: %w", path, readErr)
		}
		result.source = ngReader
		result.linkType = ngReader.LinkType()
		return result, nil
	}

	pcapReader, err := pcapgo.NewReader(reader)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("open PCAP file %q: %w", path, err)
	}
	result.source = pcapReader
	result.linkType = pcapReader.LinkType()
	return result, nil
}

func printAllDevices(w io.Writer) error {
	devices, err := listCaptureDevices()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	if len(devices) == 0 {
		_, err = fmt.Fprintln(w, "No capture interfaces found.")
		return err
	}
	for _, device := range devices {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%v\n", device.Name, device.Description, device.Addresses); err != nil {
			return err
		}
	}
	return nil
}

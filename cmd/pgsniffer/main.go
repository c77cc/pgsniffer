// Command pgsniffer passively analyzes PostgreSQL wire-protocol traffic.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

const maxQueryKeys = 10000

var releaseVersion string

type config struct {
	interfaceName string
	server        string
	topN          int
	verbose       bool
	showValues    bool
	listDevices   bool
	readPCAP      string
	version       bool
}

type captureContext struct {
	info gopacket.CaptureInfo
}

func (c captureContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }

type pgStreamFactory struct {
	serverIP   string
	serverPort layers.TCPPort
	collector  *pgsql.Collector
	verbose    bool
	showValues bool
}

type pgStream struct {
	session       *pgsql.Session
	collector     *pgsql.Collector
	firstIsClient bool
	verbose       bool
	showValues    bool
	lastSeen      time.Time
}

func (f *pgStreamFactory) New(netFlow, _ gopacket.Flow, tcp *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	firstIsClient := false
	switch {
	case netFlow.Dst().String() == f.serverIP && tcp.DstPort == f.serverPort:
		firstIsClient = true
	case netFlow.Src().String() == f.serverIP && tcp.SrcPort == f.serverPort:
		firstIsClient = false
	case tcp.SYN && tcp.ACK:
		firstIsClient = false
	}

	clientIP, clientPort := netFlow.Src().String(), tcp.SrcPort.String()
	if !firstIsClient {
		clientIP, clientPort = netFlow.Dst().String(), tcp.DstPort.String()
	}
	metadata := pgsql.Metadata{Client: net.JoinHostPort(clientIP, clientPort)}

	stream := &pgStream{
		collector: f.collector, firstIsClient: firstIsClient,
		verbose: f.verbose, showValues: f.showValues,
	}
	stream.session = pgsql.NewSession(pgsql.DefaultMaxFrameSize, metadata, func(event pgsql.Event) {
		f.collector.Add(event)
		if !f.verbose {
			return
		}
		if event.Encrypted {
			log.Printf("encrypted PostgreSQL session client=%s", event.Metadata.Client)
			return
		}
		query := pgsql.Fingerprint(event.Query)
		if f.showValues {
			query = event.Query
		}
		if event.ErrorCode != "" {
			log.Printf("query duration=%s sqlstate=%s sql=%q", event.Duration, event.ErrorCode, query)
		} else {
			log.Printf("query duration=%s sql=%q", event.Duration, query)
		}
	})
	return stream
}

func (s *pgStream) Accept(_ *layers.TCP, info gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	// Passive capture commonly starts after the TCP handshake.
	*start = true
	if info.Timestamp.After(s.lastSeen) {
		s.lastSeen = info.Timestamp
	}
	return true
}

func (s *pgStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}
	data := sg.Fetch(length)
	info := sg.CaptureInfo(0)
	if info.Timestamp.After(s.lastSeen) {
		s.lastSeen = info.Timestamp
	}
	direction, _, _, skip := sg.Info()
	if skip != 0 {
		s.collector.AddDecodeError()
	}

	clientToServer := direction == reassembly.TCPDirClientToServer
	if !s.firstIsClient {
		clientToServer = !clientToServer
	}
	pgDirection := pgsql.ServerToClient
	if clientToServer {
		pgDirection = pgsql.ClientToServer
	}
	if err := s.session.Feed(pgDirection, data, info.Timestamp); err != nil {
		s.collector.AddDecodeError()
		if s.verbose {
			log.Printf("discarding malformed PostgreSQL stream data: %v", err)
		}
	}
}

func (s *pgStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	at := s.lastSeen
	if ac != nil {
		closedAt := ac.GetCaptureInfo().Timestamp
		if closedAt.After(at) {
			at = closedAt
		}
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.session.Close(at)
	return true
}

func main() {
	if err := runMain(); err != nil {
		log.Printf("pgsniffer: %v", err)
		os.Exit(1)
	}
}

func runMain() error {
	cfg, err := parseFlags(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfg.version {
		fmt.Println(buildVersion())
		return nil
	}
	if cfg.listDevices {
		return printAllDevices(os.Stdout)
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	collector := pgsql.NewCollector(maxQueryKeys, cfg.showValues)
	captureErr := runCapture(ctx, cfg, collector)
	if err := pgsql.WriteJSON(os.Stdout, collector.Snapshot("max", cfg.topN)); err != nil {
		return err
	}
	if errors.Is(captureErr, context.Canceled) {
		return nil
	}
	return captureErr
}

func parseFlags(args []string) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("pgsniffer", flag.ContinueOnError)
	flags.StringVar(&cfg.interfaceName, "i", defaultCaptureInterface(), "network interface to capture")
	flags.StringVar(&cfg.server, "server", "", "PostgreSQL server endpoint as IP:PORT (required)")
	flags.IntVar(&cfg.topN, "n", 50, "number of query fingerprints to report (0 means all)")
	flags.BoolVar(&cfg.verbose, "v", false, "log every completed query")
	flags.BoolVar(&cfg.showValues, "show-query-values", false, "show and retain raw query values (sensitive)")
	flags.BoolVar(&cfg.listDevices, "l", false, "list capture interfaces and exit")
	flags.StringVar(&cfg.readPCAP, "read-pcap", "", "read packets from a PCAP file instead of an interface")
	flags.BoolVar(&cfg.version, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return cfg, nil
}

func validateConfig(cfg config) error {
	if _, err := parseServerEndpoint(cfg.server); err != nil {
		return err
	}
	if cfg.topN < 0 {
		return fmt.Errorf("top N cannot be negative")
	}
	if cfg.readPCAP == "" && cfg.interfaceName == "" {
		return fmt.Errorf("-i is required for live capture on this platform; use -l to list interfaces")
	}
	return nil
}

func parseServerEndpoint(value string) (netip.AddrPort, error) {
	if value == "" {
		return netip.AddrPort{}, fmt.Errorf("--server is required (for example 127.0.0.1:5432)")
	}
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid --server %q: expected IP:PORT: %w", value, err)
	}
	if endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid --server %q: port must be between 1 and 65535", value)
	}
	address := endpoint.Addr().Unmap()
	if address.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("invalid --server %q: IPv6 zones are not supported", value)
	}
	return netip.AddrPortFrom(address, endpoint.Port()), nil
}

func serverBPFFilter(endpoint netip.AddrPort) string {
	if endpoint.Addr().Is6() {
		return fmt.Sprintf("ip6 and host %s and tcp port %d", endpoint.Addr(), endpoint.Port())
	}
	return fmt.Sprintf("host %s and tcp port %d", endpoint.Addr(), endpoint.Port())
}

func runCapture(ctx context.Context, cfg config, collector *pgsql.Collector) error {
	server, err := parseServerEndpoint(cfg.server)
	if err != nil {
		return err
	}
	handle, err := openCapture(cfg, server)
	if err != nil {
		return err
	}
	defer handle.Close()

	factory := &pgStreamFactory{
		serverIP: server.Addr().String(), serverPort: layers.TCPPort(server.Port()), collector: collector,
		verbose: cfg.verbose, showValues: cfg.showValues,
	}
	pool := reassembly.NewStreamPool(factory)
	assembler := reassembly.NewAssembler(pool)
	assembler.MaxBufferedPagesPerConnection = 128
	assembler.MaxBufferedPagesTotal = 4096

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()
	flushTicker := time.NewTicker(30 * time.Second)
	defer flushTicker.Stop()
	latestCaptureTime := time.Time{}
	packetCount := uint64(0)
	for {
		select {
		case <-ctx.Done():
			assembler.FlushAll()
			return ctx.Err()
		case <-flushTicker.C:
			if !latestCaptureTime.IsZero() {
				assembler.FlushCloseOlderThan(latestCaptureTime.Add(-2 * time.Minute))
			}
		case packet, ok := <-packets:
			if !ok || packet == nil {
				assembler.FlushAll()
				return nil
			}
			metadata := packet.Metadata()
			if metadata == nil {
				collector.AddDecodeError()
				continue
			}
			latestCaptureTime = metadata.Timestamp
			network := packet.NetworkLayer()
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if network == nil || tcpLayer == nil {
				continue
			}
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			if !packetMatchesServer(network, tcp, server) {
				continue
			}
			assembler.AssembleWithContext(network.NetworkFlow(), tcp, captureContext{info: metadata.CaptureInfo})
			packetCount++
			if packetCount%10000 == 0 {
				assembler.FlushCloseOlderThan(latestCaptureTime.Add(-2 * time.Minute))
			}
		}
	}
}

func packetMatchesServer(network gopacket.NetworkLayer, tcp *layers.TCP, server netip.AddrPort) bool {
	flow := network.NetworkFlow()
	source, sourceErr := netip.ParseAddr(flow.Src().String())
	destination, destinationErr := netip.ParseAddr(flow.Dst().String())
	if sourceErr != nil || destinationErr != nil {
		return false
	}
	address := server.Addr().Unmap()
	port := layers.TCPPort(server.Port())
	return source.Unmap() == address && tcp.SrcPort == port || destination.Unmap() == address && tcp.DstPort == port
}

func buildVersion() string {
	version := releaseVersion
	var revision string
	if info, ok := debug.ReadBuildInfo(); ok {
		if version == "" {
			version = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value
				break
			}
		}
	}
	if version == "" || version == "(devel)" {
		version = "devel"
	}
	if revision != "" {
		return strings.Join([]string{"pgsniffer", version, revision[:min(12, len(revision))]}, " ")
	}
	return "pgsniffer " + version
}

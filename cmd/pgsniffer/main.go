// Command pgsniffer passively analyzes PostgreSQL wire-protocol traffic.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/ip4defrag"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

const maxQueryKeys = 10000

const (
	groupByFingerprint = "fingerprint"
	groupByRawSQL      = "raw-sql"
)

var releaseVersion string

type config struct {
	interfaceName  string
	server         string
	topN           int
	logQueries     bool
	groupBy        string
	listDevices    bool
	readPCAP       string
	listen         string
	reportInterval time.Duration
	reportFile     string
	version        bool
}

type captureContext struct {
	info gopacket.CaptureInfo
}

func (c captureContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }

type pgStreamFactory struct {
	serverIP   string
	serverPort layers.TCPPort
	collector  *pgsql.Collector
	logQueries bool
	notify     func(captureEventKind)
	sqlOnce    sync.Once
	tlsOnce    sync.Once
}

type pgStream struct {
	session       *pgsql.Session
	collector     *pgsql.Collector
	firstIsClient bool
	logQueries    bool
	lastSeen      time.Time
	sawTCPClose   bool
	sawMidstream  bool
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

	clientIP, clientPort := netFlow.Src().String(), tcp.SrcPort
	if !firstIsClient {
		clientIP, clientPort = netFlow.Dst().String(), tcp.DstPort
	}
	metadata := pgsql.Metadata{
		Client: net.JoinHostPort(clientIP, clientPort.String()), ClientAddress: clientIP, ClientPort: uint16(clientPort),
	}

	stream := &pgStream{
		collector: f.collector, firstIsClient: firstIsClient,
		logQueries: f.logQueries,
	}
	stream.session = pgsql.NewSession(pgsql.DefaultMaxFrameSize, metadata, func(event pgsql.Event) {
		f.collector.Add(event)
		if event.Encrypted {
			f.tlsOnce.Do(func() { f.notifyEvent(captureEventEncrypted) })
		} else if event.Query != "" && !event.Incomplete {
			f.sqlOnce.Do(func() { f.notifyEvent(captureEventSQL) })
		}
		if !f.logQueries {
			return
		}
		logCompletedQuery(event)
	})
	return stream
}

func (f *pgStreamFactory) notifyEvent(kind captureEventKind) {
	if f.notify != nil {
		f.notify(kind)
	}
}

func logCompletedQuery(event pgsql.Event) {
	if event.Encrypted {
		log.Printf("encrypted PostgreSQL session client=%s", event.Metadata.Client)
		return
	}
	if event.ErrorCode != "" {
		log.Printf("query duration=%s sqlstate=%s sql=%q", event.Duration, event.ErrorCode, event.Query)
	} else {
		log.Printf("query duration=%s sql=%q", event.Duration, event.Query)
	}
}

func (s *pgStream) Accept(tcp *layers.TCP, info gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	// Passive capture commonly starts after the TCP handshake.
	*start = true
	if tcp.FIN || tcp.RST {
		s.sawTCPClose = true
	}
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
	completedInfo := sg.CaptureInfo(length - 1)
	if completedInfo.Timestamp.Before(info.Timestamp) {
		completedInfo = info
	}
	if completedInfo.Timestamp.After(s.lastSeen) {
		s.lastSeen = completedInfo.Timestamp
	}
	direction, _, end, skip := sg.Info()
	if end {
		s.sawTCPClose = true
	}
	if skip > 0 {
		s.collector.AddTCPGap(skip)
		s.collector.AddDecodeError()
		s.session.Gap(info.Timestamp)
	} else if skip < 0 && !s.sawMidstream {
		s.sawMidstream = true
		s.collector.AddMidstreamConnection()
	}

	clientToServer := direction == reassembly.TCPDirClientToServer
	if !s.firstIsClient {
		clientToServer = !clientToServer
	}
	pgDirection := pgsql.ServerToClient
	if clientToServer {
		pgDirection = pgsql.ClientToServer
	}
	if err := s.session.FeedSpan(pgDirection, data, info.Timestamp, completedInfo.Timestamp); err != nil {
		s.collector.AddDecodeError()
		s.session.Abort(info.Timestamp)
		if s.logQueries {
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
	reason := "capture_or_idle_timeout"
	if s.sawTCPClose {
		reason = "connection_closed"
	}
	s.session.CloseWithReason(at, reason)
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
	collector := pgsql.NewCollector(maxQueryKeys, cfg.groupBy == groupByRawSQL)
	captureErr := runCaptureWithServices(ctx, cfg, collector)
	if err := pgsql.WriteJSON(os.Stdout, collector.Snapshot("max", cfg.topN)); err != nil {
		return err
	}
	if errors.Is(captureErr, context.Canceled) {
		return nil
	}
	return captureErr
}

func parseFlags(args []string) (config, error) {
	return parseFlagsWithOutput(args, os.Stderr)
}

func parseFlagsWithOutput(args []string, output io.Writer) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("pgsniffer", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() {
		_, _ = fmt.Fprint(flags.Output(), usageText(defaultCaptureInterface()))
	}
	flags.StringVar(&cfg.interfaceName, "interface", defaultCaptureInterface(), "network interface to capture")
	flags.StringVar(&cfg.server, "server", "", "PostgreSQL server endpoint as IP:PORT (required)")
	flags.IntVar(&cfg.topN, "max-groups", 50, "maximum number of SQL groups to report (0 means all)")
	flags.BoolVar(&cfg.logQueries, "log-queries", false, "log every completed query with raw SQL (sensitive)")
	flags.StringVar(&cfg.groupBy, "group-by", groupByFingerprint, "report grouping: fingerprint or raw-sql")
	flags.BoolVar(&cfg.listDevices, "list-interfaces", false, "list capture interfaces and exit")
	flags.StringVar(&cfg.readPCAP, "read-pcap", "", "read packets from a PCAP file instead of an interface")
	flags.StringVar(&cfg.listen, "listen", "", "HTTP address for /healthz, /report, and /metrics")
	flags.DurationVar(&cfg.reportInterval, "report-interval", 0, "periodic JSONL report interval (requires --report-file)")
	flags.StringVar(&cfg.reportFile, "report-file", "", "append periodic JSON reports to this file")
	flags.BoolVar(&cfg.version, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return cfg, nil
}

func usageText(defaultInterface string) string {
	interfaceDefault := ""
	if defaultInterface != "" {
		interfaceDefault = fmt.Sprintf(" (default: %s)", defaultInterface)
	}
	return fmt.Sprintf(`Usage:
  pgsniffer [options]

Capture options:
  --server IP:PORT
        PostgreSQL server endpoint; required for capture and replay
  --interface INTERFACE
        Network interface for live capture%s
  --list-interfaces
        List capture interfaces and exit
  --read-pcap FILE
        Analyze a PCAP/PCAPNG file instead of live capture

SQL output options:
  --group-by MODE
        Report grouping mode: fingerprint or raw-sql (default: fingerprint)
  --log-queries
        Log every completed original SQL query to stderr
        Warning: may expose sensitive values
  --max-groups COUNT
        Maximum number of SQL groups ordered by maximum latency;
        0 reports all groups (default: 50)

Observability options:
  --listen ADDRESS
        Serve /healthz, /report, and /metrics
        Example: 127.0.0.1:9108
  --report-interval DURATION
        Periodic JSONL report interval; requires --report-file
  --report-file FILE
        Append periodic JSONL reports; requires --report-interval

Other options:
  --version
        Print version and exit
  -h, --help
        Show this help
`, interfaceDefault)
}

func validateConfig(cfg config) error {
	if _, err := parseServerEndpoint(cfg.server); err != nil {
		return err
	}
	if cfg.topN < 0 {
		return fmt.Errorf("--max-groups cannot be negative")
	}
	if cfg.groupBy != groupByFingerprint && cfg.groupBy != groupByRawSQL {
		return fmt.Errorf("invalid --group-by %q: expected fingerprint or raw-sql", cfg.groupBy)
	}
	if cfg.reportInterval < 0 {
		return fmt.Errorf("--report-interval cannot be negative")
	}
	if cfg.reportInterval > 0 && cfg.reportFile == "" {
		return fmt.Errorf("--report-file is required with --report-interval")
	}
	if cfg.reportFile != "" && cfg.reportInterval == 0 {
		return fmt.Errorf("--report-interval is required with --report-file")
	}
	if cfg.readPCAP == "" && cfg.interfaceName == "" {
		return fmt.Errorf("--interface is required for live capture on this platform; use --list-interfaces to list interfaces")
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
	return runCaptureObserved(ctx, cfg, collector, nil)
}

func runCaptureObserved(ctx context.Context, cfg config, collector *pgsql.Collector, notify func(captureEventKind)) error {
	server, err := parseServerEndpoint(cfg.server)
	if err != nil {
		return err
	}
	handle, err := openCapture(cfg, server)
	if err != nil {
		return err
	}
	defer handle.Close()
	defer updateCaptureStatistics(handle, collector)
	if notify != nil {
		notify(captureEventReady)
	}

	factory := &pgStreamFactory{
		serverIP: server.Addr().String(), serverPort: layers.TCPPort(server.Port()), collector: collector,
		logQueries: cfg.logQueries, notify: notify,
	}
	pool := reassembly.NewStreamPool(factory)
	assembler := reassembly.NewAssembler(pool)
	assembler.MaxBufferedPagesPerConnection = 128
	assembler.MaxBufferedPagesTotal = 4096
	defragmenter := ip4defrag.NewIPv4Defragmenter()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()
	flushTicker := time.NewTicker(30 * time.Second)
	defer flushTicker.Stop()
	statisticsTicker := time.NewTicker(10 * time.Second)
	defer statisticsTicker.Stop()
	latestCaptureTime := time.Time{}
	packetCount := uint64(0)
	trafficDetected := false
	for {
		select {
		case <-ctx.Done():
			assembler.FlushAll()
			return ctx.Err()
		case <-flushTicker.C:
			if !latestCaptureTime.IsZero() {
				assembler.FlushCloseOlderThan(latestCaptureTime.Add(-2 * time.Minute))
				defragmenter.DiscardOlderThan(latestCaptureTime.Add(-2 * time.Minute))
			}
		case <-statisticsTicker.C:
			updateCaptureStatistics(handle, collector)
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
			if packet.ErrorLayer() != nil {
				collector.AddDecodeError()
			}
			latestCaptureTime = metadata.Timestamp
			network, tcp, waitingForFragments, decodeErr := decodeNetworkTCP(packet, defragmenter, metadata.Timestamp)
			if decodeErr != nil {
				collector.AddDecodeError()
				collector.ObservePacket(metadata.CaptureLength, metadata.Length, false)
				continue
			}
			if waitingForFragments {
				collector.ObservePacket(metadata.CaptureLength, metadata.Length, fragmentMatchesServer(packet.NetworkLayer(), server))
				continue
			}
			if network == nil || tcp == nil {
				collector.ObservePacket(metadata.CaptureLength, metadata.Length, false)
				continue
			}
			matched := packetMatchesServer(network, tcp, server)
			collector.ObservePacket(metadata.CaptureLength, metadata.Length, matched)
			if !matched {
				continue
			}
			if !trafficDetected {
				trafficDetected = true
				if notify != nil {
					notify(captureEventTraffic)
				}
			}
			assembler.AssembleWithContext(network.NetworkFlow(), tcp, captureContext{info: metadata.CaptureInfo})
			packetCount++
			if packetCount%10000 == 0 {
				assembler.FlushCloseOlderThan(latestCaptureTime.Add(-2 * time.Minute))
			}
		}
	}
}

func decodeNetworkTCP(packet gopacket.Packet, defragmenter *ip4defrag.IPv4Defragmenter, timestamp time.Time) (gopacket.NetworkLayer, *layers.TCP, bool, error) {
	network := packet.NetworkLayer()
	if ipv4, ok := network.(*layers.IPv4); ok && (ipv4.Flags&layers.IPv4MoreFragments != 0 || ipv4.FragOffset != 0) {
		defragmented, err := defragmenter.DefragIPv4WithTimestamp(ipv4, timestamp)
		if err != nil {
			return nil, nil, false, fmt.Errorf("defragment IPv4 packet: %w", err)
		}
		if defragmented == nil {
			return nil, nil, true, nil
		}
		tcp := &layers.TCP{}
		if err := tcp.DecodeFromBytes(defragmented.Payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, nil, false, fmt.Errorf("decode defragmented TCP packet: %w", err)
		}
		return defragmented, tcp, false, nil
	}
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return network, tcp, false, nil
}

func fragmentMatchesServer(network gopacket.NetworkLayer, server netip.AddrPort) bool {
	if network == nil {
		return false
	}
	flow := network.NetworkFlow()
	source, sourceErr := netip.ParseAddr(flow.Src().String())
	destination, destinationErr := netip.ParseAddr(flow.Dst().String())
	if sourceErr != nil || destinationErr != nil {
		return false
	}
	address := server.Addr().Unmap()
	return source.Unmap() == address || destination.Unmap() == address
}

func updateCaptureStatistics(handle captureHandle, collector *pgsql.Collector) {
	stats, err := handle.Stats()
	if err != nil {
		collector.AddCaptureStatisticsError()
		return
	}
	collector.SetKernelCaptureStatistics(stats.PacketsReceived, stats.PacketsDropped, stats.InterfaceDropped)
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

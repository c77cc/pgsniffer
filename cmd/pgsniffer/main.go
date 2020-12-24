package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/c77cc/pgsniffer/pkg/pgsql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var (
	_interface, filter         string
	help, verbose, listDevices bool
	topn                       int
)

func init() {
	flag.StringVar(&_interface, "i", "lo0", "the interface you want listen")
	flag.StringVar(&filter, "f", "tcp port 5432", "port and direction")
	flag.IntVar(&topn, "n", 50, "show top-n slowest sql")
	flag.BoolVar(&help, "h", false, "show this help")
	flag.BoolVar(&listDevices, "l", false, "list all interface and exit")
	flag.BoolVar(&verbose, "v", true, "output all sqls captured")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	if help {
		flag.Usage()
		printAllDevices()
		return
	}

	if listDevices {
		printAllDevices()
		return
	}

	pgsql.RunStats(verbose)

	streamPool := tcpassembly.NewStreamPool(pgsql.NewStreamFactory())
	assembler := tcpassembly.NewAssembler(streamPool)

	handle, _ := pcap.OpenLive(_interface, 65535, true, pcap.BlockForever)
	if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go waitForPackets(assembler, packetSource)
	waitForSignals(topn)
}

func printAllDevices() {
	ds, _ := pcap.FindAllDevs()
	if len(ds) < 1 {
		fmt.Println("Devices not found.")
		return
	}
	fmt.Println("INTERFACES:")
	for i := range ds {
		isLoopback := strings.Contains(strings.ToLower(ds[i].Name), `loopback`)
		if len(ds[i].Addresses) < 1 && !isLoopback {
			continue
		}
		fmt.Println(`Interface:`, ds[i].Name)
		fmt.Println(`Description:`, ds[i].Description)
		fmt.Println(`Addresses:`, ds[i].Addresses)
		fmt.Println(``)
	}
	return
}

func waitForPackets(assembler *tcpassembly.Assembler, packetSource *gopacket.PacketSource) {
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				fmt.Println("packet nil")
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				fmt.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

func waitForSignals(topn int) {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	for {
		_ = <-s
		pgsql.PrintStats(topn)
		pgsql.CloseStats()
		break
	}
}

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/c77cc/pgsniffer/pgsql"
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
	"github.com/tsg/gopacket/pcap"
	"github.com/tsg/gopacket/tcpassembly"
	"github.com/tsg/gopacket/tcpassembly/tcpreader"
)

type StreamFactory struct {
	pgsqls map[uint64]*pgsql.Pgsql
	mux    sync.RWMutex
}

type StreamHandler struct {
	r tcpreader.ReaderStream
}

var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, pgsql.MaxBufferSize) },
}

func (m *StreamHandler) run(cpgsql *pgsql.Pgsql) {
	var buf = []byte{}
	var tmpbuf = bufPool.Get().([]byte)
	defer bufPool.Put(tmpbuf)

	for {
		n, err := m.r.Read(tmpbuf)
		if err != nil {
			break
		}
		if n < 1 {
			continue
		}

		if len(buf) > 0 {
			buf = append(buf, tmpbuf[:n]...)
			if complete, _ := cpgsql.Parse(buf); complete {
				buf = []byte{}
			}
			continue
		}

		if complete, err := cpgsql.Parse(tmpbuf[:n]); err == nil && !complete {
			buf = append(buf, tmpbuf[:n]...)
		}
	}
}

func (f *StreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	s := &StreamHandler{r: tcpreader.NewReaderStream()}
	go s.run(f.pgsql(a.FastHash()))
	return &s.r
}

func (f *StreamFactory) pgsql(hash uint64) *pgsql.Pgsql {
	if p, found := f.pgsqls[hash]; found {
		return p
	}

	p := pgsql.NewPgsql()
	f.mux.Lock()
	f.pgsqls[hash] = p
	f.mux.Unlock()

	return f.pgsqls[hash]
}

func main() {
	var (
		_interface, filter string
		help, verbose, listDevices bool
		topn               int
	)

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

	streamFactory := &StreamFactory{pgsqls: make(map[uint64]*pgsql.Pgsql)}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
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
        fmt.Printf("%s\n%s\n%v\n\n", ds[i].Name, ds[i].Description, ds[i].Addresses)
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

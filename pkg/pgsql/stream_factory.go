package pgsql

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type StreamFactory struct {
	parsers map[uint64]*Parser
	mux     sync.RWMutex
}

type StreamHandler struct {
	r tcpreader.ReaderStream
}

var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, MaxBufferSize) },
}

func (m *StreamHandler) run(cpgsql *Parser) {
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

func (f *StreamFactory) pgsql(hash uint64) *Parser {
	if p, found := f.parsers[hash]; found {
		return p
	}

	p := NewParser()
	f.mux.Lock()
	f.parsers[hash] = p
	f.mux.Unlock()

	return f.parsers[hash]
}

func NewStreamFactory() *StreamFactory {
	streamFactory := &StreamFactory{parsers: make(map[uint64]*Parser)}
	return streamFactory
}

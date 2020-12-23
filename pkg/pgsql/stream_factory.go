package pgsql

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type StreamFactory struct {
	pgsqls map[uint64]*Pgsql
	mux    sync.RWMutex
}

type StreamHandler struct {
	r tcpreader.ReaderStream
}

var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, MaxBufferSize) },
}

func (m *StreamHandler) run(cpgsql *Pgsql) {
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

func (f *StreamFactory) pgsql(hash uint64) *Pgsql {
	if p, found := f.pgsqls[hash]; found {
		return p
	}

	p := NewPgsql()
	f.mux.Lock()
	f.pgsqls[hash] = p
	f.mux.Unlock()

	return f.pgsqls[hash]
}

func NewStreamFactory() *StreamFactory {
	streamFactory := &StreamFactory{pgsqls: make(map[uint64]*Pgsql)}
	return streamFactory
}

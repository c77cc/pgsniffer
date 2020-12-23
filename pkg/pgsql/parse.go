package pgsql

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type PgsqlMessage struct {
	Typ    byte
	Query  string
	Offset int
	Length int // Length = Packet_Len - 1

	RawData   []byte
	CreatedAt time.Time
	CostTime  time.Duration

	ErrorInfo     string
	ErrorCode     string
	ErrorSeverity string
}

func (pm *PgsqlMessage) hasError() bool {
	return len(pm.ErrorInfo) > 0 || len(pm.ErrorCode) > 0 || len(pm.ErrorSeverity) > 0
}

func (pm *PgsqlMessage) readType() (b byte) {
	if bs := pm.readBytes(1); len(bs) > 0 {
		return bs[0]
	}
	return
}

func (pm *PgsqlMessage) readLength() int {
	return int(pm.readInt32())
}

func (pm *PgsqlMessage) readBytes(size int) []byte {
	if len(pm.RawData[pm.Offset:]) < size {
		size = len(pm.RawData[pm.Offset:])
	}
	bs := pm.RawData[pm.Offset : pm.Offset+size]
	pm.Offset += size
	return bs
}

func (pm *PgsqlMessage) readInt16() int16 {
	i := readCount(pm.RawData[pm.Offset:])
	pm.Offset += 2
	return int16(i)
}

func (pm *PgsqlMessage) readInt32() int32 {
	i := readLength(pm.RawData[pm.Offset:])
	pm.Offset += 4
	return int32(i)
}

func (pm *PgsqlMessage) readNullTerString() (s string, err error) {
	s, err = readNullTerString(pm.RawData[pm.Offset:])
	if err == nil {
		pm.Offset += len(s)
	}
	return
}

func (pm *PgsqlMessage) readString(size int) (s string, err error) {
	s, err = pgsqlString(pm.RawData[pm.Offset:], size)
	if err == nil {
		pm.Offset += size
	}
	return
}

func (pm *PgsqlMessage) hasMoreData() bool {
	if len(pm.RawData[1:]) < pm.Length {
		return true
	}
	return false
}

func (pm *PgsqlMessage) readError() {
	off := 0
	buf := pm.RawData[pm.Offset:]
	for off < len(buf) {
		// read field type(byte1)
		typ := buf[off]
		if typ == 0 {
			break
		}

		// read field value(string)
		val, err := readNullTerString(buf[off+1:])
		if err != nil {
			log.Println("Failed to read the column field")
			break
		}
		off += len(val) + 1

		switch typ {
		case 'M':
			pm.ErrorInfo = val
		case 'C':
			pm.ErrorCode = val
		case 'S':
			pm.ErrorSeverity = val
		}
	}
	if pm.hasError() {
		pm.Offset += off
	}
}

type Pgsql struct {
	msgs []*PgsqlMessage
	mux  sync.RWMutex
}

var (
	errInvalidString = errors.New("invalid pgsql string")
	ignorePrefixQ    = []string{"BEGIN", "COMMIT", "DEALLOCATE"}
)

var (
	MaxBufferSize = 8 * 1024
)

func NewPgsql() *Pgsql {
	return &Pgsql{}
}

func (p *Pgsql) Parse(bytes []byte) (complete bool, err error) {
	if len(bytes) < 6 {
		err = fmt.Errorf("ignore")
		return
	}

	pmsg := &PgsqlMessage{RawData: bytes}
	_type := pmsg.readType()
	if valid := pgsqlValidType(_type); !valid {
		err = fmt.Errorf("type %v invalid", string(_type))
		return
	}
	//log.Printf("type: %v, len: %d", string(_type), len(bytes))

	pmsg.Typ = _type
	pmsg.CreatedAt = time.Now()
	pmsg.Length = pmsg.readLength()

	if pmsg.hasMoreData() {
		//log.Println("wait for more data")
		return
	}

	// 忽略异步SQL
	switch _type {
	case 'Q':
		p.parseSimpleQuery(pmsg)
	case 'T':
		p.parseRowDescription(pmsg)
	case 'I':
		p.parseEmptyQueryResponse(pmsg)
	case 'C':
		p.parseCommandComplete(pmsg)
	case 'Z':
		p.parseReadyForQuery(pmsg)
	case 'E':
		p.parseErrorResponse(pmsg)
	case 'S':
		p.parseParameterStatus(pmsg)
	case 'P':
		p.parseParse(pmsg)
	case '1':
		p.parseParseComplete(pmsg)
	case 'B':
		p.parseBind(pmsg)
	case '2':
		p.parseBindComplete(pmsg)
	default:
		//log.Println("Unknonw type:", string(_type))
	}
	complete = true
	return
}

func (p *Pgsql) parseSimpleQuery(pmsg *PgsqlMessage) {
	//log.Printf("offset: %d, length: %d, raw-data-len: %d\n", pmsg.Offset, pmsg.Length, len(pmsg.RawData) - 1)
	query, err := pmsg.readString(pmsg.Length - 4)
	//for i := range ignorePrefixQ {
	//    if strings.Index(query, ignorePrefixQ[i]) == 0 {
	//        log.Println("Ingore Q: ", query)
	//        return
	//    }
	//}
	if err != nil {
		log.Printf("data-total-len:%d, offset: %d, data-sub-len: %d\n", len(pmsg.RawData), pmsg.Offset, pmsg.Length)
		log.Println("failed to parse simple query,", err.Error(), string(pmsg.RawData))
		return
	}
	if len(query) < 1 {
		log.Printf("simple query empty, skiped, raw-data: %v\n", string(pmsg.RawData))
		return
	}
	pmsg.Query = query

	//logPgMsg("push pgsql msg to queue", pmsg)
	p.appendMsg(pmsg)
}

func (p *Pgsql) parseRowDescription(pmsg *PgsqlMessage) {
	// Ignore row desc msg.
	msg := p.cutTopMsg()
	if msg == nil {
		log.Println("cannot cut a pgsql msg 'T'.")
		return
	}
	msg.CostTime = time.Now().Sub(msg.CreatedAt)

	//logPgMsg("send pgsql msg to Receiver", msg)
	sqlReceiver <- msg
}

func (p *Pgsql) parseEmptyQueryResponse(pmsg *PgsqlMessage) {
}

func (p *Pgsql) parseCommandComplete(pmsg *PgsqlMessage) {
	msg := p.cutTopMsg()
	if msg == nil {
		log.Println("cannot cut a pgsql msg 'C'.")
		return
	}
	msg.CostTime = time.Now().Sub(msg.CreatedAt)

	//logPgMsg("send pgsql msg to Receiver", msg)
	sqlReceiver <- msg
}

func (p *Pgsql) parseReadyForQuery(pmsg *PgsqlMessage) {
}

func (p *Pgsql) parseErrorResponse(pmsg *PgsqlMessage) {
	pmsg.readError()

	msg := p.cutTopMsg()
	if msg == nil {
		log.Println("cannot cut a pgsql msg 'E'.")
		return
	}
	msg.CostTime = time.Now().Sub(msg.CreatedAt)
	msg.ErrorInfo = pmsg.ErrorInfo
	msg.ErrorCode = pmsg.ErrorCode
	msg.ErrorSeverity = pmsg.ErrorSeverity

	//logPgMsg("send pgsql msg to Receiver", msg)
	sqlReceiver <- msg
}

func (p *Pgsql) parseParameterStatus(pmsg *PgsqlMessage) {
	msg := p.cutTopMsg()
	if msg == nil {
		log.Println("cannot cut a pgsql msg 'C'.")
		return
	}
	msg.CostTime = time.Now().Sub(msg.CreatedAt)

	//logPgMsg("send pgsql msg to Receiver", msg)
	sqlReceiver <- msg
}

func (p *Pgsql) parseParse(pmsg *PgsqlMessage) {
	// The name of the destination prepared statement (an empty string selects the unnamed prepared statement).
	_, err := pmsg.readNullTerString()
	if err != nil {
		log.Println(err.Error())
		return
	}

	query, err := pmsg.readNullTerString()
	if err != nil {
		log.Println("failed to parse parse sql,", err.Error(), string(pmsg.RawData))
		return
	}
	if len(query) < 1 {
		log.Printf("parse sql empty, skiped, raw-data: %v\n", string(pmsg.RawData))
		return
	}
	pmsg.Query = query

	//logPgMsg("push pgsql msg to queue", pmsg)
	p.appendMsg(pmsg)
}

func (p *Pgsql) parseParseComplete(pmsg *PgsqlMessage) {
	msg := p.cutTopMsg()
	if msg == nil {
		log.Println("cannot cut a pgsql msg '1'.")
		return
	}
	msg.CostTime = time.Now().Sub(msg.CreatedAt)

	//logPgMsg("send pgsql msg to Receiver", msg)
	sqlReceiver <- msg
}

func (p *Pgsql) parseBind(pmsg *PgsqlMessage) {
	_, err := pmsg.readNullTerString()
	if err != nil {
		log.Println(err.Error())
		return
	}
	_, err = pmsg.readNullTerString()
	if err != nil {
		log.Println(err.Error())
		return
	}

	// The number of parameter format codes that follow (denoted C below).
	pn := int(pmsg.readInt16())

	// The parameter format codes. Each must presently be zero (text) or one (binary).
	pmsg.Offset += 2 * pn

	// The number of parameter values that follow (possibly zero). This must match the number of parameters needed by the query.
	pc := int(pmsg.readInt16())

	paramters := []string{}
	for i := 0; i < pc; i++ {
		le := int(pmsg.readInt32())
		paramter := pmsg.readBytes(le)
		paramters = append(paramters, string(paramter))
	}

	if err != nil {
		log.Println("failed to parse bind sql,", err.Error(), string(pmsg.RawData))
		return
	}
	//if len(paramters) < 1 {
	//	log.Printf("bind sql empty, skiped, raw-data: %v\n", string(pmsg.RawData))
	//	return
	//}
	// NOTE: May be Query is empty.
	pmsg.Query = strings.Join(paramters, ", ")

	//logPgMsg("push pgsql msg to queue", pmsg)
	p.appendMsg(pmsg)
}

func (p *Pgsql) parseBindComplete(pmsg *PgsqlMessage) {
	// NOTE: try parse error
	pmsg.Offset += 10
	pmsg.readError()

	msg := p.cutTopMsg()
	if msg == nil {
		log.Println("cannot cut a pgsql msg '2'.")
		return
	}
	msg.CostTime = time.Now().Sub(msg.CreatedAt)
	msg.ErrorInfo = pmsg.ErrorInfo
	msg.ErrorCode = pmsg.ErrorCode
	msg.ErrorSeverity = pmsg.ErrorSeverity

	//logPgMsg("send pgsql msg to Receiver", msg)
	sqlReceiver <- msg
}

func (p *Pgsql) appendMsg(msg *PgsqlMessage) {
	p.mux.Lock()
	p.msgs = append(p.msgs, msg)
	p.mux.Unlock()
}

func (p *Pgsql) cutTopMsg() (msg *PgsqlMessage) {
	if len(p.msgs) < 1 {
		return
	}
	p.mux.Lock()
	msg = p.msgs[0]
	p.msgs = append(p.msgs[:0], p.msgs[1:]...)
	p.mux.Unlock()
	return
}

func logPgMsg(prefix string, msg *PgsqlMessage) {
	//send pgsql msg to Receiver
	bstr := prefix + ", msg: %v, errInfo: %s, errCode: %s, errSever: %s\n"
	if len(msg.Query) > 0 {
		log.Printf(bstr, msg.Query, msg.ErrorInfo, msg.ErrorCode, msg.ErrorSeverity)
		return
	}
	log.Printf(prefix+", raw-msg: %v\n", string(msg.RawData))
}

func readLength(b []byte) int {
	return int(Bytes_Ntohl(b))
}

func readCount(b []byte) int {
	return int(Bytes_Ntohs(b))
}

func pgsqlString(b []byte, sz int) (string, error) {
	if sz == 0 {
		return "", nil
	}

	if b[sz-1] != 0 {
		return "", errInvalidString
	}

	return string(b[:sz-1]), nil
}

func pgsqlValidType(t byte) bool {
	switch t {
	case '1', '2', '3',
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K',
		'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z',
		'c', 'd', 'f', 'n', 'p', 's', 't':
		return true
	default:
		return false
	}
}

package pgsql

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion3 = 196608
	sslRequestCode   = 80877103
	gssRequestCode   = 80877104
	cancelRequest    = 80877102

	DefaultMaxFrameSize = 16 << 20
	maxPreparedObjects  = 4096
	maxPendingRequests  = 4096
)

var (
	errFrameTooLarge = errors.New("postgresql frame exceeds configured limit")
	errInvalidFrame  = errors.New("invalid postgresql frame")
)

// Direction identifies which side of a PostgreSQL connection produced bytes.
type Direction uint8

const (
	ClientToServer Direction = iota
	ServerToClient
)

// Metadata contains dimensions discovered from the startup packet and capture.
type Metadata struct {
	User            string `json:"user,omitempty"`
	Database        string `json:"database,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
	Client          string `json:"client,omitempty"`
	ClientAddress   string `json:"client_address,omitempty"`
	ClientPort      uint16 `json:"client_port,omitempty"`
}

// Command describes one CommandComplete response associated with a query.
type Command struct {
	Tag          string `json:"tag"`
	RowsAffected uint64 `json:"rows_affected,omitempty"`
}

// Event is one completed query observed on the wire.
type Event struct {
	Query             string        `json:"query"`
	StartedAt         time.Time     `json:"started_at"`
	FinishedAt        time.Time     `json:"finished_at"`
	Duration          time.Duration `json:"duration"`
	ErrorCode         string        `json:"error_code,omitempty"`
	ErrorInfo         string        `json:"error,omitempty"`
	Severity          string        `json:"severity,omitempty"`
	Metadata          Metadata      `json:"metadata"`
	Commands          []Command     `json:"commands,omitempty"`
	TransactionStatus string        `json:"transaction_status_before,omitempty"`
	Encrypted         bool          `json:"encrypted,omitempty"`
	Incomplete        bool          `json:"incomplete,omitempty"`
	IncompleteReason  string        `json:"incomplete_reason,omitempty"`
}

type timedBuffer struct {
	data      []byte
	startedAt time.Time
}

type portal struct {
	query string
}

type pendingRequest struct {
	query             string
	startedAt         time.Time
	metadata          Metadata
	simple            bool
	commands          []Command
	transactionStatus string
	syncGroup         uint64
	errorCode         string
	errorInfo         string
	severity          string
}

// Session incrementally decodes both halves of one PostgreSQL TCP connection.
// Feed is safe to call from multiple assemblers.
type Session struct {
	mu sync.Mutex

	client timedBuffer
	server timedBuffer

	maxFrameSize int
	emit         func(Event)
	metadata     Metadata

	startupDone      bool
	sslPending       bool
	encrypted        bool
	encryptedEmitted bool

	statements        map[string]string
	portals           map[string]portal
	pending           []pendingRequest
	transactionStatus string
	frontendSyncGroup uint64
	backendSyncGroup  uint64
	extendedError     bool
}

func NewSession(maxFrameSize int, metadata Metadata, emit func(Event)) *Session {
	if maxFrameSize <= 0 {
		maxFrameSize = DefaultMaxFrameSize
	}
	if emit == nil {
		emit = func(Event) {}
	}
	return &Session{
		maxFrameSize: maxFrameSize,
		emit:         emit,
		metadata:     metadata,
		statements:   make(map[string]string),
		portals:      make(map[string]portal),
	}
}

// Feed adds reassembled stream bytes. A non-nil error means the current half
// stream was malformed and its buffered bytes were discarded.
func (s *Session) Feed(direction Direction, data []byte, at time.Time) error {
	if len(data) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.encrypted {
		return nil
	}

	buffer := &s.client
	if direction == ServerToClient {
		buffer = &s.server
	}
	oldLen := len(buffer.data)
	if oldLen == 0 {
		buffer.startedAt = at
	}
	buffer.data = append(buffer.data, data...)

	for len(buffer.data) > 0 {
		consumed, err := s.consume(direction, buffer.data, buffer.startedAt)
		if err != nil {
			buffer.data = buffer.data[:0]
			buffer.startedAt = time.Time{}
			return err
		}
		if consumed == 0 {
			if len(buffer.data) > s.maxFrameSize {
				buffer.data = buffer.data[:0]
				buffer.startedAt = time.Time{}
				return errFrameTooLarge
			}
			return nil
		}

		buffer.data = buffer.data[consumed:]
		if len(buffer.data) == 0 {
			buffer.startedAt = time.Time{}
			return nil
		}
		if consumed >= oldLen {
			buffer.startedAt = at
			oldLen = 0
		} else {
			oldLen -= consumed
		}
	}
	return nil
}

func (s *Session) consume(direction Direction, data []byte, at time.Time) (int, error) {
	if s.encrypted {
		return len(data), nil
	}
	if direction == ClientToServer && !s.startupDone {
		return s.consumeStartup(data, at)
	}
	if direction == ServerToClient && s.sslPending {
		response := data[0]
		if response != 'N' && response != 'S' && response != 'G' {
			return 0, fmt.Errorf("%w: invalid SSL response %q", errInvalidFrame, response)
		}
		s.sslPending = false
		if response == 'S' || response == 'G' {
			s.encrypted = true
			s.emitEncrypted(at)
		}
		return 1, nil
	}

	if len(data) < 5 {
		return 0, nil
	}
	length := int(binary.BigEndian.Uint32(data[1:5]))
	if length < 4 {
		return 0, fmt.Errorf("%w: message length %d", errInvalidFrame, length)
	}
	if length > s.maxFrameSize {
		return 0, errFrameTooLarge
	}
	total := length + 1
	if len(data) < total {
		return 0, nil
	}

	payload := data[5:total]
	if direction == ClientToServer {
		s.handleFrontend(data[0], payload, at)
	} else {
		s.handleBackend(data[0], payload, at)
	}
	return total, nil
}

func (s *Session) consumeStartup(data []byte, at time.Time) (int, error) {
	// Captures may begin after the connection was established. A plausible
	// typed frontend message switches directly into regular framing mode.
	if len(data) >= 5 && isFrontendType(data[0]) {
		length := int(binary.BigEndian.Uint32(data[1:5]))
		if length >= 4 && length <= s.maxFrameSize {
			s.startupDone = true
			return s.consume(ClientToServer, data, at)
		}
	}

	if len(data) < 4 {
		return 0, nil
	}
	length := int(binary.BigEndian.Uint32(data[:4]))
	if length < 8 {
		return 0, fmt.Errorf("%w: startup length %d", errInvalidFrame, length)
	}
	if length > s.maxFrameSize {
		return 0, errFrameTooLarge
	}
	if len(data) < length {
		return 0, nil
	}

	code := binary.BigEndian.Uint32(data[4:8])
	switch code {
	case sslRequestCode, gssRequestCode:
		s.sslPending = true
	case cancelRequest:
		// CancelRequest is a complete, standalone startup-style packet.
	case protocolVersion3:
		s.startupDone = true
		s.parseStartupParameters(data[8:length])
	default:
		return 0, fmt.Errorf("%w: unsupported startup code %d", errInvalidFrame, code)
	}
	return length, nil
}

func (s *Session) parseStartupParameters(payload []byte) {
	values := make([]string, 0, 8)
	for len(payload) > 0 && payload[0] != 0 {
		value, rest, ok := readCString(payload)
		if !ok {
			return
		}
		values = append(values, value)
		payload = rest
	}
	for i := 0; i+1 < len(values); i += 2 {
		switch values[i] {
		case "user":
			s.metadata.User = values[i+1]
		case "database":
			s.metadata.Database = values[i+1]
		case "application_name":
			s.metadata.ApplicationName = values[i+1]
		}
	}
	if s.metadata.Database == "" {
		s.metadata.Database = s.metadata.User
	}
}

func (s *Session) handleFrontend(typ byte, payload []byte, at time.Time) {
	switch typ {
	case 'Q':
		query, _, ok := readCString(payload)
		if ok && query != "" {
			s.appendPending(pendingRequest{
				query: query, startedAt: at, metadata: s.metadata, simple: true,
				transactionStatus: s.transactionStatus,
			})
		}
	case 'P':
		name, rest, ok := readCString(payload)
		if !ok {
			return
		}
		query, _, ok := readCString(rest)
		if ok && query != "" {
			if _, found := s.statements[name]; found || len(s.statements) < maxPreparedObjects {
				s.statements[name] = query
			}
		}
	case 'B':
		portalName, rest, ok := readCString(payload)
		if !ok {
			return
		}
		statementName, _, ok := readCString(rest)
		if !ok {
			return
		}
		if query, found := s.statements[statementName]; found {
			if _, exists := s.portals[portalName]; exists || len(s.portals) < maxPreparedObjects {
				s.portals[portalName] = portal{query: query}
			}
		}
	case 'E':
		portalName, _, ok := readCString(payload)
		if !ok {
			return
		}
		if bound, found := s.portals[portalName]; found && bound.query != "" {
			s.appendPending(pendingRequest{
				query: bound.query, startedAt: at, metadata: s.metadata,
				transactionStatus: s.transactionStatus, syncGroup: s.frontendSyncGroup,
			})
		}
	case 'S':
		s.frontendSyncGroup++
	case 'C':
		if len(payload) < 2 {
			return
		}
		name, _, ok := readCString(payload[1:])
		if !ok {
			return
		}
		if payload[0] == 'S' {
			delete(s.statements, name)
		} else if payload[0] == 'P' {
			delete(s.portals, name)
		}
	case 'X':
		s.finishAll(at, "client_terminated")
	}
}

func (s *Session) appendPending(request pendingRequest) {
	if len(s.pending) >= maxPendingRequests {
		s.finishFirst(request.startedAt, "", "", "", "pending_limit")
	}
	s.pending = append(s.pending, request)
}

func (s *Session) handleBackend(typ byte, payload []byte, at time.Time) {
	switch typ {
	case 'S': // ParameterStatus can change application/session identity.
		name, rest, ok := readCString(payload)
		if !ok {
			return
		}
		value, _, ok := readCString(rest)
		if !ok {
			return
		}
		switch name {
		case "application_name":
			s.metadata.ApplicationName = value
		case "session_authorization":
			s.metadata.User = value
		}
	case 'C': // CommandComplete
		if len(s.pending) > 0 {
			s.pending[0].commands = append(s.pending[0].commands, parseCommand(payload))
		}
		if len(s.pending) > 0 && !s.pending[0].simple {
			s.finishFirst(at, "", "", "", "")
		}
	case 's': // PortalSuspended completes this Execute, but not the portal.
		if len(s.pending) > 0 && !s.pending[0].simple {
			s.pending[0].commands = append(s.pending[0].commands, Command{Tag: "PORTAL SUSPENDED"})
			s.finishFirst(at, "", "", "", "")
		}
	case 'E':
		code, message, severity := parseError(payload)
		if len(s.pending) > 0 && s.pending[0].simple {
			s.pending[0].errorCode = code
			s.pending[0].errorInfo = message
			s.pending[0].severity = severity
			break
		}
		if len(s.pending) > 0 {
			s.extendedError = true
		}
		s.finishFirst(at, code, message, severity, "")
	case 'I': // EmptyQueryResponse
		if len(s.pending) > 0 && !s.pending[0].simple {
			s.finishFirst(at, "", "", "", "")
		}
	case 'Z': // ReadyForQuery is the boundary for one Simple Query message.
		if len(s.pending) > 0 && s.pending[0].simple {
			s.finishFirst(at, "", "", "", "")
		}
		if s.backendSyncGroup < s.frontendSyncGroup {
			if s.extendedError {
				for len(s.pending) > 0 && !s.pending[0].simple && s.pending[0].syncGroup == s.backendSyncGroup {
					s.finishFirst(at, "", "", "", "aborted_after_error")
				}
				s.extendedError = false
			}
			s.backendSyncGroup++
		}
		if len(payload) > 0 {
			s.transactionStatus = transactionStatusName(payload[0])
		}
	}
}

func (s *Session) finishFirst(at time.Time, code, message, severity, incompleteReason string) {
	if len(s.pending) == 0 {
		return
	}
	pending := s.pending[0]
	s.pending = s.pending[1:]
	if code == "" && message == "" && severity == "" {
		code, message, severity = pending.errorCode, pending.errorInfo, pending.severity
	}
	duration := at.Sub(pending.startedAt)
	if duration < 0 {
		duration = 0
	}
	s.emit(Event{
		Query: pending.query, StartedAt: pending.startedAt, FinishedAt: at,
		Duration: duration, ErrorCode: code, ErrorInfo: message,
		Severity: severity, Metadata: pending.metadata, Commands: pending.commands,
		TransactionStatus: pending.transactionStatus,
		Incomplete:        incompleteReason != "", IncompleteReason: incompleteReason,
	})
}

func (s *Session) finishAll(at time.Time, incompleteReason string) {
	for len(s.pending) > 0 {
		s.finishFirst(at, "", "", "", incompleteReason)
	}
}

func (s *Session) emitEncrypted(at time.Time) {
	if s.encryptedEmitted {
		return
	}
	s.encryptedEmitted = true
	s.emit(Event{FinishedAt: at, Metadata: s.metadata, Encrypted: true})
}

// Gap records that TCP reassembly skipped bytes and resets buffered protocol
// fragments so an affected request is never reported as complete.
func (s *Session) Gap(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishAll(at, "tcp_gap")
	s.client = timedBuffer{}
	s.server = timedBuffer{}
}

// Abort reports pending requests as incomplete after malformed protocol data.
func (s *Session) Abort(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishAll(at, "protocol_error")
	s.client = timedBuffer{}
	s.server = timedBuffer{}
}

// Close reports requests that were still in flight when reassembly ended.
func (s *Session) Close(at time.Time) {
	s.CloseWithReason(at, "connection_closed")
}

func (s *Session) CloseWithReason(at time.Time, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishAll(at, reason)
}

func parseCommand(payload []byte) Command {
	value, _, ok := readCString(payload)
	if !ok {
		value = string(payload)
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return Command{}
	}
	command := Command{Tag: strings.ToUpper(value)}
	baseTag := strings.ToUpper(fields[0])
	if rows, err := strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil && commandHasRowCount(baseTag) {
		command.Tag = baseTag
		command.RowsAffected = rows
	}
	return command
}

func commandHasRowCount(tag string) bool {
	switch tag {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "MOVE", "FETCH", "COPY":
		return true
	default:
		return false
	}
}

func transactionStatusName(status byte) string {
	switch status {
	case 'I':
		return "idle"
	case 'T':
		return "in_transaction"
	case 'E':
		return "failed_transaction"
	default:
		return "unknown"
	}
}

func readCString(data []byte) (value string, rest []byte, ok bool) {
	for i, b := range data {
		if b == 0 {
			return string(data[:i]), data[i+1:], true
		}
	}
	return "", data, false
}

func parseError(payload []byte) (code, message, severity string) {
	for len(payload) > 0 && payload[0] != 0 {
		field := payload[0]
		value, rest, ok := readCString(payload[1:])
		if !ok {
			break
		}
		switch field {
		case 'C':
			code = value
		case 'M':
			message = value
		case 'S', 'V':
			severity = value
		}
		payload = rest
	}
	return code, message, severity
}

func isFrontendType(typ byte) bool {
	switch typ {
	case 'B', 'C', 'D', 'E', 'F', 'H', 'P', 'Q', 'S', 'X', 'c', 'd', 'f', 'p':
		return true
	default:
		return false
	}
}

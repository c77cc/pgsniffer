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
	maxFrontendOps      = maxPendingRequests * 8
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
	FirstResponse     time.Duration `json:"first_response"`
	ResponseTransfer  time.Duration `json:"response_transfer"`
	PhaseObserved     bool          `json:"phase_observed"`
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
	id                uint64
	query             string
	startedAt         time.Time
	firstResponseAt   time.Time
	metadata          Metadata
	simple            bool
	commands          []Command
	transactionStatus string
	syncGroup         uint64
	errorCode         string
	errorInfo         string
	severity          string
}

type operationKind byte

const (
	operationParse operationKind = iota
	operationBind
	operationDescribe
	operationExecute
	operationClose
)

type frontendOperation struct {
	kind              operationKind
	query             string
	startedAt         time.Time
	metadata          Metadata
	transactionStatus string
	syncGroup         uint64
	requestID         uint64
	objectType        byte
	objectName        string
	mutated           bool
	previousQuery     string
	previousFound     bool
	previousPortal    portal
	previousPortalSet bool
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
	operations        []frontendOperation
	nextRequestID     uint64
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
	return s.FeedSpan(direction, data, at, at)
}

// FeedSpan adds reassembled stream bytes with timestamps for their first and
// last bytes. This lets message timing use completion timestamps when a frame
// spans multiple captured TCP packets.
func (s *Session) FeedSpan(direction Direction, data []byte, startedAt, completedAt time.Time) error {
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
		buffer.startedAt = startedAt
	}
	buffer.data = append(buffer.data, data...)

	for len(buffer.data) > 0 {
		consumed, err := s.consume(direction, buffer.data, buffer.startedAt, completedAt)
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
			buffer.startedAt = startedAt
			oldLen = 0
		} else {
			oldLen -= consumed
		}
	}
	return nil
}

func (s *Session) consume(direction Direction, data []byte, startedAt, completedAt time.Time) (int, error) {
	if s.encrypted {
		return len(data), nil
	}
	if direction == ClientToServer && !s.startupDone {
		return s.consumeStartup(data, startedAt, completedAt)
	}
	if direction == ServerToClient && s.sslPending {
		response := data[0]
		if response != 'N' && response != 'S' && response != 'G' {
			return 0, fmt.Errorf("%w: invalid SSL response %q", errInvalidFrame, response)
		}
		s.sslPending = false
		if response == 'S' || response == 'G' {
			s.encrypted = true
			s.emitEncrypted(completedAt)
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
		s.handleFrontend(data[0], payload, completedAt)
	} else {
		s.handleBackend(data[0], payload, startedAt, completedAt)
	}
	return total, nil
}

func (s *Session) consumeStartup(data []byte, startedAt, completedAt time.Time) (int, error) {
	// Captures may begin after the connection was established. A plausible
	// typed frontend message switches directly into regular framing mode.
	if len(data) >= 5 && isFrontendType(data[0]) {
		length := int(binary.BigEndian.Uint32(data[1:5]))
		if length >= 4 && length <= s.maxFrameSize {
			s.startupDone = true
			return s.consume(ClientToServer, data, startedAt, completedAt)
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
		if ok {
			previousQuery, previousFound := s.statements[name]
			previousPortal, previousPortalSet := s.portals[""]
			// PostgreSQL closes the unnamed portal when the unnamed
			// statement is replaced, even before a new Bind arrives.
			if name == "" {
				delete(s.portals, "")
			}
			mutated := false
			if previousFound || len(s.statements) < maxPreparedObjects {
				s.statements[name] = query
				mutated = true
			}
			s.appendOperation(frontendOperation{
				kind: operationParse, query: query, objectName: name, mutated: mutated,
				previousQuery: previousQuery, previousFound: previousFound,
				previousPortal: previousPortal, previousPortalSet: previousPortalSet,
			}, at)
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
		query, statementFound := s.statements[statementName]
		previousPortal, previousFound := s.portals[portalName]
		mutated := false
		if statementFound && (previousFound || len(s.portals) < maxPreparedObjects) {
			s.portals[portalName] = portal{query: query}
			mutated = true
		}
		s.appendOperation(frontendOperation{
			kind: operationBind, query: query, objectName: portalName, mutated: mutated,
			previousQuery: previousPortal.query, previousFound: previousFound,
		}, at)
	case 'D':
		if len(payload) < 2 {
			return
		}
		name, _, ok := readCString(payload[1:])
		if !ok {
			return
		}
		var query string
		switch payload[0] {
		case 'S':
			query = s.statements[name]
		case 'P':
			query = s.portals[name].query
		default:
			return
		}
		s.appendOperation(frontendOperation{kind: operationDescribe, query: query}, at)
	case 'E':
		portalName, _, ok := readCString(payload)
		if !ok {
			return
		}
		var requestID uint64
		if bound, found := s.portals[portalName]; found && bound.query != "" {
			requestID = s.appendPending(pendingRequest{
				query: bound.query, startedAt: at, metadata: s.metadata,
				transactionStatus: s.transactionStatus, syncGroup: s.frontendSyncGroup,
			})
		}
		query := ""
		if bound, found := s.portals[portalName]; found {
			query = bound.query
		}
		s.appendOperation(frontendOperation{kind: operationExecute, query: query, requestID: requestID}, at)
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
		var query string
		var found bool
		if payload[0] == 'S' {
			query, found = s.statements[name]
			delete(s.statements, name)
		} else if payload[0] == 'P' {
			var value portal
			value, found = s.portals[name]
			query = value.query
			delete(s.portals, name)
		} else {
			return
		}
		s.appendOperation(frontendOperation{
			kind: operationClose, query: query, objectType: payload[0], objectName: name, mutated: found,
			previousQuery: query, previousFound: found,
		}, at)
	case 'X':
		s.finishAll(at, "client_terminated")
	}
}

func (s *Session) appendPending(request pendingRequest) uint64 {
	if len(s.pending) >= maxPendingRequests {
		s.finishFirst(request.startedAt, "", "", "", "pending_limit")
	}
	s.nextRequestID++
	request.id = s.nextRequestID
	s.pending = append(s.pending, request)
	return request.id
}

func (s *Session) appendOperation(operation frontendOperation, at time.Time) {
	if len(s.operations) >= maxFrontendOps {
		s.finishAll(at, "operation_limit")
		for index := len(s.operations) - 1; index >= 0; index-- {
			s.rollbackOperation(s.operations[index])
		}
		s.operations = nil
	}
	operation.startedAt = at
	operation.metadata = s.metadata
	operation.transactionStatus = s.transactionStatus
	operation.syncGroup = s.frontendSyncGroup
	s.operations = append(s.operations, operation)
}

func (s *Session) handleBackend(typ byte, payload []byte, startedAt, completedAt time.Time) {
	s.markQueryResponse(typ, startedAt)
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
		if len(s.pending) > 0 && s.pending[0].simple {
			s.pending[0].commands = append(s.pending[0].commands, parseCommand(payload))
		} else if operation, ok := s.consumeOperation(operationExecute); ok {
			s.addCommand(operation.requestID, parseCommand(payload))
			s.finishRequest(operation.requestID, completedAt, "", "", "", "")
		}
	case 's': // PortalSuspended completes this Execute, but not the portal.
		if operation, ok := s.consumeOperation(operationExecute); ok {
			s.addCommand(operation.requestID, Command{Tag: "PORTAL SUSPENDED"})
			s.finishRequest(operation.requestID, completedAt, "", "", "", "")
		}
	case 'E':
		code, message, severity := parseError(payload)
		if len(s.pending) > 0 && s.pending[0].simple {
			s.pending[0].errorCode = code
			s.pending[0].errorInfo = message
			s.pending[0].severity = severity
			break
		}
		s.extendedError = true
		if len(s.operations) > 0 && s.operations[0].syncGroup == s.backendSyncGroup {
			operation := s.operations[0]
			requestID := operation.requestID
			if requestID == 0 && (operation.kind == operationParse || operation.kind == operationBind) {
				requestID = s.findExecuteRequest(operation.syncGroup, operation.query)
			}
			if requestID != 0 {
				s.markFirstResponse(requestID, startedAt)
				s.finishRequest(requestID, completedAt, code, message, severity, "")
			} else if operation.query != "" && (operation.kind == operationParse || operation.kind == operationBind) {
				s.emitOperationError(operation, startedAt, completedAt, code, message, severity)
			}
			break
		}
	case 'I': // EmptyQueryResponse
		if operation, ok := s.consumeOperation(operationExecute); ok {
			s.finishRequest(operation.requestID, completedAt, "", "", "", "")
		}
	case '1': // ParseComplete
		s.consumeOperation(operationParse)
	case '2': // BindComplete
		s.consumeOperation(operationBind)
	case '3': // CloseComplete
		s.consumeOperation(operationClose)
	case 'T', 'n': // RowDescription or NoData completes Describe.
		if len(s.operations) > 0 && s.operations[0].syncGroup == s.backendSyncGroup && s.operations[0].kind == operationDescribe {
			s.operations = s.operations[1:]
		}
	case 'Z': // ReadyForQuery is the boundary for one Simple Query message.
		if len(s.pending) > 0 && s.pending[0].simple {
			s.finishFirst(completedAt, "", "", "", "")
		}
		if s.backendSyncGroup < s.frontendSyncGroup {
			reason := "sync_without_completion"
			if s.extendedError {
				reason = "aborted_after_error"
			}
			s.finishSyncGroup(s.backendSyncGroup, completedAt, reason)
			s.dropSyncGroupOperations(s.backendSyncGroup, true)
			s.extendedError = false
			s.backendSyncGroup++
		}
		if len(payload) > 0 {
			s.transactionStatus = transactionStatusName(payload[0])
		}
	}
}

func (s *Session) markQueryResponse(typ byte, at time.Time) {
	if !isQueryResponse(typ) {
		return
	}
	if len(s.pending) > 0 && s.pending[0].simple {
		s.markFirstResponse(s.pending[0].id, at)
		return
	}
	if typ == 'E' || len(s.operations) == 0 {
		return
	}
	operation := s.operations[0]
	if operation.syncGroup == s.backendSyncGroup && operation.kind == operationExecute {
		s.markFirstResponse(operation.requestID, at)
	}
}

func isQueryResponse(typ byte) bool {
	switch typ {
	case 'T', 'D', 'C', 'E', 'I', 'G', 'H', 'W', 'd', 'c', 's', 'n', 'Z':
		return true
	default:
		return false
	}
}

func (s *Session) consumeOperation(kind operationKind) (frontendOperation, bool) {
	if len(s.operations) == 0 || s.operations[0].syncGroup != s.backendSyncGroup || s.operations[0].kind != kind {
		return frontendOperation{}, false
	}
	operation := s.operations[0]
	s.operations = s.operations[1:]
	return operation, true
}

func (s *Session) findExecuteRequest(syncGroup uint64, query string) uint64 {
	for _, operation := range s.operations {
		if operation.syncGroup != syncGroup {
			break
		}
		if operation.kind == operationExecute && operation.requestID != 0 && (query == "" || operation.query == query) {
			return operation.requestID
		}
	}
	return 0
}

func (s *Session) addCommand(requestID uint64, command Command) {
	for index := range s.pending {
		if s.pending[index].id == requestID {
			s.pending[index].commands = append(s.pending[index].commands, command)
			return
		}
	}
}

func (s *Session) markFirstResponse(requestID uint64, at time.Time) {
	if requestID == 0 {
		return
	}
	for index := range s.pending {
		if s.pending[index].id == requestID && s.pending[index].firstResponseAt.IsZero() {
			s.pending[index].firstResponseAt = at
			return
		}
	}
}

func (s *Session) finishRequest(requestID uint64, at time.Time, code, message, severity, incompleteReason string) {
	if requestID == 0 {
		return
	}
	for index := range s.pending {
		if s.pending[index].id == requestID {
			s.finishAt(index, at, code, message, severity, incompleteReason)
			return
		}
	}
}

func (s *Session) finishSyncGroup(group uint64, at time.Time, reason string) {
	for index := 0; index < len(s.pending); {
		if !s.pending[index].simple && s.pending[index].syncGroup == group {
			s.finishAt(index, at, "", "", "", reason)
			continue
		}
		index++
	}
}

func (s *Session) dropSyncGroupOperations(group uint64, rollback bool) {
	count := 0
	for count < len(s.operations) && s.operations[count].syncGroup == group {
		count++
	}
	if rollback {
		for index := count - 1; index >= 0; index-- {
			s.rollbackOperation(s.operations[index])
		}
	}
	s.operations = s.operations[count:]
}

func (s *Session) rollbackOperation(operation frontendOperation) {
	if operation.kind == operationParse && operation.objectName == "" {
		if operation.previousPortalSet {
			s.portals[""] = operation.previousPortal
		} else {
			delete(s.portals, "")
		}
	}
	if !operation.mutated {
		return
	}
	restore := func(values map[string]string) {
		if operation.previousFound {
			values[operation.objectName] = operation.previousQuery
		} else {
			delete(values, operation.objectName)
		}
	}
	switch operation.kind {
	case operationParse:
		restore(s.statements)
	case operationBind:
		if operation.previousFound {
			s.portals[operation.objectName] = portal{query: operation.previousQuery}
		} else {
			delete(s.portals, operation.objectName)
		}
	case operationClose:
		if operation.objectType == 'S' {
			restore(s.statements)
		} else if operation.objectType == 'P' && operation.previousFound {
			s.portals[operation.objectName] = portal{query: operation.previousQuery}
		}
	}
}

func (s *Session) emitOperationError(operation frontendOperation, firstResponseAt, finishedAt time.Time, code, message, severity string) {
	duration, firstResponse, responseTransfer := splitDuration(operation.startedAt, firstResponseAt, finishedAt)
	s.emit(Event{
		Query: operation.query, StartedAt: operation.startedAt, FinishedAt: finishedAt,
		Duration: duration, ErrorCode: code, ErrorInfo: message, Severity: severity,
		FirstResponse: firstResponse, ResponseTransfer: responseTransfer, PhaseObserved: true,
		Metadata: operation.metadata, TransactionStatus: operation.transactionStatus,
	})
}

func (s *Session) finishFirst(at time.Time, code, message, severity, incompleteReason string) {
	if len(s.pending) == 0 {
		return
	}
	s.finishAt(0, at, code, message, severity, incompleteReason)
}

func (s *Session) finishAt(index int, at time.Time, code, message, severity, incompleteReason string) {
	pending := s.pending[index]
	copy(s.pending[index:], s.pending[index+1:])
	s.pending = s.pending[:len(s.pending)-1]
	if code == "" && message == "" && severity == "" {
		code, message, severity = pending.errorCode, pending.errorInfo, pending.severity
	}
	duration := at.Sub(pending.startedAt)
	if duration < 0 {
		duration = 0
	}
	firstResponse, responseTransfer := time.Duration(0), time.Duration(0)
	phaseObserved := incompleteReason == "" && !pending.firstResponseAt.IsZero()
	if phaseObserved {
		duration, firstResponse, responseTransfer = splitDuration(pending.startedAt, pending.firstResponseAt, at)
	}
	s.emit(Event{
		Query: pending.query, StartedAt: pending.startedAt, FinishedAt: at,
		Duration: duration, ErrorCode: code, ErrorInfo: message,
		FirstResponse: firstResponse, ResponseTransfer: responseTransfer, PhaseObserved: phaseObserved,
		Severity: severity, Metadata: pending.metadata, Commands: pending.commands,
		TransactionStatus: pending.transactionStatus,
		Incomplete:        incompleteReason != "", IncompleteReason: incompleteReason,
	})
}

func splitDuration(startedAt, firstResponseAt, finishedAt time.Time) (time.Duration, time.Duration, time.Duration) {
	if finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	if firstResponseAt.Before(startedAt) {
		firstResponseAt = startedAt
	}
	if firstResponseAt.After(finishedAt) {
		firstResponseAt = finishedAt
	}
	return finishedAt.Sub(startedAt), firstResponseAt.Sub(startedAt), finishedAt.Sub(firstResponseAt)
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
	s.resetProtocolObjects()
}

// Abort reports pending requests as incomplete after malformed protocol data.
func (s *Session) Abort(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishAll(at, "protocol_error")
	s.client = timedBuffer{}
	s.server = timedBuffer{}
	s.resetProtocolObjects()
}

func (s *Session) resetProtocolObjects() {
	s.operations = nil
	s.statements = make(map[string]string)
	s.portals = make(map[string]portal)
	s.backendSyncGroup = s.frontendSyncGroup
	s.extendedError = false
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

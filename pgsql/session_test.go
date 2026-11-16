package pgsql

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSessionSimpleQuerySplitAndCoalescedResponses(t *testing.T) {
	var events []Event
	session := NewSession(1024, Metadata{Client: "127.0.0.1:40000"}, func(event Event) {
		events = append(events, event)
	})

	startup := startupPacket(map[string]string{
		"user": "alice", "database": "app", "application_name": "psql",
	})
	t0 := time.Unix(100, 0)
	if err := session.Feed(ClientToServer, startup[:3], t0); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ClientToServer, startup[3:], t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	queryAt := t0.Add(10 * time.Millisecond)
	query := message('Q', cstring("SELECT 42"))
	if err := session.Feed(ClientToServer, query[:2], queryAt); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ClientToServer, query[2:], queryAt.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	finishedAt := t0.Add(30 * time.Millisecond)
	responses := append(message('T', nil), message('C', cstring("SELECT 1"))...)
	responses = append(responses, message('Z', []byte{'I'})...)
	if err := session.Feed(ServerToClient, responses, finishedAt); err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	event := events[0]
	if event.Query != "SELECT 42" {
		t.Fatalf("query = %q", event.Query)
	}
	if event.Duration != 20*time.Millisecond {
		t.Fatalf("duration = %s, want 20ms", event.Duration)
	}
	if event.Metadata.User != "alice" || event.Metadata.Database != "app" || event.Metadata.ApplicationName != "psql" {
		t.Fatalf("metadata = %+v", event.Metadata)
	}
}

func TestSessionExtendedQueryMeasuresExecute(t *testing.T) {
	var events []Event
	session := NewSession(4096, Metadata{}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(200, 0)

	frontend := message('P', append(append(cstring("get_user"), cstring("SELECT * FROM users WHERE id = $1")...), 0, 0))
	frontend = append(frontend, message('B', append(cstring("portal_1"), cstring("get_user")...))...)
	executePayload := append(cstring("portal_1"), 0, 0, 0, 0)
	frontend = append(frontend, message('E', executePayload)...)
	if err := session.Feed(ClientToServer, frontend, t0); err != nil {
		t.Fatal(err)
	}

	backend := append(message('1', nil), message('2', nil)...)
	backend = append(backend, message('C', cstring("SELECT 1"))...)
	if err := session.Feed(ServerToClient, backend, t0.Add(7*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Query != "SELECT * FROM users WHERE id = $1" {
		t.Fatalf("query = %q", events[0].Query)
	}
	if events[0].Duration != 7*time.Millisecond {
		t.Fatalf("duration = %s", events[0].Duration)
	}
}

func TestSessionErrorResponse(t *testing.T) {
	var events []Event
	session := NewSession(1024, Metadata{}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(300, 0)

	if err := session.Feed(ClientToServer, message('Q', cstring("SELECT missing")), t0); err != nil {
		t.Fatal(err)
	}
	errorPayload := append([]byte{'S'}, cstring("ERROR")...)
	errorPayload = append(errorPayload, 'C')
	errorPayload = append(errorPayload, cstring("42703")...)
	errorPayload = append(errorPayload, 'M')
	errorPayload = append(errorPayload, cstring("column does not exist")...)
	errorPayload = append(errorPayload, 0)
	if err := session.Feed(ServerToClient, message('E', errorPayload), t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("simple query finished before ReadyForQuery: %+v", events)
	}
	if err := session.Feed(ServerToClient, message('Z', []byte{'I'}), t0.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].ErrorCode != "42703" || events[0].ErrorInfo != "column does not exist" || events[0].Severity != "ERROR" {
		t.Fatalf("error event = %+v", events[0])
	}
}

func TestSessionPipelinedSimpleErrorDoesNotFinishNextQuery(t *testing.T) {
	var events []Event
	session := NewSession(1024, Metadata{}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(325, 0)
	frontend := append(message('Q', cstring("SELECT 1 / 0")), message('Q', cstring("SELECT 2"))...)
	if err := session.Feed(ClientToServer, frontend, t0); err != nil {
		t.Fatal(err)
	}
	errorPayload := append([]byte{'C'}, cstring("22012")...)
	errorPayload = append(errorPayload, 0)
	firstResponse := append(message('E', errorPayload), message('Z', []byte{'I'})...)
	if err := session.Feed(ServerToClient, firstResponse, t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Query != "SELECT 1 / 0" || events[0].ErrorCode != "22012" {
		t.Fatalf("events after first response = %+v", events)
	}
	secondResponse := append(message('C', cstring("SELECT 1")), message('Z', []byte{'I'})...)
	if err := session.Feed(ServerToClient, secondResponse, t0.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Query != "SELECT 2" || events[1].ErrorCode != "" {
		t.Fatalf("events after second response = %+v", events)
	}
}

func TestSessionCapturesCommandRowsAndTransactionContext(t *testing.T) {
	var events []Event
	session := NewSession(4096, Metadata{ClientAddress: "10.0.0.2"}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(350, 0)
	if err := session.Feed(ClientToServer, startupPacket(map[string]string{
		"user": "alice", "application_name": "orders-api",
	}), t0); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ServerToClient, message('Z', []byte{'I'}), t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ClientToServer, message('Q', cstring("UPDATE orders SET state = 'paid'; SELECT 1")), t0.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	responses := append(message('C', cstring("UPDATE 3")), message('C', cstring("SELECT 1"))...)
	responses = append(responses, message('Z', []byte{'T'})...)
	if err := session.Feed(ServerToClient, responses, t0.Add(8*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	event := events[0]
	if event.Metadata.Database != "alice" || event.Metadata.ApplicationName != "orders-api" {
		t.Fatalf("metadata = %+v", event.Metadata)
	}
	if event.TransactionStatus != "idle" {
		t.Fatalf("transaction status = %q", event.TransactionStatus)
	}
	if len(event.Commands) != 2 || event.Commands[0] != (Command{Tag: "UPDATE", RowsAffected: 3}) || event.Commands[1] != (Command{Tag: "SELECT", RowsAffected: 1}) {
		t.Fatalf("commands = %+v", event.Commands)
	}

	parameterStatus := append(cstring("application_name"), cstring("orders-worker")...)
	if err := session.Feed(ServerToClient, message('S', parameterStatus), t0.Add(8*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ClientToServer, message('Q', cstring("ROLLBACK")), t0.Add(9*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ServerToClient, message('C', cstring("ROLLBACK")), t0.Add(10*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ServerToClient, message('Z', []byte{'I'}), t0.Add(11*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].TransactionStatus != "in_transaction" || events[1].Metadata.ApplicationName != "orders-worker" {
		t.Fatalf("second event = %+v", events)
	}
}

func TestSessionMarksTCPGapIncomplete(t *testing.T) {
	var events []Event
	session := NewSession(1024, Metadata{}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(375, 0)
	if err := session.Feed(ClientToServer, message('Q', cstring("SELECT pg_sleep(1)")), t0); err != nil {
		t.Fatal(err)
	}
	session.Gap(t0.Add(time.Millisecond))
	if len(events) != 1 || !events[0].Incomplete || events[0].IncompleteReason != "tcp_gap" {
		t.Fatalf("events = %+v", events)
	}
}

func TestSessionMarksSkippedPipelineQueriesAfterError(t *testing.T) {
	var events []Event
	session := NewSession(4096, Metadata{}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(390, 0)
	var frontend []byte
	for index, query := range []string{"SELECT 1 / 0", "SELECT 2"} {
		name := "statement_" + strconv.Itoa(index)
		portal := "portal_" + strconv.Itoa(index)
		frontend = append(frontend, message('P', append(append(cstring(name), cstring(query)...), 0, 0))...)
		frontend = append(frontend, message('B', append(cstring(portal), cstring(name)...))...)
		frontend = append(frontend, message('E', append(cstring(portal), 0, 0, 0, 0))...)
	}
	frontend = append(frontend, message('S', nil)...)
	if err := session.Feed(ClientToServer, frontend, t0); err != nil {
		t.Fatal(err)
	}
	errorPayload := append([]byte{'C'}, cstring("22012")...)
	errorPayload = append(errorPayload, 0)
	backend := append(message('E', errorPayload), message('Z', []byte{'I'})...)
	if err := session.Feed(ServerToClient, backend, t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ErrorCode != "22012" || events[1].IncompleteReason != "aborted_after_error" {
		t.Fatalf("events = %+v", events)
	}
}

func TestSessionDetectsTLS(t *testing.T) {
	var events []Event
	session := NewSession(1024, Metadata{Client: "db-client"}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(400, 0)

	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request, 8)
	binary.BigEndian.PutUint32(request[4:], sslRequestCode)
	if err := session.Feed(ClientToServer, request, t0); err != nil {
		t.Fatal(err)
	}
	serverData := []byte{'S', 0x16, 0x03, 0x03, 0, 10}
	if err := session.Feed(ServerToClient, serverData, t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.Feed(ClientToServer, []byte{0x16, 0x03, 0x03, 0, 10}, t0.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 || !events[0].Encrypted {
		t.Fatalf("events = %+v", events)
	}
}

func TestSessionRejectsOversizedFrame(t *testing.T) {
	session := NewSession(64, Metadata{}, nil)
	frame := make([]byte, 5)
	frame[0] = 'Q'
	binary.BigEndian.PutUint32(frame[1:], 65)
	if err := session.Feed(ClientToServer, frame, time.Now()); err == nil {
		t.Fatal("expected oversized frame error")
	}
}

func TestSessionCloseMarksPendingQueryIncomplete(t *testing.T) {
	var events []Event
	session := NewSession(1024, Metadata{}, func(event Event) { events = append(events, event) })
	t0 := time.Unix(500, 0)
	if err := session.Feed(ClientToServer, message('Q', cstring("SELECT pg_sleep(1)")), t0); err != nil {
		t.Fatal(err)
	}
	session.Close(t0.Add(time.Second))
	if len(events) != 1 || !events[0].Incomplete {
		t.Fatalf("events = %+v", events)
	}
}

func FuzzSessionFeed(f *testing.F) {
	f.Add([]byte{'Q', 0, 0, 0, 5, 0}, uint8(ClientToServer))
	f.Add([]byte{0, 0, 0, 8, 4, 210, 22, 47}, uint8(ClientToServer))
	f.Add([]byte{'E', 0, 0, 0, 5, 0}, uint8(ServerToClient))
	f.Fuzz(func(t *testing.T, data []byte, rawDirection uint8) {
		direction := Direction(rawDirection % 2)
		session := NewSession(4096, Metadata{}, nil)
		_ = session.Feed(direction, data, time.Unix(1, 0))
	})
}

func message(typ byte, payload []byte) []byte {
	result := make([]byte, 5+len(payload))
	result[0] = typ
	binary.BigEndian.PutUint32(result[1:], uint32(4+len(payload)))
	copy(result[5:], payload)
	return result
}

func cstring(value string) []byte {
	return append([]byte(value), 0)
}

func startupPacket(parameters map[string]string) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, protocolVersion3)
	for _, key := range []string{"user", "database", "application_name"} {
		if value := parameters[key]; value != "" {
			payload = append(payload, cstring(key)...)
			payload = append(payload, cstring(value)...)
		}
	}
	payload = append(payload, 0)
	result := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(result, uint32(len(result)))
	copy(result[4:], payload)
	return result
}

func TestReadCStringDoesNotRetainTerminator(t *testing.T) {
	value, rest, ok := readCString([]byte("hello\x00world"))
	if !ok || value != "hello" || string(rest) != "world" || strings.ContainsRune(value, 0) {
		t.Fatalf("value=%q rest=%q ok=%v", value, rest, ok)
	}
}

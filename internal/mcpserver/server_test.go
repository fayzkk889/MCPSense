package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func testConnection(t *testing.T, handler Handler) (*json.Encoder, *json.Decoder) {
	t.Helper()
	input, inputWriter := io.Pipe()
	output, outputWriter := io.Pipe()
	server := Server{Version: "test", Tools: []Tool{{Name: "inspect", InputSchema: map[string]interface{}{"type": "object"}}}, Call: handler}
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), input, outputWriter); _ = outputWriter.Close() }()
	t.Cleanup(func() {
		_ = inputWriter.Close()
		_ = output.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop on EOF")
		}
	})
	return json.NewEncoder(inputWriter), json.NewDecoder(output)
}

func exchange(t *testing.T, encoder *json.Encoder, decoder *json.Decoder, request interface{}) map[string]interface{} {
	t.Helper()
	if err := encoder.Encode(request); err != nil {
		t.Fatal(err)
	}
	var result map[string]interface{}
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func initializeTest(t *testing.T, encoder *json.Encoder, decoder *json.Decoder) {
	t.Helper()
	response := exchange(t, encoder, decoder, map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{}, "clientInfo": map[string]string{"name": "test", "version": "1"}}})
	if response["error"] != nil {
		t.Fatal(response)
	}
	if err := encoder.Encode(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleErrorsAndToolResults(t *testing.T) {
	encoder, decoder := testConnection(t, func(_ context.Context, _ string, _ json.RawMessage) Result {
		return TextResult("finding", map[string]interface{}{"findings": 1})
	})
	response := exchange(t, encoder, decoder, map[string]interface{}{"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
	if response["error"] == nil {
		t.Fatal("uninitialized tool access succeeded")
	}
	initializeTest(t, encoder, decoder)
	for _, method := range []string{"ping", "tools/list"} {
		response = exchange(t, encoder, decoder, map[string]interface{}{"jsonrpc": "2.0", "id": method, "method": method})
		if response["error"] != nil || response["id"] != method {
			t.Fatal(response)
		}
	}
	response = exchange(t, encoder, decoder, map[string]interface{}{"jsonrpc": "2.0", "id": "scan", "method": "tools/call", "params": map[string]interface{}{"name": "inspect", "arguments": map[string]interface{}{}}})
	result := response["result"].(map[string]interface{})
	if result["isError"] != nil || result["structuredContent"] == nil {
		t.Fatal(response)
	}
	for _, request := range []map[string]interface{}{
		{"jsonrpc": "2.0", "id": 2, "method": "unknown"},
		{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]interface{}{"name": "missing"}},
		{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]interface{}{"name": "inspect", "arguments": []string{"flags"}}},
		{"jsonrpc": "2.0", "id": true, "method": "ping"},
		{"jsonrpc": "2.0", "id": nil, "method": "ping"},
	} {
		if response := exchange(t, encoder, decoder, request); response["error"] == nil {
			t.Fatal(response)
		}
	}
}

func TestModernRequestsAreStatelessAndVersioned(t *testing.T) {
	encoder, decoder := testConnection(t, func(context.Context, string, json.RawMessage) Result {
		return TextResult("complete", map[string]bool{"completed": true})
	})
	meta := map[string]interface{}{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]interface{}{}}
	request := map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": map[string]interface{}{"_meta": meta}}
	response := exchange(t, encoder, decoder, request)
	result, ok := response["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" || result["_meta"] == nil {
		t.Fatal(response)
	}
	request["method"] = "tools/call"
	request["params"] = map[string]interface{}{"_meta": meta, "name": "inspect"}
	if response = exchange(t, encoder, decoder, request); response["error"] != nil {
		t.Fatal(response)
	}
	delete(meta, "io.modelcontextprotocol/clientCapabilities")
	if response = exchange(t, encoder, decoder, request); response["error"] == nil {
		t.Fatal("request inherited capabilities")
	}
	meta["io.modelcontextprotocol/clientCapabilities"] = map[string]interface{}{}
	meta["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
	response = exchange(t, encoder, decoder, request)
	fault, ok := response["error"].(map[string]interface{})
	if !ok || fault["code"] != float64(-32022) || fault["data"] == nil {
		t.Fatal(response)
	}
	request["params"] = map[string]interface{}{"name": "inspect"}
	if response = exchange(t, encoder, decoder, request); response["error"] == nil {
		t.Fatal("modern request initialized a legacy session")
	}
}

func TestContextCancellationInterruptsIdleInput(t *testing.T) {
	input, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{}).Serve(ctx, input, io.Discard) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle stdin blocked process cancellation")
	}
}

func TestCancellationAndBusyCalls(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	encoder, decoder := testConnection(t, func(ctx context.Context, _ string, _ json.RawMessage) Result {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return TextResult("cancelled", nil)
	})
	initializeTest(t, encoder, decoder)
	request := map[string]interface{}{"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": map[string]interface{}{"name": "inspect"}}
	if err := encoder.Encode(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("tool did not start")
	}
	request["id"] = 12
	if response := exchange(t, encoder, decoder, request); response["error"] == nil {
		t.Fatal("concurrent operation was not bounded")
	}
	if err := encoder.Encode(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]interface{}{"requestId": 11}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("tool did not cancel")
	}
	response := exchange(t, encoder, decoder, map[string]interface{}{"jsonrpc": "2.0", "id": 13, "method": "ping"})
	if response["id"] != float64(13) {
		t.Fatal("cancelled operation emitted a normal success response", response)
	}
}

func TestMalformedAndOversizedMessages(t *testing.T) {
	server := Server{}
	var out strings.Builder
	if err := server.Serve(context.Background(), strings.NewReader("{broken}\n[]\n"), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), `"error"`) != 2 {
		t.Fatal(out.String())
	}
	if err := server.Serve(context.Background(), strings.NewReader(strings.Repeat("x", MaxMessageBytes+1)), io.Discard); err == nil {
		t.Fatal("oversized message accepted")
	}
}

func TestAppNegotiationAndResourceBoundary(t *testing.T) {
	encoder, decoder := testConnection(t, func(context.Context, string, json.RawMessage) Result { return TextResult("ok", nil) })
	request := map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{
		"protocolVersion": "2025-11-25", "clientInfo": map[string]string{"name": "app-host", "version": "1"},
		"capabilities": map[string]interface{}{"extensions": map[string]interface{}{"io.modelcontextprotocol/ui": map[string]interface{}{"mimeTypes": []string{ReportMIME}}}},
	}}
	if result := exchange(t, encoder, decoder, request); result["error"] != nil {
		t.Fatal(result)
	}
	if err := encoder.Encode(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatal(err)
	}
	result := exchange(t, encoder, decoder, map[string]interface{}{"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": map[string]string{"uri": ReportURI}})
	data, _ := json.Marshal(result)
	if !strings.Contains(string(data), "MCPSense findings") || !strings.Contains(string(data), ReportMIME) {
		t.Fatal("missing embedded view")
	}
	result = exchange(t, encoder, decoder, map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": map[string]string{"uri": "file:///private"}})
	if result["error"] == nil {
		t.Fatal("arbitrary resource path accepted")
	}
}

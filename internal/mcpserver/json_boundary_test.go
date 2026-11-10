package mcpserver

import (
	"context"
	"encoding/json"
	"testing"
)

func TestAmbiguousRequestsNeverReachHandler(t *testing.T) {
	calls := 0
	encoder, decoder := testConnection(t, func(context.Context, string, json.RawMessage) Result { calls++; return TextResult("unexpected", nil) })
	initializeTest(t, encoder, decoder)
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":2,"Method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","Method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","paramſ":{"name":"inspect","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"Name":"inspect","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect","arguments":{"x":1,"x":2}}}`,
	} {
		response := exchange(t, encoder, decoder, json.RawMessage(raw))
		if response["error"] == nil {
			t.Fatalf("ambiguous request accepted: %s => %+v", raw, response)
		}
	}
	if calls != 0 {
		t.Fatal("handler executed for malformed input")
	}
	response := exchange(t, encoder, decoder, json.RawMessage(`{"jsonrpc":"2.0","id":3,"method":"ping"}`))
	if response["error"] != nil {
		t.Fatal("invalid input broke subsequent valid requests")
	}
}

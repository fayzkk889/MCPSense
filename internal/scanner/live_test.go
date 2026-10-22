package scanner

import (
	"encoding/json"
	"github.com/fayzkk889/MCPSense/internal/models"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLegacyHTTPPaginationAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		requests := 0
		client := &http.Client{Transport: fakeTransport(func(req *http.Request) (*http.Response, error) {
			requests++
			var q models.MCPJSONRPCRequest
			_ = json.NewDecoder(req.Body).Decode(&q)
			result := `{}`
			switch q.Method {
			case "server/discover":
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"not found"}}`)), Header: make(http.Header)}, nil
			case "initialize":
				result = `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"test","version":"1"}}`
			case "tools/list":
				if q.ID == 2 {
					result = `{"tools":[],"nextCursor":"page2"}`
				} else {
					result = `{"tools":[{"name":"read","description":"Read notes","inputSchema":{"type":"object"}}]}`
				}
			}
			data, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": json.RawMessage(result)})
			if fail && q.Method == "tools/list" {
				data = []byte(`{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"synthetic"}}`)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
		})}
		m, err := fetchManifestViaHTTP(client, "https://synthetic.invalid")
		if fail {
			if err == nil {
				t.Fatal("list failure accepted")
			}
		} else if err != nil || len(m.Tools) != 1 || requests != 5 {
			t.Fatalf("legacy pagination: m=%+v err=%v requests=%d", m, err, requests)
		}
	}
}
func TestOversizedRPCResponse(t *testing.T) {
	c := &http.Client{Transport: fakeTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxRPCMessage+1))), Header: make(http.Header)}, nil
	})}
	if _, err := fetchManifestViaHTTP(c, "https://synthetic.invalid"); err == nil {
		t.Fatal("oversized response accepted")
	}
}

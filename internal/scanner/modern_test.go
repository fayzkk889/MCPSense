package scanner

import (
	"encoding/json"
	"github.com/fayzkk889/MCPSense/internal/models"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestModernHTTPMetadata(t *testing.T) {
	methods := []string{}
	c := &http.Client{Transport: fakeTransport(func(req *http.Request) (*http.Response, error) {
		var q models.MCPJSONRPCRequest
		if err := json.NewDecoder(req.Body).Decode(&q); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, q.Method)
		if req.Header.Get("MCP-Protocol-Version") != "2026-07-28" || req.Header.Get("Mcp-Method") != q.Method || req.Header.Get("Mcp-Session-Id") != "" {
			t.Fatal("incorrect modern headers")
		}
		params, ok := q.Params.(map[string]interface{})
		if !ok {
			t.Fatal("missing params")
		}
		meta, ok := params["_meta"].(map[string]interface{})
		if !ok || meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" || meta["io.modelcontextprotocol/clientCapabilities"] == nil {
			t.Fatal("missing modern metadata")
		}
		result := `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"modern","version":"1"}}}`
		if q.Method == "tools/list" {
			result = `{"resultType":"complete","tools":[]}`
		}
		data, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": json.RawMessage(result)})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})}
	m, err := fetchManifestViaHTTP(c, "https://synthetic.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if m.ProtocolVersion != "2026-07-28" || m.Name != "modern" || strings.Join(methods, ",") != "server/discover,tools/list" {
		t.Fatalf("unexpected modern flow: %+v %v", m, methods)
	}
}

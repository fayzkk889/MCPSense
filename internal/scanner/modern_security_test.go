package scanner

import (
	"github.com/fayzkk889/MCPSense/internal/models"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSSEFramingAndIncompleteStreams(t *testing.T) {
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{": keepalive\r\n\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\n" + "data: \"result\":{\"resultType\":\"complete\"}}\n\n", true},
		{"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n", false},
		{"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n\n", false},
		{strings.Repeat(":comment\n", maxRPCMessage/9+1), false},
	} {
		resp := &http.Response{Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(tc.body))}
		r, err := readHTTPRPC(resp, 1)
		if tc.ok && (err != nil || r == nil) {
			t.Fatalf("valid SSE failed: %v", err)
		}
		if !tc.ok && err == nil {
			t.Fatal("incomplete stream accepted")
		}
	}
}
func TestModernErrorsNeverBlindlyDowngrade(t *testing.T) {
	for _, body := range []string{`{"resultType":"input_required","supportedVersions":["2026-07-28"],"capabilities":{}}`, `{"resultType":"complete","supportedVersions":["2099-01-01"],"capabilities":{}}`} {
		calls := 0
		_, err := negotiateManifest(func(q models.MCPJSONRPCRequest) (*models.MCPJSONRPCResponse, error) {
			calls++
			return &models.MCPJSONRPCResponse{Result: []byte(body)}, nil
		}, func() error { t.Fatal("notification during modern flow"); return nil }, "auto", func() { t.Fatal("unsafe legacy downgrade") })
		if err == nil || calls != 1 {
			t.Fatalf("invalid modern result accepted: %v", err)
		}
	}
}

package scanner

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/models"
	"io"
	"net/http"
	"strings"
)

type rpcFailure struct {
	Code, Status int
	Data         json.RawMessage
}

func (e *rpcFailure) Error() string { return fmt.Sprintf("MCP JSON-RPC error %d", e.Code) }
func modernCall(call rpcCall) rpcCall {
	return func(q models.MCPJSONRPCRequest) (*models.MCPJSONRPCResponse, error) {
		p := map[string]interface{}{}
		if q.Params != nil {
			b, _ := json.Marshal(q.Params)
			if json.Unmarshal(b, &p) != nil {
				return nil, fmt.Errorf("invalid modern request params")
			}
		}
		p["_meta"] = map[string]interface{}{"io.modelcontextprotocol/protocolVersion": modernProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]interface{}{}, "io.modelcontextprotocol/clientInfo": models.MCPInfo{Name: "mcpsense", Version: "dev"}}
		q.Params = p
		r, err := call(q)
		if err != nil {
			return nil, err
		}
		var result struct {
			ResultType string `json:"resultType"`
		}
		if json.Unmarshal(r.Result, &result) != nil || result.ResultType != "complete" {
			return nil, fmt.Errorf("modern discovery did not return a complete result")
		}
		return r, nil
	}
}
func negotiateManifest(call rpcCall, notify rpcNotify, policy string, legacy func()) (*models.MCPManifest, error) {
	if policy == "legacy" {
		legacy()
		return legacyManifest(call, notify)
	}
	if policy != "" && policy != "auto" && policy != "modern" {
		return nil, fmt.Errorf("invalid protocol policy")
	}
	mc := modernCall(call)
	r, err := mc(models.MCPJSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "server/discover"})
	if err != nil {
		var failure *rpcFailure
		if policy != "modern" && errors.As(err, &failure) {
			fallback := failure.Code == -32601 && (failure.Status == 0 || failure.Status == 200 || failure.Status == 404)
			if failure.Code == -32022 {
				var data struct {
					Supported []string `json:"supported"`
				}
				if json.Unmarshal(failure.Data, &data) == nil {
					for _, v := range data.Supported {
						if v == defaultProtocolVersion {
							fallback = true
						}
					}
				}
			}
			if fallback {
				legacy()
				return legacyManifest(call, notify)
			}
		}
		return nil, fmt.Errorf("modern discovery failed (use --protocol legacy only for an authorized legacy peer): %w", err)
	}
	var d struct {
		Supported    []string                   `json:"supportedVersions"`
		Capabilities map[string]json.RawMessage `json:"capabilities"`
		Instructions string                     `json:"instructions"`
		Meta         map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(r.Result, &d) != nil || d.Capabilities == nil {
		return nil, fmt.Errorf("invalid discovery metadata")
	}
	supported := false
	for _, v := range d.Supported {
		if v == modernProtocolVersion {
			supported = true
		}
	}
	if !supported {
		return nil, fmt.Errorf("server does not advertise a supported modern protocol")
	}
	var info models.MCPInfo
	if raw, ok := d.Meta["io.modelcontextprotocol/serverInfo"]; ok {
		if json.Unmarshal(raw, &info) != nil {
			return nil, fmt.Errorf("invalid server identity metadata")
		}
	}
	m := &models.MCPManifest{Name: info.Name, Version: info.Version, ProtocolVersion: modernProtocolVersion, Instructions: d.Instructions}
	return listManifest(mc, m, d.Capabilities)
}
func readHTTPRPC(resp *http.Response, id int) (*models.MCPJSONRPCResponse, error) {
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCMessage+1))
		if err != nil {
			return nil, fmt.Errorf("MCP response read failed")
		}
		if len(data) > maxRPCMessage {
			return nil, fmt.Errorf("MCP response exceeds size limit")
		}
		return decodeRPC(data, id)
	}
	// Bound the entire response, including comments, notifications and event framing.
	limited := &io.LimitedReader{R: resp.Body, N: maxRPCMessage + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxRPCMessage)
	var data []string
	dispatch := func() (*models.MCPJSONRPCResponse, error) {
		raw := []byte(strings.Join(data, "\n"))
		data = nil
		var envelope map[string]json.RawMessage
		if json.Unmarshal(raw, &envelope) != nil {
			return nil, fmt.Errorf("invalid SSE JSON")
		}
		if _, ok := envelope["method"]; ok {
			if _, hasID := envelope["id"]; hasID {
				return nil, fmt.Errorf("server requests are unsupported during metadata discovery")
			}
			return nil, nil
		}
		return decodeRPC(raw, id)
	}
	for scanner.Scan() {
		if limited.N <= 0 {
			return nil, fmt.Errorf("MCP SSE exceeds size limit")
		}
		line := scanner.Text()
		if line == "" && len(data) > 0 {
			r, err := dispatch()
			if err != nil || r != nil {
				return r, err
			}
		}
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if scanner.Err() != nil || limited.N <= 0 {
		return nil, fmt.Errorf("MCP SSE read failed or exceeds limit")
	}
	if len(data) > 0 {
		r, err := dispatch()
		if err != nil || r != nil {
			return r, err
		}
	}
	return nil, fmt.Errorf("MCP SSE ended without a response")
}

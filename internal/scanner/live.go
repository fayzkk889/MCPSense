package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/models"
	"io"
	"net/http"
	"os"
	"strings"
)

const defaultProtocolVersion = "2025-11-25"
const modernProtocolVersion = "2026-07-28"
const maxRPCMessage = 2 << 20
const maxListPages = 64

type rpcCall func(models.MCPJSONRPCRequest) (*models.MCPJSONRPCResponse, error)
type rpcNotify func() error

func (s *Scanner) scanLive(target string, ctx *checks.ScanContext) error {
	if s.opts.Offline {
		return fmt.Errorf("offline policy prohibits live scanning")
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return s.scanLiveSSE(target, ctx)
	}
	if !s.opts.AllowExec {
		return fmt.Errorf("local server execution requires --allow-exec")
	}
	return s.scanLiveStdio(target, ctx)
}
func (s *Scanner) scanLiveSSE(target string, ctx *checks.ScanContext) error {
	client, err := liveClient(target, s.opts.AllowPrivateNetwork)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(s.opts.Context, s.opts.Timeout)
	defer cancel()
	m, err := fetchHTTPProtocolContext(client, target, s.opts.Protocol, runCtx)
	if err != nil {
		return fmt.Errorf("live HTTP discovery failed: %w", err)
	}
	ctx.Manifest = m
	return nil
}
func fetchManifestViaHTTP(client *http.Client, target string) (*models.MCPManifest, error) {
	return tryFetchManifestFromURL(client, target)
}
func tryFetchManifestFromURL(client *http.Client, target string) (*models.MCPManifest, error) {
	return fetchHTTPProtocol(client, target, "auto")
}
func fetchHTTPProtocol(client *http.Client, target, policy string) (*models.MCPManifest, error) {
	return fetchHTTPProtocolContext(client, target, policy, context.Background())
}
func fetchHTTPProtocolContext(client *http.Client, target, policy string, runCtx context.Context) (*models.MCPManifest, error) {
	session := ""
	protocol := modernProtocolVersion
	if policy == "legacy" {
		protocol = defaultProtocolVersion
	}
	post := func(v interface{}) (*http.Response, error) {
		body, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(runCtx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("invalid MCP endpoint")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", protocol)
		if q, ok := v.(models.MCPJSONRPCRequest); ok {
			req.Header.Set("Mcp-Method", q.Method)
		}
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("MCP HTTP transport failed")
		}
		if v, ok := v.(models.MCPJSONRPCRequest); ok && v.Method == "initialize" {
			session = resp.Header.Get("Mcp-Session-Id")
		}
		return resp, nil
	}
	call := func(req models.MCPJSONRPCRequest) (*models.MCPJSONRPCResponse, error) {
		resp, err := post(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		r, err := readHTTPRPC(resp, req.ID)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var failure *rpcFailure
			if errors.As(err, &failure) {
				failure.Status = resp.StatusCode
				return nil, failure
			}
			return nil, fmt.Errorf("MCP HTTP status %d", resp.StatusCode)
		}
		if err == nil && req.Method == "initialize" {
			var init struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			if json.Unmarshal(r.Result, &init) == nil {
				protocol = init.ProtocolVersion
			}
		}
		return r, err
	}
	notify := func() error {
		resp, err := post(models.MCPJSONRPCNotification{JSONRPC: "2.0", Method: "notifications/initialized"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("initialized notification HTTP status %d", resp.StatusCode)
		}
		return nil
	}
	return negotiateManifest(call, notify, policy, func() { protocol = defaultProtocolVersion; session = "" })
}
func decodeRPC(data []byte, id int) (*models.MCPJSONRPCResponse, error) {
	var r models.MCPJSONRPCResponse
	if json.Unmarshal(data, &r) != nil {
		return nil, fmt.Errorf("invalid MCP JSON response")
	}
	if r.JSONRPC != "2.0" || r.ID != id {
		return nil, fmt.Errorf("MCP response version or request ID mismatch")
	}
	if r.Error != nil {
		if len(r.Result) > 0 {
			return nil, fmt.Errorf("ambiguous JSON-RPC result and error")
		}
		return nil, &rpcFailure{Code: r.Error.Code, Data: r.Error.Data}
	}
	if len(r.Result) == 0 || bytes.Equal(bytes.TrimSpace(r.Result), []byte("null")) {
		return nil, fmt.Errorf("MCP response is missing a result")
	}
	if bytes.TrimSpace(r.Result)[0] != '{' {
		return nil, fmt.Errorf("MCP result must be an object")
	}
	return &r, nil
}
func legacyManifest(call rpcCall, notify rpcNotify) (*models.MCPManifest, error) {
	r, err := call(models.MCPJSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: models.MCPInitializeRequest{ProtocolVersion: defaultProtocolVersion, Capabilities: map[string]interface{}{}, ClientInfo: models.MCPInfo{Name: "mcpsense", Version: "dev"}}})
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var init struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ServerInfo      models.MCPInfo             `json:"serverInfo"`
		Instructions    string                     `json:"instructions"`
	}
	if json.Unmarshal(r.Result, &init) != nil || init.Capabilities == nil || init.ServerInfo.Name == "" {
		return nil, fmt.Errorf("invalid initialize result")
	}
	switch init.ProtocolVersion {
	case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
	default:
		return nil, fmt.Errorf("unsupported negotiated legacy protocol")
	}
	if err := notify(); err != nil {
		return nil, fmt.Errorf("initialized notification: %w", err)
	}
	m := &models.MCPManifest{Name: init.ServerInfo.Name, Version: init.ServerInfo.Version, ProtocolVersion: init.ProtocolVersion, Instructions: init.Instructions}
	return listManifest(call, m, init.Capabilities)
}
func listManifest(call rpcCall, m *models.MCPManifest, capabilities map[string]json.RawMessage) (*models.MCPManifest, error) {
	id := 2
	for _, kind := range []string{"tools", "resources", "prompts"} {
		if _, ok := capabilities[kind]; !ok {
			continue
		}
		cursor := ""
		seen := map[string]bool{}
		for page := 0; ; page++ {
			if page >= maxListPages {
				return nil, fmt.Errorf("%s list exceeds page limit", kind)
			}
			var params interface{}
			if cursor != "" {
				params = map[string]string{"cursor": cursor}
			}
			r, err := call(models.MCPJSONRPCRequest{JSONRPC: "2.0", ID: id, Method: kind + "/list", Params: params})
			id++
			if err != nil {
				return nil, fmt.Errorf("%s/list: %w", kind, err)
			}
			var raw map[string]json.RawMessage
			if json.Unmarshal(r.Result, &raw) != nil {
				return nil, fmt.Errorf("invalid %s list", kind)
			}
			array := bytes.TrimSpace(raw[kind])
			if len(array) == 0 || array[0] != '[' {
				return nil, fmt.Errorf("missing %s array", kind)
			}
			switch kind {
			case "tools":
				var v []models.MCPTool
				if json.Unmarshal(array, &v) != nil {
					return nil, fmt.Errorf("invalid tools")
				}
				m.Tools = append(m.Tools, v...)
			case "resources":
				var v []models.MCPResource
				if json.Unmarshal(array, &v) != nil {
					return nil, fmt.Errorf("invalid resources")
				}
				m.Resources = append(m.Resources, v...)
			case "prompts":
				var v []models.MCPPrompt
				if json.Unmarshal(array, &v) != nil {
					return nil, fmt.Errorf("invalid prompts")
				}
				m.Prompts = append(m.Prompts, v...)
			}
			if len(m.Tools)+len(m.Resources)+len(m.Prompts) > 50000 {
				return nil, fmt.Errorf("MCP catalog exceeds item limit")
			}
			cursor = ""
			if v, ok := raw["nextCursor"]; ok {
				if json.Unmarshal(v, &cursor) != nil {
					return nil, fmt.Errorf("invalid list cursor")
				}
			}
			if cursor == "" {
				break
			}
			if seen[cursor] {
				return nil, fmt.Errorf("repeated pagination cursor")
			}
			seen[cursor] = true
		}
	}
	return m, nil
}
func (s *Scanner) scanLiveStdio(target string, ctx *checks.ScanContext) error {
	var parts []string
	if len(s.opts.ServerArgs) > 0 {
		parts = append([]string{target}, s.opts.ServerArgs...)
	} else if info, err := os.Stat(target); err == nil && !info.IsDir() {
		parts = []string{target}
	} else {
		parts = strings.Fields(target)
	}
	if len(parts) == 0 {
		return fmt.Errorf("empty target command")
	}
	runCtx, cancel := context.WithTimeout(s.opts.Context, s.opts.Timeout)
	defer cancel()
	stdin, stdout, stop, err := startStdioProcess(runCtx, parts)
	if err != nil {
		return err
	}
	defer stop()
	type result struct {
		m   *models.MCPManifest
		err error
	}
	done := make(chan result, 1)
	go func() { m, err := interrogateStdioProtocol(stdin, stdout, s.opts.Protocol); done <- result{m, err} }()
	select {
	case <-runCtx.Done():
		return fmt.Errorf("MCP server discovery timed out or cancelled")
	case r := <-done:
		if runCtx.Err() != nil {
			return fmt.Errorf("MCP server discovery timed out or cancelled")
		}
		if r.err != nil {
			return fmt.Errorf("stdio discovery failed: %w", r.err)
		}
		ctx.Manifest = r.m
		return nil
	}
}
func interrogateStdioServer(stdin io.Writer, stdout io.Reader) (*models.MCPManifest, error) {
	return interrogateStdioProtocol(stdin, stdout, "auto")
}
func interrogateStdioProtocol(stdin io.Writer, stdout io.Reader, policy string) (*models.MCPManifest, error) {
	reader := bufio.NewReaderSize(stdout, maxRPCMessage+1)
	call := func(req models.MCPJSONRPCRequest) (*models.MCPJSONRPCResponse, error) {
		data, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(stdin, "%s\n", data); err != nil {
			return nil, fmt.Errorf("MCP write failed")
		}
		for count := 0; count < 64; count++ {
			line, err := reader.ReadSlice('\n')
			if err != nil {
				return nil, fmt.Errorf("incomplete or oversized MCP stdio response")
			}
			if len(line) > maxRPCMessage {
				return nil, fmt.Errorf("MCP message exceeds size limit")
			}
			var envelope map[string]json.RawMessage
			if json.Unmarshal(line, &envelope) != nil {
				return nil, fmt.Errorf("invalid MCP stdio JSON")
			}
			if _, ok := envelope["method"]; ok {
				if _, hasID := envelope["id"]; hasID {
					return nil, fmt.Errorf("server requests unsupported during metadata discovery")
				}
				continue
			}
			return decodeRPC(line, req.ID)
		}
		return nil, fmt.Errorf("too many stdio notifications before response")
	}
	notify := func() error {
		_, err := io.WriteString(stdin, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
		return err
	}
	return negotiateManifest(call, notify, policy, func() {})
}

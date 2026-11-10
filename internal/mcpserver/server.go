// Package mcpserver implements the stdio MCP lifecycle and typed tool dispatch.
// It deliberately exposes no HTTP listener or arbitrary command interface.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const MaxMessageBytes = 8 << 20
const ReportURI = "ui://mcpsense/report.html"
const ReportMIME = "text/html;profile=mcp-app"

//go:embed report.html
var reportHTML string

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	Annotations map[string]interface{} `json:"annotations"`
	Meta        map[string]interface{} `json:"_meta,omitempty"`
}

type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type Result struct {
	Content           []Content   `json:"content"`
	StructuredContent interface{} `json:"structuredContent,omitempty"`
	IsError           bool        `json:"isError,omitempty"`
}

func TextResult(text string, data interface{}) Result {
	return Result{Content: []Content{{Type: "text", Text: text}}, StructuredContent: data}
}

type Handler func(context.Context, string, json.RawMessage) Result

type Server struct {
	Version string
	Tools   []Tool
	Call    Handler
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Serve serializes tool calls, permits ping/cancellation while a call runs, and
// cancels the active call on EOF. Stdout carries only newline-delimited JSON.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Closing the owned stdio input interrupts an idle read on process shutdown.
	stopWatching := make(chan struct{})
	defer close(stopWatching)
	if closer, ok := in.(io.ReadCloser); ok {
		go func() {
			select {
			case <-ctx.Done():
				_ = closer.Close()
			case <-stopWatching:
			}
		}()
	}
	var writeMu sync.Mutex
	var workers sync.WaitGroup
	var activeMu sync.Mutex
	var activeID string
	var activeCancel context.CancelFunc
	defer workers.Wait()
	send := func(id json.RawMessage, result interface{}, fault *rpcError, modern ...bool) error {
		if fault == nil && len(modern) > 0 && modern[0] {
			data, err := json.Marshal(result)
			if err != nil {
				return err
			}
			var envelope map[string]interface{}
			if err := json.Unmarshal(data, &envelope); err != nil {
				return err
			}
			envelope["resultType"] = "complete"
			envelope["_meta"] = map[string]interface{}{"io.modelcontextprotocol/serverInfo": map[string]string{"name": "mcpsense", "version": s.Version}}
			result = envelope
		}
		response := map[string]interface{}{"jsonrpc": "2.0", "id": id}
		if fault != nil {
			response["error"] = fault
		} else {
			response["result"] = result
		}
		data, err := json.Marshal(response)
		if err != nil || len(data) > MaxMessageBytes {
			data, err = json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": rpcError{Code: -32603, Message: "Response exceeds the supported limit"}})
		}
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, err = out.Write(append(data, '\n'))
		if err != nil {
			cancel()
		}
		return err
	}
	input := bufio.NewScanner(in)
	input.Buffer(make([]byte, 64<<10), MaxMessageBytes)
	initialized, ready, appUI := false, false, false
	for input.Scan() {
		if ctx.Err() != nil {
			break
		}
		var request message
		line := bytes.TrimSpace(input.Bytes())
		if !json.Valid(line) {
			if err := send(json.RawMessage("null"), nil, &rpcError{Code: -32700, Message: "Invalid JSON"}); err != nil {
				return err
			}
			continue
		}
		if json.Unmarshal(line, &request) != nil || request.JSONRPC != "2.0" || request.Method == "" {
			if err := send(json.RawMessage("null"), nil, &rpcError{Code: -32600, Message: "Invalid JSON-RPC request"}); err != nil {
				return err
			}
			continue
		}
		notification := len(request.ID) == 0
		if !notification && !validID(request.ID) {
			if err := send(json.RawMessage("null"), nil, &rpcError{Code: -32600, Message: "Request ID must be a string or integer"}); err != nil {
				return err
			}
			continue
		}
		if notification {
			switch request.Method {
			case "notifications/initialized":
				ready = initialized
			case "notifications/cancelled":
				var p struct {
					RequestID json.RawMessage `json:"requestId"`
				}
				if json.Unmarshal(request.Params, &p) == nil {
					activeMu.Lock()
					if requestKey(p.RequestID) == activeID && activeCancel != nil {
						activeCancel()
					}
					activeMu.Unlock()
				}
			}
			continue
		}
		var result interface{}
		var fault *rpcError
		modern, requestUI, metadataError := requestMetadata(request, appUI)
		if metadataError != nil {
			if err := send(request.ID, nil, metadataError); err != nil {
				return err
			}
			continue
		}
		switch request.Method {
		case "server/discover":
			result = map[string]interface{}{"supportedVersions": []string{"2026-07-28"}, "capabilities": map[string]interface{}{"tools": map[string]interface{}{}, "resources": map[string]interface{}{}}, "instructions": serverInstructions, "ttlMs": 0, "cacheScope": "private"}
		case "initialize":
			var p struct {
				ProtocolVersion string          `json:"protocolVersion"`
				Capabilities    json.RawMessage `json:"capabilities"`
				ClientInfo      json.RawMessage `json:"clientInfo"`
			}
			if initialized || json.Unmarshal(request.Params, &p) != nil || p.ProtocolVersion == "" || len(p.Capabilities) == 0 || len(p.ClientInfo) == 0 {
				fault = &rpcError{Code: -32602, Message: "Expected a single initialize request with protocolVersion, capabilities and clientInfo"}
				break
			}
			var capabilities struct {
				Extensions map[string]struct {
					MIMETypes []string `json:"mimeTypes"`
				} `json:"extensions"`
			}
			var client struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(p.Capabilities, &capabilities) != nil || string(p.Capabilities) == "null" ||
				json.Unmarshal(p.ClientInfo, &client) != nil || client.Name == "" || client.Version == "" {
				fault = &rpcError{Code: -32602, Message: "Invalid client capabilities or clientInfo"}
				break
			}
			for _, mime := range capabilities.Extensions["io.modelcontextprotocol/ui"].MIMETypes {
				if mime == ReportMIME {
					appUI = true
				}
			}
			protocol := p.ProtocolVersion
			switch protocol {
			case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
			default:
				protocol = "2025-11-25"
			}
			initialized = true
			result = map[string]interface{}{
				"protocolVersion": protocol,
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}, "resources": map[string]interface{}{}},
				"serverInfo":      map[string]string{"name": "mcpsense", "version": s.Version},
				"instructions":    serverInstructions,
			}
		case "ping":
			result = map[string]interface{}{}
		default:
			if !modern && !ready {
				fault = &rpcError{Code: -32600, Message: "Initialize and send notifications/initialized before using tools"}
				break
			}
			switch request.Method {
			case "tools/list":
				tools := append([]Tool{}, s.Tools...)
				for i := range tools {
					if requestUI && (tools[i].Name == "mcpsense_scan" || tools[i].Name == "mcpsense_accept_baseline") {
						tools[i].Meta = map[string]interface{}{"ui": map[string]interface{}{"resourceUri": ReportURI, "visibility": []string{"model", "app"}}}
					}
				}
				result = map[string]interface{}{"tools": tools, "ttlMs": 0, "cacheScope": "private"}
			case "resources/list":
				result = map[string]interface{}{"ttlMs": 0, "cacheScope": "private", "resources": []map[string]interface{}{{"uri": ReportURI, "name": "MCPSense findings", "description": "Inspect and filter findings from your current scan.", "mimeType": ReportMIME}}}
			case "resources/templates/list":
				result = map[string]interface{}{"resourceTemplates": []interface{}{}, "ttlMs": 0, "cacheScope": "private"}
			case "resources/read":
				var p struct {
					URI string `json:"uri"`
				}
				if json.Unmarshal(request.Params, &p) != nil || p.URI != ReportURI {
					fault = &rpcError{Code: -32602, Message: "Unknown resource"}
					break
				}
				result = map[string]interface{}{"ttlMs": 0, "cacheScope": "private", "contents": []map[string]interface{}{{"uri": ReportURI, "mimeType": ReportMIME, "text": reportHTML,
					"_meta": map[string]interface{}{"ui": map[string]interface{}{"csp": map[string]interface{}{"connectDomains": []string{}, "resourceDomains": []string{}}}}}}}
			case "tools/call":
				var p struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				}
				if json.Unmarshal(request.Params, &p) != nil || p.Name == "" {
					fault = &rpcError{Code: -32602, Message: "Tool name and object arguments are required"}
					break
				}
				if len(p.Arguments) == 0 {
					p.Arguments = json.RawMessage("{}")
				}
				if len(p.Arguments) == 0 || bytes.TrimSpace(p.Arguments)[0] != '{' {
					fault = &rpcError{Code: -32602, Message: "Tool arguments must be an object"}
					break
				}
				found := false
				for _, tool := range s.Tools {
					if tool.Name == p.Name {
						found = true
						break
					}
				}
				if !found {
					fault = &rpcError{Code: -32602, Message: "Unknown tool"}
					break
				}
				activeMu.Lock()
				if activeCancel != nil {
					activeMu.Unlock()
					fault = &rpcError{Code: -32603, Message: "A tool call is already running; retry after it completes"}
					break
				}
				callCtx, callCancel := context.WithCancel(ctx)
				activeCancel, activeID = callCancel, requestKey(request.ID)
				activeMu.Unlock()
				id, args, name := append(json.RawMessage{}, request.ID...), append(json.RawMessage{}, p.Arguments...), p.Name
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer callCancel()
					answer := s.call(callCtx, name, args)
					activeMu.Lock()
					activeCancel, activeID = nil, ""
					activeMu.Unlock()
					if callCtx.Err() == nil {
						_ = send(id, answer, nil, modern)
					}
				}()
				continue
			default:
				fault = &rpcError{Code: -32601, Message: "Method not supported"}
			}
		}
		if err := send(request.ID, result, fault, modern); err != nil {
			return err
		}
	}
	inputErr, contextErr := input.Err(), ctx.Err()
	cancel()
	if inputErr != nil && contextErr == nil {
		return fmt.Errorf("MCP input unreadable or message exceeds %d bytes", MaxMessageBytes)
	}
	return nil
}

func (s *Server) call(ctx context.Context, name string, args json.RawMessage) (answer Result) {
	defer func() {
		if recover() != nil {
			answer = TextResult("Tool failed; scan completion was not established.", nil)
			answer.IsError = true
		}
	}()
	return s.Call(ctx, name, args)
}

func validID(id json.RawMessage) bool {
	var text string
	if len(id) > 0 && id[0] == '"' && json.Unmarshal(id, &text) == nil {
		return true
	}
	var n json.Number
	decoder := json.NewDecoder(bytes.NewReader(id))
	decoder.UseNumber()
	var value interface{}
	if decoder.Decode(&value) != nil {
		return false
	}
	n, ok := value.(json.Number)
	if !ok {
		return false
	}
	_, err := n.Int64()
	return err == nil
}

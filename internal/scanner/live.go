package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/models"
)

// scanLive connects to a live MCP server and interrogates it for tools and resources.
func (s *Scanner) scanLive(target string, ctx *checks.ScanContext) error {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return s.scanLiveSSE(target, ctx)
	}
	return s.scanLiveStdio(target, ctx)
}

// scanLiveSSE connects to an MCP server over HTTP/SSE.
func (s *Scanner) scanLiveSSE(target string, ctx *checks.ScanContext) error {
	client := &http.Client{Timeout: 10 * time.Second}

	// Try to fetch tools via the JSON-RPC endpoint.
	manifest, err := fetchManifestViaHTTP(client, target)
	if err != nil {
		return fmt.Errorf("live SSE scan failed for %q: %w", target, err)
	}
	ctx.Manifest = manifest
	return nil
}

// fetchManifestViaHTTP sends initialize + tools/list + resources/list to an HTTP MCP endpoint.
func fetchManifestViaHTTP(client *http.Client, baseURL string) (*models.MCPManifest, error) {
	rpcURL := strings.TrimRight(baseURL, "/") + "/rpc"

	initReq := models.MCPJSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: models.MCPInitializeRequest{
			ProtocolVersion: "2024-11-05",
			Capabilities:    map[string]interface{}{},
			ClientInfo:      models.MCPInfo{Name: "mcpsense", Version: "0.1.0"},
		},
	}

	initData, err := json.Marshal(initReq)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(rpcURL, "application/json", strings.NewReader(string(initData)))
	if err != nil {
		return nil, fmt.Errorf("initialize request failed: %w", err)
	}
	defer resp.Body.Close()

	var initResp models.MCPJSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return nil, fmt.Errorf("decoding initialize response: %w", err)
	}

	manifest := &models.MCPManifest{}

	// Extract server info from initialize response.
	if initResp.Result != nil {
		var initResult models.MCPInitializeResponse
		if err := json.Unmarshal(initResp.Result, &initResult); err == nil {
			manifest.Name = initResult.ServerInfo.Name
			manifest.Version = initResult.ServerInfo.Version
		}
	}

	// Fetch tools list.
	toolsReq := models.MCPJSONRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list"}
	toolsData, _ := json.Marshal(toolsReq)
	toolsResp, err := client.Post(rpcURL, "application/json", strings.NewReader(string(toolsData)))
	if err == nil {
		defer toolsResp.Body.Close()
		var rpcResp models.MCPJSONRPCResponse
		if json.NewDecoder(toolsResp.Body).Decode(&rpcResp) == nil && rpcResp.Result != nil {
			var toolsList models.MCPToolsListResult
			if json.Unmarshal(rpcResp.Result, &toolsList) == nil {
				manifest.Tools = toolsList.Tools
			}
		}
	}

	// Fetch resources list.
	resReq := models.MCPJSONRPCRequest{JSONRPC: "2.0", ID: 3, Method: "resources/list"}
	resData, _ := json.Marshal(resReq)
	resResp, err := client.Post(rpcURL, "application/json", strings.NewReader(string(resData)))
	if err == nil {
		defer resResp.Body.Close()
		var rpcResp models.MCPJSONRPCResponse
		if json.NewDecoder(resResp.Body).Decode(&rpcResp) == nil && rpcResp.Result != nil {
			var resList models.MCPResourcesListResult
			if json.Unmarshal(rpcResp.Result, &resList) == nil {
				manifest.Resources = resList.Resources
			}
		}
	}

	return manifest, nil
}

// scanLiveStdio spawns an MCP server process and communicates over stdin/stdout.
func (s *Scanner) scanLiveStdio(target string, ctx *checks.ScanContext) error {
	parts := strings.Fields(target)
	if len(parts) == 0 {
		return fmt.Errorf("empty target command")
	}

	cmd := exec.Command(parts[0], parts[1:]...) //nolint:gosec // user-supplied command for live testing
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting server process %q: %w", target, err)
	}
	defer func() {
		stdin.Close()
		cmd.Process.Kill() //nolint:errcheck // best-effort cleanup
		cmd.Wait()         //nolint:errcheck // best-effort wait
	}()

	manifest, err := interrogateStdioServer(stdin, stdout)
	if err != nil {
		return fmt.Errorf("interrogating stdio server: %w", err)
	}
	ctx.Manifest = manifest
	return nil
}

// interrogateStdioServer sends MCP protocol messages and collects tool/resource info.
func interrogateStdioServer(stdin io.Writer, stdout io.Reader) (*models.MCPManifest, error) {
	reader := bufio.NewReader(stdout)

	sendRPC := func(req models.MCPJSONRPCRequest) (*models.MCPJSONRPCResponse, error) {
		data, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(stdin, "%s\n", data); err != nil {
			return nil, err
		}
		// Read response line with timeout via a channel.
		type result struct {
			line string
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			line, err := reader.ReadString('\n')
			ch <- result{line, err}
		}()

		select {
		case r := <-ch:
			if r.err != nil {
				return nil, r.err
			}
			var resp models.MCPJSONRPCResponse
			if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &resp); err != nil {
				return nil, err
			}
			return &resp, nil
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("timeout waiting for server response")
		}
	}

	manifest := &models.MCPManifest{}

	// Initialize.
	initReq := models.MCPJSONRPCRequest{
		JSONRPC: "2.0", ID: 1, Method: "initialize",
		Params: models.MCPInitializeRequest{
			ProtocolVersion: "2024-11-05",
			Capabilities:    map[string]interface{}{},
			ClientInfo:      models.MCPInfo{Name: "mcpsense", Version: "0.1.0"},
		},
	}
	initResp, err := sendRPC(initReq)
	if err == nil && initResp.Result != nil {
		var result models.MCPInitializeResponse
		if json.Unmarshal(initResp.Result, &result) == nil {
			manifest.Name = result.ServerInfo.Name
			manifest.Version = result.ServerInfo.Version
		}
	}

	// Tools list.
	toolsResp, err := sendRPC(models.MCPJSONRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list"})
	if err == nil && toolsResp != nil && toolsResp.Result != nil {
		var toolsList models.MCPToolsListResult
		if json.Unmarshal(toolsResp.Result, &toolsList) == nil {
			manifest.Tools = toolsList.Tools
		}
	}

	// Resources list.
	resResp, err := sendRPC(models.MCPJSONRPCRequest{JSONRPC: "2.0", ID: 3, Method: "resources/list"})
	if err == nil && resResp != nil && resResp.Result != nil {
		var resList models.MCPResourcesListResult
		if json.Unmarshal(resResp.Result, &resList) == nil {
			manifest.Resources = resList.Resources
		}
	}

	return manifest, nil
}

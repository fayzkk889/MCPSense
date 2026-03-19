package models

import "encoding/json"

// MCPManifest represents the top-level MCP server manifest/config.
type MCPManifest struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	Tools       []MCPTool     `json:"tools"`
	Resources   []MCPResource `json:"resources,omitempty"`
	Auth        *MCPAuth      `json:"auth,omitempty"`
}

// MCPTool represents a tool exposed by an MCP server.
type MCPTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// MCPResource represents a resource exposed by an MCP server.
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

// MCPAuth describes the authentication configuration for the server.
type MCPAuth struct {
	Type string `json:"type"` // "oauth2", "api_key", "none"
}

// MCPInitializeRequest is the MCP protocol initialize request payload.
type MCPInitializeRequest struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Capabilities    interface{} `json:"capabilities"`
	ClientInfo      MCPInfo     `json:"clientInfo"`
}

// MCPInfo holds name and version metadata used in protocol handshakes.
type MCPInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPInitializeResponse is the MCP protocol initialize response payload.
type MCPInitializeResponse struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Capabilities    interface{} `json:"capabilities"`
	ServerInfo      MCPInfo     `json:"serverInfo"`
}

// MCPJSONRPCRequest wraps an MCP method call in JSON-RPC 2.0 format.
type MCPJSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// MCPJSONRPCResponse wraps an MCP response in JSON-RPC 2.0 format.
type MCPJSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPRPCError    `json:"error,omitempty"`
}

// MCPRPCError represents a JSON-RPC error object.
type MCPRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPToolsListResult holds the result of a tools/list call.
type MCPToolsListResult struct {
	Tools []MCPTool `json:"tools"`
}

// MCPResourcesListResult holds the result of a resources/list call.
type MCPResourcesListResult struct {
	Resources []MCPResource `json:"resources"`
}

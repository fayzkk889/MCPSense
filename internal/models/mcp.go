package models

import "encoding/json"

// MCPManifest represents the top-level MCP server manifest/config.
type MCPManifest struct {
	Name            string        `json:"name"`
	Version         string        `json:"version"`
	ProtocolVersion string        `json:"protocolVersion,omitempty"`
	Description     string        `json:"description"`
	Tools           []MCPTool     `json:"tools"`
	Resources       []MCPResource `json:"resources,omitempty"`
	Prompts         []MCPPrompt   `json:"prompts,omitempty"`
	Auth            *MCPAuth      `json:"auth,omitempty"`
}

// ToolAnnotations holds behavioral hints for a tool as defined in MCP spec 2025-03-26+.
// IMPORTANT: All fields are HINTS, not guarantees. Untrusted servers can lie about these.
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// MCPTool represents a tool exposed by an MCP server.
type MCPTool struct {
	Name         string           `json:"name"`
	Title        string           `json:"title,omitempty"`
	Description  string           `json:"description"`
	InputSchema  json.RawMessage  `json:"inputSchema"`
	OutputSchema json.RawMessage  `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
}

// MCPResource represents a resource exposed by an MCP server.
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

// MCPPrompt represents a prompt template exposed by an MCP server.
type MCPPrompt struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
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

// MCPJSONRPCNotification is a JSON-RPC 2.0 notification (no id field, no response expected).
type MCPJSONRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
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

// MCPPromptsListResult holds the result of a prompts/list call.
type MCPPromptsListResult struct {
	Prompts []MCPPrompt `json:"prompts"`
}

// MCPClientConfig represents an MCP client configuration file (mcp.json, claude_desktop_config.json, etc.).
type MCPClientConfig struct {
	MCPServers map[string]MCPServerEntry `json:"mcpServers"`
}

// MCPServerEntry represents a single server entry in an MCP client config.
type MCPServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
	Type    string            `json:"type,omitempty"`
}

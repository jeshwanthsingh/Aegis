package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
)

const (
	jsonRPCVersion    = "2.0"
	latestProtocol    = "2025-06-18"
	serverName        = "aegis-mcp"
	maxMessageBytes   = 1024 * 1024
	errParse          = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternal       = -32603
	errServerStart    = -32000
)

const (
	methodInitialize  = "initialize"
	methodInitialized = "notifications/initialized"
	methodPing        = "ping"
	methodToolsList   = "tools/list"
	methodToolsCall   = "tools/call"
)

type Server struct {
	handler Handler
	logger  *log.Logger
}

type Handler interface {
	Initialize(context.Context, InitializeParams) (InitializeResult, error)
	ListTools(context.Context) (ToolsListResult, error)
	CallTool(context.Context, CallToolParams) (CallToolResult, error)
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ClientInfo      ClientInfo     `json:"clientInfo"`
	Capabilities    map[string]any `json:"capabilities,omitempty"`
}

type ClientInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type toolsListParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type Tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type CallToolResult struct {
	Content           []ToolContent  `json:"content"`
	StructuredContent map[string]any `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func NewServer(handler Handler, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{handler: handler, logger: logger}
}

func (s *Server) Serve(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	reader := bufio.NewReader(stdin)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(line) == 0 {
			continue
		}
		if len(line) > maxMessageBytes {
			if err := writeResponse(stdout, rpcResponse{
				JSONRPC: jsonRPCVersion,
				Error:   &rpcError{Code: errInvalidRequest, Message: "message exceeds maximum size"},
			}); err != nil {
				return err
			}
			continue
		}
		resp, write := s.handleLine(ctx, line)
		if !write {
			continue
		}
		if err := writeResponse(stdout, resp); err != nil {
			return err
		}
	}
}

func (s *Server) handleLine(ctx context.Context, line []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return rpcResponse{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: errParse, Message: "invalid JSON"}}, true
	}
	if req.JSONRPC != jsonRPCVersion {
		return s.errorResponse(req.ID, errInvalidRequest, "jsonrpc must be 2.0", nil), len(req.ID) > 0
	}
	if req.Method == "" {
		return s.errorResponse(req.ID, errInvalidRequest, "method is required", nil), len(req.ID) > 0
	}
	if len(req.ID) == 0 {
		s.handleNotification(ctx, req)
		return rpcResponse{}, false
	}
	switch req.Method {
	case methodInitialize:
		var params InitializeParams
		if err := decodeLooseParams(req.Params, &params); err != nil {
			return s.errorResponse(req.ID, errInvalidParams, "invalid initialize params", err.Error()), true
		}
		result, err := s.handler.Initialize(ctx, params)
		if err != nil {
			return s.errorResponse(req.ID, errServerStart, err.Error(), nil), true
		}
		return rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Result: result}, true
	case methodPing:
		return rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Result: map[string]any{}}, true
	case methodToolsList:
		var params toolsListParams
		if err := decodeLooseParams(req.Params, &params); err != nil {
			return s.errorResponse(req.ID, errInvalidParams, "invalid tools/list params", err.Error()), true
		}
		result, err := s.handler.ListTools(ctx)
		if err != nil {
			return s.errorResponse(req.ID, errInternal, err.Error(), nil), true
		}
		return rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Result: result}, true
	case methodToolsCall:
		var params CallToolParams
		if err := decodeLooseParams(req.Params, &params); err != nil {
			return s.errorResponse(req.ID, errInvalidParams, "invalid tools/call params", err.Error()), true
		}
		result, err := s.handler.CallTool(ctx, params)
		if err != nil {
			var invalid *InvalidParamsError
			if errors.As(err, &invalid) {
				return s.errorResponse(req.ID, errInvalidParams, invalid.Error(), invalid.Details), true
			}
			return s.errorResponse(req.ID, errInternal, err.Error(), nil), true
		}
		return rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Result: result}, true
	default:
		return s.errorResponse(req.ID, errMethodNotFound, fmt.Sprintf("method %q not found", req.Method), nil), true
	}
}

func (s *Server) handleNotification(_ context.Context, req rpcRequest) {
	switch req.Method {
	case methodInitialized:
		s.logger.Printf("client initialized")
	default:
		s.logger.Printf("ignored notification %s", req.Method)
	}
}

func (s *Server) errorResponse(id json.RawMessage, code int, message string, data any) rpcResponse {
	return rpcResponse{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Error:   &rpcError{Code: code, Message: message, Data: data},
	}
}

func decodeLooseParams(raw json.RawMessage, dst any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	return json.Unmarshal(raw, dst)
}

func writeResponse(stdout io.Writer, resp rpcResponse) error {
	encoded, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(encoded, '\n'))
	return err
}

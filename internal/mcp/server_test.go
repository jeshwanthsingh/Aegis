package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type stubHandler struct{}

func (stubHandler) Initialize(_ context.Context, _ InitializeParams) (InitializeResult, error) {
	return InitializeResult{
		ProtocolVersion: latestProtocol,
		Capabilities:    map[string]any{"tools": map[string]any{}},
		ServerInfo:      ServerInfo{Name: "test", Version: "1.0.0"},
	}, nil
}

func (stubHandler) ListTools(_ context.Context) (ToolsListResult, error) {
	return ToolsListResult{Tools: []Tool{{Name: "aegis_execute", Description: "run", InputSchema: map[string]any{"type": "object"}}}}, nil
}

func (stubHandler) CallTool(_ context.Context, params CallToolParams) (CallToolResult, error) {
	return CallToolResult{
		Content: []ToolContent{{Type: "text", Text: params.Name}},
		StructuredContent: map[string]any{
			"name": params.Name,
		},
	}, nil
}

func TestServerInitializeAndToolsList(t *testing.T) {
	server := NewServer(stubHandler{}, nil)
	var stdout bytes.Buffer
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"clientInfo\":{\"name\":\"test\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
	if err := server.Serve(context.Background(), input, &stdout); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(lines))
	}
	var initResp rpcResponse
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("unmarshal init response: %v", err)
	}
	var initResult InitializeResult
	initJSON, _ := json.Marshal(initResp.Result)
	if err := json.Unmarshal(initJSON, &initResult); err != nil {
		t.Fatalf("decode init result: %v", err)
	}
	if initResult.ProtocolVersion != latestProtocol {
		t.Fatalf("protocol version = %q", initResult.ProtocolVersion)
	}
	var listResp rpcResponse
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	var tools ToolsListResult
	toolsJSON, _ := json.Marshal(listResp.Result)
	if err := json.Unmarshal(toolsJSON, &tools); err != nil {
		t.Fatalf("decode tools result: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "aegis_execute" {
		t.Fatalf("unexpected tools payload: %+v", tools.Tools)
	}
}

func TestServerMalformedRequest(t *testing.T) {
	server := NewServer(stubHandler{}, nil)
	var stdout bytes.Buffer
	if err := server.Serve(context.Background(), strings.NewReader("{bad json}\n"), &stdout); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	var resp rpcResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != errParse {
		t.Fatalf("unexpected error response: %+v", resp.Error)
	}
}

func TestServerInvalidParams(t *testing.T) {
	server := NewServer(stubHandler{}, nil)
	var stdout bytes.Buffer
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"aegis_execute\",\"arguments\":\"bad\"}}\n")
	if err := server.Serve(context.Background(), input, &stdout); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	var resp rpcResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != errInvalidParams {
		t.Fatalf("unexpected error response: %+v", resp.Error)
	}
}

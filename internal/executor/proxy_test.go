package executor

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"aegis/internal/authority"
	"aegis/internal/broker"
	"aegis/internal/policy/contract"
)

func TestHandleBrokerConnRespondsWithoutClientClosing(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	b := broker.New(contract.BrokerScope{
		AllowedDelegations: []string{"github"},
		AllowedDomains:     []string{"example.invalid"},
	}, []string{"example.invalid"}, nil, nil, authority.ApprovalModeNone, "policy-digest", "authority-digest", "exec-test", nil, nil, nil, nil, nil)

	done := make(chan struct{})
	go func() {
		handleBrokerConn(serverConn, b, nil)
		close(done)
	}()

	req := broker.BrokerRequest{
		Method:  "GET",
		URL:     "http://127.0.0.1/test",
		Headers: map[string][]string{"Host": {"127.0.0.1"}},
	}
	if err := json.NewEncoder(clientConn).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp broker.BrokerResponse
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatalf("decode response before close: %v", err)
	}
	if !resp.Denied {
		t.Fatalf("expected denied response before client close, got %+v", resp)
	}
	if resp.DenyReason == "" {
		t.Fatalf("expected deny reason, got %+v", resp)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleBrokerConn did not return after responding")
	}
}

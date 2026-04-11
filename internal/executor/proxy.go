package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"aegis/internal/broker"
	"aegis/internal/observability"
	policydivergence "aegis/internal/policy/divergence"
)

// StartBrokerListener listens on the vsock path for guest-initiated connections on port 1025
// and dispatches brokered credential requests. The listener path follows the Firecracker
// convention: <vsock_uds_path>_<port>.
//
// If b is nil, the function waits for context cancellation without accepting connections
// (no broker configured for this execution).
func StartBrokerListener(ctx context.Context, vsockPath string, b *broker.Broker, divEval *policydivergence.Evaluator) error {
	if b == nil {
		<-ctx.Done()
		return nil
	}

	listenerPath := vsockPath + "_" + "1025"
	if err := os.Remove(listenerPath); err != nil && !os.IsNotExist(err) {
		observability.Warn("broker_listener_cleanup_failed", observability.Fields{"path": listenerPath, "error": err.Error()})
	}

	ln, err := net.Listen("unix", listenerPath)
	if err != nil {
		observability.Warn("broker_listen_failed", observability.Fields{"path": listenerPath, "error": err.Error()})
		<-ctx.Done()
		return nil
	}

	observability.Info("broker_listener_started", observability.Fields{"path": listenerPath})

	go func() {
		<-ctx.Done()
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			observability.Warn("broker_listener_close_failed", observability.Fields{"path": listenerPath, "error": err.Error()})
		}
		if err := os.Remove(listenerPath); err != nil && !os.IsNotExist(err) {
			observability.Warn("broker_listener_cleanup_failed", observability.Fields{"path": listenerPath, "error": err.Error()})
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		observability.Info("broker_conn_accepted", observability.Fields{"remote": conn.RemoteAddr().String()})
		go handleBrokerConn(conn, b, divEval)
	}
}

func handleBrokerConn(conn net.Conn, b *broker.Broker, divEval *policydivergence.Evaluator) {
	defer conn.Close()

	req, err := decodeBrokerRequest(conn)
	if err != nil {
		observability.Warn("broker_request_decode_failed", observability.Fields{"error": err.Error()})
		if encodeErr := broker.EncodeBrokerResponse(conn, broker.BrokerResponse{Error: err.Error()}); encodeErr != nil {
			observability.Warn("broker_response_encode_failed", observability.Fields{"error": encodeErr.Error()})
		}
		return
	}
	observability.Info("broker_request_decoded", observability.Fields{"method": req.Method, "url": req.URL})

	resp := b.Handle(req)
	observability.Info("broker_response_ready", observability.Fields{"allowed": resp.Allowed, "denied": resp.Denied, "status": resp.StatusCode, "deny_reason": resp.DenyReason, "error": resp.Error})
	if resp.Denied && divEval != nil {
		domain, _ := extractDomainFromURL(req.URL)
		divEval.ObserveBrokerDenial(domain, resp.DenyReason, resp.DenyReason)
	}
	if err := broker.EncodeBrokerResponse(conn, resp); err != nil {
		observability.Warn("broker_response_encode_failed", observability.Fields{"error": err.Error()})
	}
}

func decodeBrokerRequest(conn net.Conn) (broker.BrokerRequest, error) {
	limited := io.LimitReader(conn, 1<<20)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var req broker.BrokerRequest
	if err := decoder.Decode(&req); err != nil {
		return broker.BrokerRequest{}, err
	}
	return req, nil
}

func extractDomainFromURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL, err
	}
	return strings.ToLower(parsed.Hostname()), nil
}

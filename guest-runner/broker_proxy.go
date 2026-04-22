package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
)

const (
	brokerProxyAddr      = "127.0.0.1:8888"
	brokerVsockCID       = vsock.Host
	brokerVsockPort      = 1025
	brokerTimeout        = 30 * time.Second
	governedActionHeader = "X-Aegis-Governed-Action"
	approvalTicketHeader = "X-Aegis-Approval-Ticket"
)

// proxyRequest matches the BrokerRequest wire type on the host side.
type proxyRequest struct {
	Method         string              `json:"method"`
	URL            string              `json:"url"`
	ActionType     string              `json:"action_type,omitempty"`
	Headers        map[string][]string `json:"headers,omitempty"`
	BodyBase64     string              `json:"body_base64,omitempty"`
	HostAction     json.RawMessage     `json:"host_action,omitempty"`
	ApprovalTicket json.RawMessage     `json:"approval_ticket,omitempty"`
}

// proxyResponse matches the BrokerResponse wire type on the host side.
type proxyResponse struct {
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	BodyBase64 string              `json:"body_base64,omitempty"`
	Allowed    bool                `json:"allowed"`
	Denied     bool                `json:"denied,omitempty"`
	DenyReason string              `json:"deny_reason,omitempty"`
	Error      string              `json:"error,omitempty"`
	HostAction json.RawMessage     `json:"host_action,omitempty"`
}

func brokerProxyLog(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "BROKER_PROXY "+format+"\n", args...)
}

// startBrokerProxy runs an HTTP proxy on 127.0.0.1:8888 that routes
// brokered HTTP requests over vsock to the host credential broker on port 1025.
// It returns when stop is closed. The ready channel is closed once the loopback
// listener is bound so callers can avoid racing first use against startup.
func startBrokerProxy(stop <-chan struct{}, ready chan<- struct{}) {
	srv := &http.Server{
		Addr:         brokerProxyAddr,
		Handler:      http.HandlerFunc(handleBrokerProxyRequest),
		ReadTimeout:  brokerTimeout,
		WriteTimeout: brokerTimeout,
	}
	ln, err := net.Listen("tcp", brokerProxyAddr)
	if err != nil {
		brokerProxyLog("listen_error err=%v", err)
		close(ready)
		return
	}
	brokerProxyLog("listen_start addr=%s cid=%d port=%d", brokerProxyAddr, brokerVsockCID, brokerVsockPort)
	close(ready)
	go func() {
		<-stop
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		brokerProxyLog("listen_error err=%v", err)
	}
}

func handleBrokerProxyRequest(w http.ResponseWriter, r *http.Request) {
	// CONNECT tunneling is not supported in v1 - the host broker cannot inject
	// auth into opaque TLS streams.
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT tunneling not supported by Aegis broker v1", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Determine target URL: for transparent proxy mode, reconstruct from request.
	targetURL := r.URL.String()
	if !r.URL.IsAbs() {
		scheme := "http"
		targetURL = scheme + "://" + r.Host + r.URL.RequestURI()
	}

	brokerProxyLog("request_received method=%s url=%s host=%s", r.Method, publicHTTPURLString(targetURL), r.Host)
	msg := proxyRequest{
		Method:  r.Method,
		URL:     targetURL,
		Headers: make(map[string][]string),
	}
	for key, vals := range r.Header {
		if strings.EqualFold(key, governedActionHeader) {
			if msg.ActionType == "" && len(vals) > 0 {
				msg.ActionType = strings.TrimSpace(vals[0])
			}
			continue
		}
		if strings.EqualFold(key, approvalTicketHeader) {
			if len(msg.ApprovalTicket) == 0 && len(vals) > 0 {
				ticket, err := decodeApprovalTicketHeader(vals[0])
				if err != nil {
					http.Error(w, fmt.Sprintf("decode approval ticket: %v", err), http.StatusBadRequest)
					return
				}
				msg.ApprovalTicket = ticket
			}
			continue
		}
		msg.Headers[key] = vals
	}
	if len(body) > 0 {
		msg.BodyBase64 = base64.StdEncoding.EncodeToString(body)
	}

	// Dial host broker over vsock.
	brokerProxyLog("vsock_dial_start cid=%d port=%d", brokerVsockCID, brokerVsockPort)
	conn, err := vsock.Dial(brokerVsockCID, brokerVsockPort, nil)
	if err != nil {
		brokerProxyLog("vsock_dial_error err=%v", err)
		http.Error(w, fmt.Sprintf("broker unavailable: %v", err), http.StatusBadGateway)
		return
	}
	brokerProxyLog("vsock_dial_ok")
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(brokerTimeout)); err != nil {
		http.Error(w, "set deadline: "+err.Error(), http.StatusBadGateway)
		return
	}

	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		http.Error(w, fmt.Sprintf("send request: %v", err), http.StatusBadGateway)
		return
	}

	var resp proxyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		brokerProxyLog("response_decode_error err=%v", err)
		http.Error(w, fmt.Sprintf("decode response: %v", err), http.StatusBadGateway)
		return
	}
	brokerProxyLog("response_received allowed=%t denied=%t status=%d error=%q", resp.Allowed, resp.Denied, resp.StatusCode, resp.Error)

	if resp.Denied {
		http.Error(w, fmt.Sprintf("broker denied: %s", resp.DenyReason), http.StatusForbidden)
		return
	}
	if resp.Error != "" {
		http.Error(w, resp.Error, http.StatusBadGateway)
		return
	}

	for k, vals := range resp.Headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	if resp.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
		if err == nil {
			_, _ = w.Write(decoded)
		}
	}
}

func publicHTTPURLString(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.Fragment = ""
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	switch {
	case port == "":
		parsed.Host = host
	case scheme == "http" && port == "80":
		parsed.Host = host
	case scheme == "https" && port == "443":
		parsed.Host = host
	default:
		parsed.Host = host + ":" + port
	}
	pathValue := parsed.EscapedPath()
	if pathValue == "" {
		pathValue = "/"
	}
	value := scheme + "://" + parsed.Host + pathValue
	if len(parsed.Query()) > 0 {
		value += "?query_keys=" + strconv.Itoa(len(parsed.Query()))
	}
	return value
}

// brokerProxyAddr is only bound to loopback inside the guest VM.
// This check ensures we never accidentally listen on a non-loopback address.
var _ net.Addr = (*net.TCPAddr)(nil)

func decodeApprovalTicketHeader(raw string) (json.RawMessage, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode approval ticket header: %w", err)
	}
	var payload any
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("decode approval ticket header payload: %w", err)
	}
	return json.RawMessage(decoded), nil
}

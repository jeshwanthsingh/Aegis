package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/mdlayher/vsock"
)

// ProxyRequest is the JSON structure sent from guest to host over vsock port 1025.
// The header shape matches the existing guest-proxy wire format.
type ProxyRequest struct {
	Method     string              `json:"method"`
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
}

// ProxyResponse is sent back from host to guest.
type ProxyResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
	Error      string              `json:"error,omitempty"`
}

var allowedHosts = map[string]bool{
	"pypi.org":               true,
	"files.pythonhosted.org": true,
	"registry.npmjs.org":     true,
	"registry.yarnpkg.com":   true,
}

func StartProxyHandler(ctx context.Context, guestCID uint32, executionID string) error {
	listener, err := vsock.Listen(1025, nil)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("proxy accept: %w", err)
		}

		if addr, ok := conn.RemoteAddr().(*vsock.Addr); ok && guestCID != 0 && addr.ContextID != guestCID {
			log.Printf("[%s] proxy rejected unexpected CID=%d", executionID, addr.ContextID)
			_ = conn.Close()
			continue
		}

		go handleProxyConn(ctx, conn, executionID)
	}
}

func handleProxyConn(ctx context.Context, conn net.Conn, executionID string) {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	for {
		var req ProxyRequest
		if err := dec.Decode(&req); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("[%s] proxy decode: %v", executionID, err)
			}
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		if strings.EqualFold(req.Method, http.MethodConnect) {
			handleConnectTunnel(conn, enc, req, executionID)
			return
		}

		resp := forwardHTTPRequest(req, executionID)
		if err := enc.Encode(resp); err != nil {
			log.Printf("[%s] proxy encode: %v", executionID, err)
			return
		}
	}
}

func forwardHTTPRequest(req ProxyRequest, executionID string) ProxyResponse {
	parsed, err := url.Parse(req.URL)
	if err != nil {
		return ProxyResponse{StatusCode: http.StatusBadRequest, Error: "invalid url"}
	}

	host := parsed.Hostname()
	if !allowedHosts[host] {
		log.Printf("[%s] proxy blocked url=%s", executionID, req.URL)
		return ProxyResponse{StatusCode: http.StatusForbidden, Error: "blocked"}
	}

	body, err := decodeBody(req.BodyBase64)
	if err != nil {
		return ProxyResponse{StatusCode: http.StatusBadRequest, Error: "invalid body"}
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(body))
	if err != nil {
		return ProxyResponse{StatusCode: http.StatusBadRequest, Error: "invalid request"}
	}
	for k, vals := range req.Headers {
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return ProxyResponse{StatusCode: http.StatusBadGateway, Error: err.Error()}
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return ProxyResponse{StatusCode: http.StatusBadGateway, Error: err.Error()}
	}

	return ProxyResponse{
		StatusCode: httpResp.StatusCode,
		Headers:    httpResp.Header,
		BodyBase64: base64.StdEncoding.EncodeToString(respBody),
	}
}

func handleConnectTunnel(conn net.Conn, enc *json.Encoder, req ProxyRequest, executionID string) {
	host := connectHost(req.URL)
	if !allowedHosts[host] {
		log.Printf("[%s] proxy blocked url=%s", executionID, req.URL)
		_ = enc.Encode(ProxyResponse{StatusCode: http.StatusForbidden, Error: "blocked"})
		return
	}

	upstream, err := net.Dial("tcp", req.URL)
	if err != nil {
		_ = enc.Encode(ProxyResponse{StatusCode: http.StatusBadGateway, Error: err.Error()})
		return
	}
	defer upstream.Close()

	if err := enc.Encode(ProxyResponse{StatusCode: http.StatusOK}); err != nil {
		return
	}

	errCh := make(chan error, 2)
	go pipeTunnel(errCh, upstream, conn)
	go pipeTunnel(errCh, conn, upstream)
	<-errCh
}

func pipeTunnel(errCh chan<- error, dst net.Conn, src net.Conn) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

func decodeBody(bodyBase64 string) ([]byte, error) {
	if bodyBase64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(bodyBase64)
}

func connectHost(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err == nil {
		return host
	}
	return target
}

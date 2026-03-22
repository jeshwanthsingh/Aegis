package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/mdlayher/vsock"
)

const (
	listenAddr    = "127.0.0.1:8888"
	hostCID       = 2
	hostProxyPort = 1025
)

type ProxyRequest struct {
	Method     string              `json:"method"`
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64,omitempty"`
}

type ProxyResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64,omitempty"`
	Error      string              `json:"error,omitempty"`
}

func main() {
	server := &http.Server{Addr: listenAddr, Handler: http.HandlerFunc(handleProxy)}
	log.Printf("guest-proxy listening on %s", listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleConnect(w, r)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	conn, err := vsock.Dial(hostCID, hostProxyPort, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("vsock dial: %v", err), http.StatusBadGateway)
		return
	}
	defer conn.Close()

	msg := ProxyRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: r.Header,
	}
	if len(body) > 0 {
		msg.BodyBase64 = base64.StdEncoding.EncodeToString(body)
	}
	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		http.Error(w, fmt.Sprintf("encode request: %v", err), http.StatusBadGateway)
		return
	}

	var resp ProxyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		http.Error(w, fmt.Sprintf("decode response: %v", err), http.StatusBadGateway)
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
	w.WriteHeader(resp.StatusCode)
	if resp.BodyBase64 == "" {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
	if err != nil {
		http.Error(w, fmt.Sprintf("decode body: %v", err), http.StatusBadGateway)
		return
	}
	_, _ = w.Write(decoded)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}

	guestConn, err := vsock.Dial(hostCID, hostProxyPort, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("vsock dial: %v", err), http.StatusBadGateway)
		return
	}

	msg := ProxyRequest{
		Method:  http.MethodConnect,
		URL:     r.Host,
		Headers: r.Header,
	}
	if err := json.NewEncoder(guestConn).Encode(msg); err != nil {
		_ = guestConn.Close()
		http.Error(w, fmt.Sprintf("encode connect: %v", err), http.StatusBadGateway)
		return
	}

	var resp ProxyResponse
	if err := json.NewDecoder(guestConn).Decode(&resp); err != nil {
		_ = guestConn.Close()
		http.Error(w, fmt.Sprintf("decode connect response: %v", err), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = guestConn.Close()
		status := resp.StatusCode
		if status == 0 {
			status = http.StatusBadGateway
		}
		http.Error(w, resp.Error, status)
		return
	}

	clientConn, rw, err := hj.Hijack()
	if err != nil {
		_ = guestConn.Close()
		return
	}
	defer clientConn.Close()
	defer guestConn.Close()

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	if rw.Reader.Buffered() > 0 {
		if _, err := io.CopyN(guestConn, rw, int64(rw.Reader.Buffered())); err != nil {
			return
		}
	}

	errCh := make(chan error, 2)
	go proxyStream(errCh, guestConn, clientConn)
	go proxyStream(errCh, clientConn, guestConn)
	<-errCh
}

func proxyStream(errCh chan<- error, dst io.Writer, src io.Reader) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

var _ http.Hijacker = (*responseWriterHijackGuard)(nil)

type responseWriterHijackGuard struct{}

func (*responseWriterHijackGuard) Header() http.Header         { return http.Header{} }
func (*responseWriterHijackGuard) Write([]byte) (int, error)   { return 0, nil }
func (*responseWriterHijackGuard) WriteHeader(statusCode int)  {}
func (*responseWriterHijackGuard) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

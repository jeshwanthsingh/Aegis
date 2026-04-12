package broker

// BrokerRequest is the wire protocol sent by the guest proxy over vsock.
// It matches the ProxyRequest format used by guest-proxy/main.go.
type BrokerRequest struct {
	Method     string              `json:"method"`
	URL        string              `json:"url"`
	ActionType string              `json:"action_type,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	BodyBase64 string              `json:"body_base64,omitempty"`
}

// BrokerResponse is the wire protocol returned to the guest proxy over vsock.
// It matches the ProxyResponse format used by guest-proxy/main.go.
type BrokerResponse struct {
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	BodyBase64 string              `json:"body_base64,omitempty"`
	Allowed    bool                `json:"allowed"`
	Denied     bool                `json:"denied,omitempty"`
	DenyReason string              `json:"deny_reason,omitempty"`
	Error      string              `json:"error,omitempty"`
}

package dsse

const (
	StatementType = "https://in-toto.io/Statement/v1"
	PayloadType   = "application/vnd.in-toto+json"
)

type StatementSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

package dsse

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func KeyIDFromPublicKey(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "ed25519:" + hex.EncodeToString(digest[:8])
}

func SignEnvelope(payloadType string, payload []byte, privateKey ed25519.PrivateKey) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("invalid ed25519 private key length %d", len(privateKey))
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return Envelope{}, fmt.Errorf("ed25519 private key did not expose a public key")
	}
	signature := ed25519.Sign(privateKey, PAE(payloadType, payload))
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: KeyIDFromPublicKey(publicKey),
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	}, nil
}

func VerifyEnvelope(env Envelope, publicKey ed25519.PublicKey) ([]byte, Signature, error) {
	if len(env.Signatures) == 0 {
		return nil, Signature{}, fmt.Errorf("dsse envelope has no signatures")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, Signature{}, fmt.Errorf("decode dsse payload: %w", err)
	}
	signature := env.Signatures[0]
	sig, err := base64.StdEncoding.DecodeString(signature.Sig)
	if err != nil {
		return nil, Signature{}, fmt.Errorf("decode dsse signature: %w", err)
	}
	if !ed25519.Verify(publicKey, PAE(env.PayloadType, payload), sig) {
		return nil, Signature{}, fmt.Errorf("dsse signature verification failed")
	}
	return payload, signature, nil
}

package receipt

import (
	"encoding/json"
	"testing"
)

func FuzzParseSignedReceiptJSON(f *testing.F) {
	signer, err := NewSigner(SigningConfig{Mode: SigningModeDev})
	if err == nil {
		signed, buildErr := BuildSignedReceipt(testReceiptInput(), signer)
		if buildErr == nil {
			if raw, marshalErr := json.Marshal(signed); marshalErr == nil {
				f.Add(raw)
			}
		}
	}
	f.Add([]byte(`{"envelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]},"statement":{"_type":"bad"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSignedReceiptJSON(data)
	})
}

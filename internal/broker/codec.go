package broker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func DecodeBrokerRequestJSON(raw []byte) (BrokerRequest, error) {
	var req BrokerRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return BrokerRequest{}, fmt.Errorf("decode broker request: %w", err)
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return BrokerRequest{}, fmt.Errorf("decode broker request: trailing content")
		}
		return BrokerRequest{}, fmt.Errorf("decode broker request: trailing content: %w", err)
	}
	return req, nil
}

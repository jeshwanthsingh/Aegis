package broker

import (
	"encoding/json"
	"io"
)

func EncodeBrokerResponse(w io.Writer, resp BrokerResponse) error {
	return json.NewEncoder(w).Encode(resp)
}

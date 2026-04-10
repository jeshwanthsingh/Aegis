package api

import (
	"encoding/json"
	"io"
	"net/http"

	"aegis/internal/observability"
)

type APIError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type ErrorEnvelope struct {
	Error APIError `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		observability.Error("api_write_json_failed", observability.Fields{
			"status": status,
			"error":  err.Error(),
		})
	}
}

func writeAPIError(w http.ResponseWriter, status int, code string, message string, details map[string]any) {
	writeJSON(w, status, ErrorEnvelope{Error: APIError{Code: code, Message: message, Details: details}})
}

func errorDetails(kv ...any) map[string]any {
	if len(kv) == 0 {
		return nil
	}
	details := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok || key == "" {
			continue
		}
		details[key] = kv[i+1]
	}
	if len(details) == 0 {
		return nil
	}
	return details
}

func decodeJSONBody(body io.Reader, dst any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

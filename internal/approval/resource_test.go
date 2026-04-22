package approval

import (
	"strings"
	"testing"
)

func TestHTTPPublicRepresentationsSanitizeQueryStrings(t *testing.T) {
	resource, err := CanonicalizeHTTPRequest(HTTPRequestInput{
		Method: "GET",
		URL:    "https://api.example.com/v1/data?token=super-secret&sig=abc123",
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	audit := ResourceToAuditPayload(resource.Resource)
	for key, value := range audit {
		if strings.Contains(value, "super-secret") || strings.Contains(value, "abc123") {
			t.Fatalf("audit payload leaked query data in %s=%q", key, value)
		}
	}
	if got := CanonicalRequestDescription(resource.Resource); strings.Contains(got, "super-secret") || strings.Contains(got, "abc123") {
		t.Fatalf("CanonicalRequestDescription leaked query data: %s", got)
	}
	if got := PublicHTTPURLString(resource.Resource.HTTP.URL); got != "https://api.example.com/v1/data?query_keys=2" {
		t.Fatalf("PublicHTTPURLString = %q", got)
	}
}

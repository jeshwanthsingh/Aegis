package broker

import "testing"

func TestDecodeBrokerRequestJSON(t *testing.T) {
	if _, err := DecodeBrokerRequestJSON([]byte(`{"method":"GET","url":"https://api.example.com"}`)); err != nil {
		t.Fatalf("DecodeBrokerRequestJSON(valid): %v", err)
	}
	if _, err := DecodeBrokerRequestJSON([]byte(`{"method":"GET","url":"https://api.example.com","extra":true}`)); err == nil {
		t.Fatal("expected unknown field error")
	}
	if _, err := DecodeBrokerRequestJSON([]byte(`{"method":"GET","url":"https://api.example.com"} []`)); err == nil {
		t.Fatal("expected trailing content error")
	}
}

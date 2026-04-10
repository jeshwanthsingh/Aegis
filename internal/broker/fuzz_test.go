package broker

import "testing"

func FuzzDecodeBrokerRequestJSON(f *testing.F) {
	f.Add([]byte(`{"method":"GET","url":"https://api.example.com","headers":{"X-Test":["1"]}}`))
	f.Add([]byte(`{"method":"POST","url":"http://127.0.0.1:8080","body_base64":"aGk="}`))
	f.Add([]byte(`{"method":"CONNECT","url":"example.com:443"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeBrokerRequestJSON(data)
	})
}

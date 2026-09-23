package providercontract

import "testing"

func TestUsesSystemCurlMatchesCurrentAndHistoricalConfirmedEndpoints(t *testing.T) {
	if !UsesSystemCurl("https://api.deepseek.com/v1/chat/completions") {
		t.Fatal("current confirmed endpoint did not select system curl")
	}
	if !usesSystemCurlHash("920e0c1e70779d4a54b31b65e76846aa66665726deedadd73eb1253524c84133") {
		t.Fatal("historical confirmed endpoint hash did not select system curl")
	}
	for _, endpoint := range []string{
		"https://api.deepseek.com/chat/completions",
		"https://api.deepseek.com/v1/models",
		"https://api.deepseek.com.evil.example/v1/chat/completions",
	} {
		if UsesSystemCurl(endpoint) {
			t.Fatalf("unconfirmed endpoint selected system curl: %s", endpoint)
		}
	}
}

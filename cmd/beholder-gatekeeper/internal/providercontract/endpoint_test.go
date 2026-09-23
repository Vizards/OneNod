package providercontract

import "testing"

func TestUsesSystemCurlMatchesOnlyConfirmedDeepSeekEndpoint(t *testing.T) {
	if !UsesSystemCurl("https://api.deepseek.com/v1/chat/completions") {
		t.Fatal("confirmed DeepSeek endpoint did not select system curl")
	}
	for _, endpoint := range []string{
		"https://llm.home.vizards.cc/v1/chat/completions",
		"https://api.deepseek.com/chat/completions",
		"https://api.deepseek.com/v1/models",
		"https://api.deepseek.com.evil.example/v1/chat/completions",
	} {
		if UsesSystemCurl(endpoint) {
			t.Fatalf("unconfirmed endpoint selected system curl: %s", endpoint)
		}
	}
}

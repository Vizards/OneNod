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

func TestUsesConfiguredSystemCurlAcceptsOnlyExactConfiguredHTTPS(t *testing.T) {
	configured := "https://provider.example.test/v1/chat/completions"
	if !UsesConfiguredSystemCurl(configured, configured) {
		t.Fatal("exact configured HTTPS endpoint did not select system curl")
	}
	for _, endpoint := range []string{
		"http://provider.example.test/v1/chat/completions",
		"https://other.example.test/v1/chat/completions",
		"https://user@provider.example.test/v1/chat/completions",
		"https://provider.example.test/v1/chat/completions?target=other",
	} {
		if UsesConfiguredSystemCurl(endpoint, configured) {
			t.Fatalf("unconfigured endpoint selected system curl: %s", endpoint)
		}
	}
}

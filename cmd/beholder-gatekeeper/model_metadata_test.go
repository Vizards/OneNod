package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestProviderModelMetadataDoesNotGateDecisions(t *testing.T) {
	for _, retrieval := range []bool{false, true} {
		profile := "compact"
		if retrieval {
			profile = "retrieval"
		}
		for _, metadata := range []struct {
			name  string
			value json.RawMessage
		}{
			{"resolved-alias", json.RawMessage(`"deepseek-v4.1-flash"`)},
			{"different-name", json.RawMessage(`"provider-model-label"`)},
			{"omitted", nil},
			{"empty", json.RawMessage(`""`)},
			{"null", json.RawMessage(`null`)},
			{"non-string", json.RawMessage(`{"name":"provider-model-label"}`)},
		} {
			for _, decision := range []string{"allow", "escalate"} {
				t.Run(profile+"/"+metadata.name+"/"+decision, func(t *testing.T) {
					config := validTestConfig()
					request := liveRequestFixture(writeSessionFixture(t, []map[string]any{
						messageFixture("user", "", "Current human request: read the match fixture."),
					}))
					if retrieval {
						config = validRetrievalTestConfig()
						request = retrievalFixtureRequest(t)
					}
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						var input struct {
							Model    string            `json:"model"`
							Messages []json.RawMessage `json:"messages"`
						}
						if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Model != config.Model.PrimaryID {
							t.Errorf("configured request model changed: %+v, %v", input, err)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						finish := "stop"
						content, _ := json.Marshal(map[string]string{"decision": decision, "reason": "Fixture decision."})
						message := map[string]any{"role": "assistant", "content": string(content)}
						if retrieval && len(input.Messages) == 2 {
							finish, message = "tool_calls", retrievalCallsMessage("read")
						}
						reply := map[string]any{"choices": []any{map[string]any{"finish_reason": finish, "message": message}}}
						if metadata.value != nil {
							reply["model"] = metadata.value
						}
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(reply)
					}))
					defer server.Close()
					service, err := newGatekeeperService(config, confirmedConfigSHA256, []byte("fixture-gatekeeper-key-1234567890"), nil, nil, testEvidenceStore(t))
					if err != nil {
						t.Fatal(err)
					}
					defer service.close()
					service.endpoint = server.URL
					result := service.decide(request)
					service.jobs.Wait()
					if result.ErrorCode != nil || !result.ModelUsed || result.Decision != decision {
						t.Fatalf("model metadata changed the decision: %+v", result)
					}
					if retrieval && (result.ModelRounds != 2 || result.ToolCalls != 2) {
						t.Fatalf("model metadata interrupted retrieval: %+v", result)
					}
					bundle, err := service.evidence.findBundleLocked(request.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					for _, variant := range []modelCallVariant{primaryModelVariant, comparisonModelVariant} {
						encoded, err := os.ReadFile(filepath.Join(bundle, variant.responseFile))
						var evidence modelResponseEvidence
						if err != nil || json.Unmarshal(encoded, &evidence) != nil || evidence.ParserError != nil ||
							!evidence.ModelUsed || evidence.Decision != decision {
							t.Fatalf("variant decision failed: %s, %+v, %v", variant.name, evidence, err)
						}
						var body map[string]json.RawMessage
						if err := json.Unmarshal(evidence.Body, &body); err != nil {
							t.Fatal(err)
						}
						value, present := body["model"]
						var actual, expected any
						_ = json.Unmarshal(value, &actual)
						_ = json.Unmarshal(metadata.value, &expected)
						if present != (metadata.value != nil) || !reflect.DeepEqual(actual, expected) {
							t.Fatalf("provider metadata was changed in evidence: %s, %s", variant.name, value)
						}
					}
				})
			}
		}
	}
}

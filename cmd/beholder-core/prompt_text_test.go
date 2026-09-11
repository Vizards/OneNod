package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestImageMessageProtectedPromptRecovery(t *testing.T) {
	data, err := os.ReadFile("../testdata/beholder-prompt-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string
		Prompt  string
		Content json.RawMessage
		Accept  bool
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session.jsonl")
			event, err := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{
				"type": "message", "role": "user", "content": test.Content,
			}})
			if err != nil {
				t.Fatal(err)
			}
			transcript := append([]byte("{\"type\":\"event_msg\",\"payload\":{\"type\":\"task_started\",\"turn_id\":\"fixture-turn\"}}\n"), event...)
			if err := os.WriteFile(path, append(transcript, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(test.Prompt))
			proof := promptProof{TurnID: "fixture-turn", TranscriptPath: path, PromptSHA256: hex.EncodeToString(digest[:])}
			recovered, err := recoverVerifiedPrompt(proof)
			defer clear(recovered)
			if !test.Accept {
				if err == nil {
					t.Fatal("a different prompt passed the protected digest check")
				}
				return
			}
			if err != nil || string(recovered) != test.Prompt {
				t.Fatalf("protected prompt was not restored exactly: %v", err)
			}
			proof.TurnID = "different-turn"
			if recovered, err := recoverVerifiedPrompt(proof); err == nil {
				clear(recovered)
				t.Fatal("image normalization crossed the protected turn boundary")
			}
		})
	}
}

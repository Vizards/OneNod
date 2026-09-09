package modelcontract

import (
	"encoding/json"
	"errors"
)

const DirectInputProfile = "three-domain-direct-no-tools-v1"

// DirectModelInput projects captured source evidence into the provider input.
// It preserves all domains except completed tool activity and adds explicit
// delivery accounting without changing the original capture's coverage.
func DirectModelInput(captured []byte) ([]byte, error) {
	var root, core, context, coverage map[string]json.RawMessage
	if json.Unmarshal(captured, &root) != nil ||
		json.Unmarshal(root["core_verified_facts"], &core) != nil ||
		json.Unmarshal(core["captured_context"], &context) != nil || context == nil {
		return nil, errors.New("invalid captured model input")
	}
	var history []json.RawMessage
	if raw := context["completed_tool_activity"]; len(raw) != 0 && json.Unmarshal(raw, &history) != nil {
		return nil, errors.New("invalid captured tool history")
	}
	if raw := context["coverage"]; len(raw) != 0 && json.Unmarshal(raw, &coverage) != nil {
		return nil, errors.New("invalid capture coverage")
	}
	if coverage == nil {
		coverage = make(map[string]json.RawMessage)
	}
	delivery, _ := json.Marshal(struct {
		Profile string `json:"profile"`
		Omitted int    `json:"completed_tool_records_omitted"`
	}{DirectInputProfile, len(history)})
	coverage["model_delivery"] = delivery
	context["completed_tool_activity"] = json.RawMessage(`[]`)
	context["coverage"], _ = json.Marshal(coverage)
	core["captured_context"], _ = json.Marshal(context)
	root["core_verified_facts"], _ = json.Marshal(core)
	return json.Marshal(root)
}

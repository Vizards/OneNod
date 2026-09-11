package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/retrieval"
)

type retrievalToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type retrievalCompletion struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string          `json:"finish_reason"`
		Message      json.RawMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		CompletionTokensDetails struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
}

type retrievalMessage struct {
	Role             string              `json:"role"`
	Content          string              `json:"content"`
	ReasoningContent string              `json:"reasoning_content"`
	ToolCalls        []retrievalToolCall `json:"tool_calls"`
}

type retrievalToolEvidence struct {
	CallID        string           `json:"tool_call_id"`
	Name          string           `json:"name"`
	Arguments     json.RawMessage  `json:"arguments"`
	ArgumentsText string           `json:"arguments_text"`
	Result        retrieval.Result `json:"-"`
	Content       string           `json:"serialized_content"`
	LatencyMS     float64          `json:"local_ms"`
}

func messageJSON(role, content string) json.RawMessage {
	value, _ := json.Marshal(modelMessage{Role: role, Content: content})
	return value
}

func (service *gatekeeperService) callRetrievalModel(content []byte, bundle *evidenceBundle, evidenceID string, variant modelCallVariant, deadlines ...time.Time) (result modelCallResult) {
	started := time.Now()
	result = failedModelCallResult("model-not-completed", 0)
	var finalBody []byte
	var finalHeaders map[string]string
	truncated := false
	requestRecorded := false
	defer func() {
		result.latencyMS = time.Since(started).Milliseconds()
		if !requestRecorded {
			_ = service.writeFailedModelRequestVariant(bundle, evidenceID, started, result.errorCode, variant)
		}
		if err := service.finishEvidenceBundleVariant(bundle, localResponseFromModelResult(evidenceID, result), finalBody, result.httpStatus, optionalString(result.errorCode), truncated, variant, finalHeaders); err != nil {
			result.decision = "escalate"
			result.modelUsed = false
			result.errorCode = "evidence-model-response-write-failed"
			result.reason = localFailureReason(result.errorCode)
		}
		clear(finalBody)
	}()
	fail := func(code, shape string) {
		result.errorCode = code
		result.reason = localFailureReason(code)
		result.responseShape = shape
		result.decision = "escalate"
		result.modelUsed = false
	}
	if bundle == nil || bundle.retrieval == nil {
		fail("retrieval-snapshot-unavailable", "not-called")
		return
	}
	timeout := service.config.Invocation.TimeoutMS
	if variant.name == comparisonVariantName {
		timeout = service.config.Comparison.TimeoutMS
	}
	deadline := started.Add(time.Duration(timeout) * time.Millisecond)
	for _, d := range deadlines {
		if !d.IsZero() && d.Before(deadline) {
			deadline = d
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	messages := []json.RawMessage{messageJSON("system", retrievalSystemPrompt), messageJSON("user", string(content))}
	defer func() {
		for _, message := range messages {
			clear(message)
		}
	}()
	readEvidence := false
	seenCallIDs := map[string]bool{}
	for round := 1; round <= maximumRetrievalRounds; round++ {
		if ctx.Err() != nil {
			fail("gatekeeper-decision-budget-exhausted", "deadline-exhausted")
			return
		}
		requestValue := struct {
			Model    string            `json:"model"`
			Messages []json.RawMessage `json:"messages"`
			Stream   bool              `json:"stream"`
			Thinking struct {
				Type string `json:"type"`
			} `json:"thinking"`
			ResponseFormat struct {
				Type string `json:"type"`
			} `json:"response_format"`
			Tools      json.RawMessage `json:"tools"`
			ToolChoice string          `json:"tool_choice"`
		}{Model: service.config.Model.PrimaryID, Messages: messages, Tools: retrieval.Tools(), ToolChoice: "auto", ResponseFormat: service.config.Invocation.ResponseFormat}
		requestValue.Thinking.Type = variant.thinkingType
		body, err := json.Marshal(requestValue)
		if err != nil || len(body) > maximumModelRequestBytes {
			clear(body)
			fail("model-request-too-large", "request-capacity-exceeded")
			return
		}
		if round == 1 {
			if err := service.writeExactModelRequestVariant(bundle, evidenceID, started, body, true, nil, variant); err != nil {
				clear(body)
				fail("evidence-model-request-write-failed", "not-called")
				return
			}
			requestRecorded = true
		}
		length, digest, raw, parsed := rawBodyFields(body)
		requestRecord := modelRequestEvidence{SchemaVersion: 1, RecordType: "beholder_model_request", EvidenceID: evidenceID, Variant: variant.name,
			Method: http.MethodPost, Endpoint: service.endpoint, ContentType: service.config.Invocation.ContentType, StartedAt: time.Now().UTC(),
			RequestSent: true, BodyBytes: length, BodySHA256: digest, RawBodyBase64: raw, Body: parsed}
		if err := bundle.writeRetrievalRound(variant, round, "request", requestRecord); err != nil {
			clear(body)
			fail("evidence-model-request-write-failed", "not-called")
			return
		}
		clear(parsed)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, service.endpoint, bytes.NewReader(body))
		if err != nil {
			clear(body)
			fail("model-request-build-failed", "not-called")
			return
		}
		request.Header.Set("Content-Type", service.config.Invocation.ContentType)
		result.modelCalled = true
		result.modelRounds = round
		var response *http.Response
		if useSystemCurlProviderTransport(service.endpoint) {
			result.modelTransport = "system-curl"
			response, err = systemCurlProviderRoundTrip(ctx, request, service.config.Invocation.ContentType, service.apiKey, body)
		} else {
			result.modelTransport = "go-http"
			request.Header.Set("Authorization", "Bearer "+string(service.apiKey))
			response, err = service.httpClient.Do(request)
			request.Header.Del("Authorization")
		}
		clear(body)
		clear(finalBody)
		finalBody = nil
		finalHeaders = nil
		truncated = false
		result.httpStatus = 0
		if err != nil {
			result.transportDetail = safeModelTransportError(err, service.apiKey)
			code := "model-transport-error"
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				code = "model-timeout"
			}
			fail(code, "transport-error")
		} else {
			result.httpStatus = response.StatusCode
			finalHeaders = safeResponseHeaders(response.Header)
			finalBody, err = io.ReadAll(io.LimitReader(response.Body, maximumModelResponseSize+1))
			_ = response.Body.Close()
			if err != nil || len(finalBody) > maximumModelResponseSize {
				if len(finalBody) > maximumModelResponseSize {
					finalBody = finalBody[:maximumModelResponseSize]
					truncated = true
				}
				fail("model-response-unreadable", "response-unreadable")
			} else if response.StatusCode < 200 || response.StatusCode >= 300 {
				fail(fmt.Sprintf("model-http-%d", response.StatusCode), "http-error")
			} else {
				result.errorCode = ""
			}
		}
		length, digest, raw, parsed = rawBodyFields(finalBody)
		responseRecord := modelResponseEvidence{SchemaVersion: 1, RecordType: "beholder_model_response", EvidenceID: evidenceID, Variant: variant.name,
			ReceivedAt: time.Now().UTC(), HTTPStatus: result.httpStatus, Headers: finalHeaders, BodyBytes: length, BodySHA256: digest, RawBodyBase64: raw, Body: parsed,
			BodyTruncated: truncated, ParserError: optionalString(result.errorCode), ModelCalled: true, ModelTransport: result.modelTransport, TransportDetail: optionalString(result.transportDetail)}
		if err := bundle.writeRetrievalRound(variant, round, "response", responseRecord); err != nil {
			clear(parsed)
			fail("evidence-model-response-write-failed", "evidence-write-failed")
			return
		}
		clear(parsed)
		if result.errorCode != "" {
			return
		}
		var completion retrievalCompletion
		if json.Unmarshal(finalBody, &completion) != nil {
			fail("model-outer-json-invalid", "outer-json-invalid")
			return
		}
		if completion.Model != service.config.Model.PrimaryID {
			fail("model-identity-mismatch", "model-identity-mismatch")
			return
		}
		if len(completion.Choices) != 1 {
			fail("model-choices-count-invalid", "choices-count-invalid")
			return
		}
		choice := completion.Choices[0]
		var message retrievalMessage
		if json.Unmarshal(choice.Message, &message) != nil || message.Role != "assistant" {
			fail("model-message-invalid", "message-invalid")
			return
		}
		result.finishReason = normalizeFinishReason(choice.FinishReason)
		result.reasoningBytes += len(message.ReasoningContent)
		result.reasoningPresent = result.reasoningPresent || strings.TrimSpace(message.ReasoningContent) != ""
		result.reasoningTokens += max(0, completion.Usage.CompletionTokensDetails.ReasoningTokens)
		if len(message.ToolCalls) > 0 {
			if choice.FinishReason != "tool_calls" {
				fail("model-tool-call-invalid", "tool-calls-incomplete")
				return
			}
			if len(message.ToolCalls) > maximumRoundToolCalls {
				fail("model-tool-call-capacity-exceeded", "tool-calls-invalid")
				return
			}
			for _, call := range message.ToolCalls {
				if call.Type != "function" || call.ID == "" || len(call.ID) > 1024 || seenCallIDs[call.ID] {
					fail("model-tool-call-invalid", "tool-calls-invalid")
					return
				}
				seenCallIDs[call.ID] = true
			}
			// Preserve the provider's entire assistant message, including its
			// reasoning_content and all parallel calls, across continuation.
			messages = append(messages, append(json.RawMessage(nil), choice.Message...))
			outputs := executeRetrievalCalls(ctx, bundle.retrieval.store, message.ToolCalls)
			result.toolCalls += len(outputs)
			if err := bundle.writeRetrievalRound(variant, round, "tools", outputs); err != nil {
				fail("evidence-tool-results-write-failed", "evidence-write-failed")
				return
			}
			for _, out := range outputs {
				if out.Result.Error == "" {
					readEvidence = true
				}
				result.toolLatencyMS += out.LatencyMS
				encoded, _ := json.Marshal(struct {
					Role    string `json:"role"`
					CallID  string `json:"tool_call_id"`
					Content string `json:"content"`
				}{"tool", out.CallID, out.Content})
				messages = append(messages, encoded)
			}
			continue
		}
		// A body containing DSML or a partial/non-JSON decision is never
		// converted into tool calls or repaired into an approval.
		var decision parsedModelDecision
		if choice.FinishReason != "stop" || !json.Valid([]byte(message.Content)) || json.Unmarshal([]byte(message.Content), &decision) != nil ||
			(decision.Decision != "allow" && decision.Decision != "escalate") || !validModelReason(decision.Reason) {
			fail("model-decision-invalid", "decision-json-invalid")
			return
		}
		if !readEvidence {
			fail("model-retrieval-unused", "decision-without-evidence-read")
			return
		}
		var refs []string
		if json.Unmarshal(decision.EvidenceRefs, &refs) == nil {
			for _, ref := range refs {
				if validRetrievalReference(ref) {
					result.evidenceRefs = append(result.evidenceRefs, ref)
				}
			}
		}
		result.decision = decision.Decision
		result.reason = decision.Reason
		result.errorCode = ""
		result.modelUsed = true
		result.responseShape = "decision-json-valid"
		return
	}
	fail("model-round-budget-exhausted", "round-budget-exhausted")
	return
}

func executeRetrievalCalls(ctx context.Context, store *retrieval.Store, calls []retrievalToolCall) []retrievalToolEvidence {
	outputs := make([]retrievalToolEvidence, len(calls))
	slots := make(chan struct{}, 8)
	var group sync.WaitGroup
	for i, call := range calls {
		group.Add(1)
		go func(i int, call retrievalToolCall) {
			defer group.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			started := time.Now()
			args := json.RawMessage(call.Function.Arguments)
			result := store.Call(ctx, call.Function.Name, args)
			content, _ := json.Marshal(result)
			if !json.Valid(args) {
				args = nil
			}
			outputs[i] = retrievalToolEvidence{CallID: call.ID, Name: call.Function.Name, Arguments: args, ArgumentsText: call.Function.Arguments, Result: result, Content: string(content), LatencyMS: float64(time.Since(started)) / float64(time.Millisecond)}
		}(i, call)
	}
	group.Wait()
	return outputs
}

func (bundle *evidenceBundle) writeRetrievalRound(variant modelCallVariant, round int, kind string, value any) error {
	if round < 1 || round > maximumRetrievalRounds || !oneOf(kind, "request", "response", "tools") || !oneOf(variant.name, primaryVariantName, comparisonVariantName) {
		return errors.New("invalid retrieval evidence round")
	}
	name := fmt.Sprintf("round-%s-%03d-%s.json", variant.name, round, kind)
	return bundle.writeStage(name, value, "collecting", nil, nil)
}

func validRetrievalReference(ref string) bool {
	if len(ref) > 256 {
		return false
	}
	for _, prefix := range []string{"session:L", "request:L"} {
		if digits, ok := strings.CutPrefix(ref, prefix); ok && digits != "" {
			for _, r := range digits {
				if r < '0' || r > '9' {
					return false
				}
			}
			return digits[0] != '0'
		}
	}
	return false
}

package main

import "errors"

// Resource accounting is independent of message count or content. Never discard
// human consent/revocation silently. Model-delivered text reserves its budget
// before historical tools, which are retained only as local evidence. Within
// each class, displacement is chronological and visible in evidence.
func enforceRelatedContextBudget(output *relatedContext) error {
	humanBytes := 0
	for _, entry := range output.priorHumans {
		humanBytes += len(entry.Text)
	}
	if humanBytes > maximumRelatedContextBytes {
		return errors.New("human-context-budget-exceeded")
	}
	type record struct {
		ordinal, bytes int
		kind           string
	}
	for {
		otherBytes := 0
		oldest := record{}
		oldestTool := record{}
		visit := func(ordinal, size int, kind string) {
			otherBytes += size
			if oldest.ordinal == 0 || ordinal < oldest.ordinal {
				oldest = record{ordinal, size, kind}
			}
		}
		for _, e := range output.priorAgentMessages {
			visit(e.Ordinal, len(e.Text), "prior")
		}
		for _, e := range output.currentAgentMessages {
			visit(e.Ordinal, len(e.Text), "current")
		}
		for _, e := range output.ambientContext {
			visit(e.Ordinal, len(e.Text), "ambient")
		}
		for _, e := range output.completedTools {
			visit(e.CallOrdinal, len(e.Input)+len(e.Output), "tool")
			if oldestTool.ordinal == 0 || e.CallOrdinal < oldestTool.ordinal {
				oldestTool = record{e.CallOrdinal, len(e.Input) + len(e.Output), "tool"}
			}
		}
		if humanBytes+otherBytes <= maximumRelatedContextBytes || oldest.ordinal == 0 {
			output.coverage.ByteBudget = maximumRelatedContextBytes
			output.coverage.HumanBytes, output.coverage.OtherBytes = humanBytes, otherBytes
			return nil
		}
		// An omitted tool must never evict text that the model will receive.
		if oldestTool.ordinal != 0 {
			oldest = oldestTool
		}
		// Preserve both ends of a large final tool record rather than silently
		// dropping its risk-bearing suffix. Smaller records remain unchanged.
		if oldest.kind == "tool" && len(output.completedTools) == 1 {
			available := maximumRelatedContextBytes - humanBytes - (otherBytes - oldest.bytes)
			if available >= 1024 {
				entry := &output.completedTools[0]
				inputBudget := available / 3
				if len(entry.Input) < inputBudget {
					inputBudget = len(entry.Input)
				}
				if inputBudget > 0 {
					entry.Input, _ = safeUTF8Text([]byte(entry.Input), inputBudget)
				}
				entry.Output, _ = safeUTF8Text([]byte(entry.Output), available-len(entry.Input))
				for i := range output.candidates {
					c := &output.candidates[i]
					if c.CallID == entry.CallID {
						c.Reason = "context-byte-budget-excerpt"
						if c.Ordinal == entry.CallOrdinal {
							c.Input = entry.Input
						} else {
							c.Output = entry.Output
						}
					}
				}
				continue
			}
		}
		output.coverage.OmittedRecords++
		remove := func(entries []sourceText) []sourceText {
			for i, e := range entries {
				if e.Ordinal == oldest.ordinal {
					return append(entries[:i], entries[i+1:]...)
				}
			}
			return entries
		}
		switch oldest.kind {
		case "prior":
			output.priorAgentMessages = remove(output.priorAgentMessages)
		case "current":
			output.currentAgentMessages = remove(output.currentAgentMessages)
		case "ambient":
			output.ambientContext = remove(output.ambientContext)
		case "tool":
			for i, e := range output.completedTools {
				if e.CallOrdinal == oldest.ordinal {
					displaceToolCandidates(output, e.CallID, "context-byte-budget")
					output.completedTools = append(output.completedTools[:i], output.completedTools[i+1:]...)
					break
				}
			}
		}
		displaceCandidateByOrdinal(output, oldest.ordinal, "context-byte-budget")
	}
}

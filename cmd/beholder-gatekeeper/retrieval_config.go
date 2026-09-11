package main

import "errors"

const retrievalComparisonRule = "Both variants start with byte-identical system, pending request and tool definitions over the same immutable snapshot; each selects its own reads and continuation."

func validateConfirmedConfig(config confirmedConfig) error {
	if config.Revision.ID == "E2-AI0-R15" && !config.Retrieval.Enabled {
		return validateCompactConfig(config)
	}
	if config.Revision.ID != "E2-AI0-R16" ||
		config.Revision.SupersedesConfigSHA256 != "bc2efe4f48d937dc51200fd51c3e15b8adfb4c55ff98f89b904c3d614c8de896" ||
		config.Model.PrimaryID != "deepseek-flash" || config.Comparison.ModelID != "deepseek-flash" ||
		config.Invocation.TimeoutMS != 30000 || config.Comparison.TimeoutMS != 180000 ||
		config.Comparison.SaturationBehavior != "skip-observation" ||
		config.Messages.ModelInputSchemaVersion != 1 ||
		!equalStringSlices(config.Messages.TopLevelProvenanceDomains, []string{"pending_request"}) ||
		config.Messages.UserMessageOrder != "model-selected; newest-first by default" ||
		config.Messages.LatestMessageIndexPointsToLast || config.Messages.ComparisonRule != retrievalComparisonRule ||
		config.Response.AcceptValidDecisionOnNonStop ||
		!equalStringSlices(config.Response.AllowedEvidenceRefRoots, []string{"session", "request"}) ||
		!config.Retrieval.Enabled || config.Retrieval.MaximumRounds != maximumRetrievalRounds ||
		config.Retrieval.MaximumParallelTools != 8 || config.Retrieval.MaximumCallsPerRound != maximumRoundToolCalls ||
		config.Retrieval.PageCharacters != 128000 || config.Retrieval.MaximumSnapshotBytes != maximumRetrievalSnapshotBytes ||
		config.Retrieval.MaximumRequestBytes != maximumModelRequestBytes || config.Retrieval.PrefetchHistory ||
		config.Retrieval.GeneratedSummary || config.Retrieval.ToolChoice != "auto" || !config.Retrieval.PersistEveryRound {
		return errors.New("E2-AI0 retrieval configuration does not match the deployment contract")
	}
	// Validate unchanged transport, authority and evidence requirements against
	// the preceding compact contract. That contract remains useful for offline
	// replay; loadProductionConfig only accepts the new pinned revision.
	config.Revision.ID = "E2-AI0-R15"
	config.Revision.SupersedesConfigSHA256 = "29b16bfafb4a17c25dfd1b1ecd5a117f4b4696e4c3734da1f9ff9724bc92f542"
	config.Model.PrimaryID, config.Comparison.ModelID = "deepseek-v4-flash", "deepseek-v4-flash"
	config.Invocation.TimeoutMS, config.Comparison.TimeoutMS = 10000, 600000
	config.Messages.ModelInputSchemaVersion = externalDecisionInputSchemaVersion
	config.Messages.TopLevelProvenanceDomains = []string{"user_messages", "assistant_messages", "core_verified_facts"}
	config.Messages.UserMessageOrder = userMessageOrder
	config.Messages.LatestMessageIndexPointsToLast = true
	config.Messages.ComparisonRule = "Both variants receive byte-identical system and user messages; only thinking.type and non-authoritative execution timing differ."
	config.Response.AcceptValidDecisionOnNonStop = true
	config.Response.AllowedEvidenceRefRoots = allowedEvidenceRefRoots()
	return validateCompactConfig(config)
}

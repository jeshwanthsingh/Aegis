package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"aegis/internal/models"
	"aegis/internal/telemetry"
)

func BuildSignedReceipt(input Input, signer *Signer) (SignedReceipt, error) {
	if signer == nil {
		return SignedReceipt{}, fmt.Errorf("receipt signer is required")
	}
	predicate, runtimeEventCount, err := buildPredicate(input, signer)
	if err != nil {
		return SignedReceipt{}, err
	}
	statement := Statement{
		Type:          StatementType,
		Subject:       buildSubjects(input.OutputArtifacts),
		PredicateType: PredicateType,
		Predicate:     predicate,
	}
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return SignedReceipt{}, fmt.Errorf("marshal receipt statement: %w", err)
	}
	preAuth := pae(PayloadType, statementBytes)
	signature := ed25519.Sign(signer.PrivateKey, preAuth)
	envelope := Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(statementBytes),
		Signatures:  []Signature{{KeyID: signer.KeyID, Sig: base64.StdEncoding.EncodeToString(signature)}},
	}
	_ = runtimeEventCount
	return SignedReceipt{Envelope: envelope, Statement: statement}, nil
}

func buildPredicate(input Input, signer *Signer) (ExecutionReceiptPredicate, int, error) {
	intentDigest, intentAlgo := digestBytes(input.IntentRaw)
	evidenceDigest, runtimeEventCount, pointSummary, divergenceSummary, brokerSummary, governedSummary, err := summarizeTelemetry(input.TelemetryEvents)
	if err != nil {
		return ExecutionReceiptPredicate{}, 0, err
	}
	limitations := []string{"host attestation deferred"}
	if input.Outcome.OutputTruncated {
		limitations = append(limitations, "captured standard stream artifacts may be truncated")
	}
	if hasReadOnlyFileSemantics(input.TelemetryEvents) {
		limitations = append(limitations, "file.open semantics are read-only in RuntimeEvent v1")
	}
	metadata := cloneStringMap(input.Attributes)
	return ExecutionReceiptPredicate{
		Version:            PredicateVersion,
		ExecutionID:        input.ExecutionID,
		WorkflowID:         input.WorkflowID,
		Backend:            input.Backend,
		TaskClass:          input.TaskClass,
		DeclaredPurpose:    input.DeclaredPurpose,
		WorkspaceID:        input.WorkspaceID,
		IntentDigest:       intentDigest,
		IntentDigestAlgo:   intentAlgo,
		EvidenceDigest:     evidenceDigest,
		EvidenceDigestAlgo: "sha256",
		RuntimeEventCount:  runtimeEventCount,
		PointDecisions:     pointSummary,
		Divergence:         divergenceSummary,
		Outcome:            input.Outcome,
		BrokerSummary:      brokerSummary,
		GovernedActions:    governedSummary,
		Trust:              trustPostureForSigner(signer),
		Limitations:        limitations,
		StartedAt:          input.StartedAt.UTC(),
		FinishedAt:         input.FinishedAt.UTC(),
		SignerKeyID:        signer.KeyID,
		Metadata:           metadata,
	}, runtimeEventCount, nil
}

func buildSubjects(artifacts []Artifact) []StatementSubject {
	if len(artifacts) == 0 {
		return []StatementSubject{}
	}
	subjects := make([]StatementSubject, 0, len(artifacts))
	for _, artifact := range artifacts {
		subjects = append(subjects, StatementSubject{Name: artifact.Name, Digest: cloneStringMap(artifact.Digest)})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Name < subjects[j].Name })
	return subjects
}

func summarizeTelemetry(events []telemetry.Event) (string, int, PointDecisionSummary, DivergenceSummary, *BrokerSummary, *GovernedActionSummary, error) {
	canonical := make([]map[string]any, 0, len(events))
	pointSummary := PointDecisionSummary{}
	divergenceSummary := DivergenceSummary{Verdict: models.DivergenceAllow, TriggeredRuleIDs: []string{}}
	runtimeEventCount := 0
	allowedDomainsSet := map[string]struct{}{}
	deniedDomainsSet := map[string]struct{}{}
	bindingsUsedSet := map[string]struct{}{}
	brokerReqCount, brokerAllowedCount, brokerDeniedCount := 0, 0, 0
	governedActions := make([]GovernedActionRecord, 0)
	for _, event := range events {
		if event.Kind == telemetry.KindReceipt {
			continue
		}
		canonical = append(canonical, map[string]any{"kind": event.Kind, "data": json.RawMessage(event.Data)})
		switch event.Kind {
		case telemetry.KindRuntimeEvent:
			runtimeEventCount++
		case telemetry.KindPolicyPointDecision:
			var point models.PolicyPointDecision
			if err := json.Unmarshal(event.Data, &point); err != nil {
				return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("decode point decision: %w", err)
			}
			switch point.Decision {
			case models.DecisionAllow:
				pointSummary.AllowCount++
			case models.DecisionDeny:
				pointSummary.DenyCount++
			case models.DecisionNotApplicable:
				pointSummary.NotApplicableCount++
			}
		case telemetry.KindPolicyDivergence:
			var divergence models.PolicyDivergenceResult
			if err := json.Unmarshal(event.Data, &divergence); err != nil {
				return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("decode divergence result: %w", err)
			}
			ruleIDs := make([]string, 0, len(divergence.TriggeredRules))
			for _, hit := range divergence.TriggeredRules {
				ruleIDs = append(ruleIDs, hit.RuleID)
			}
			sort.Strings(ruleIDs)
			divergenceSummary = DivergenceSummary{Verdict: divergence.CurrentVerdict, TriggeredRuleIDs: ruleIDs, RuleHitCount: len(ruleIDs)}
		case telemetry.KindGovernedAction:
			var action telemetry.GovernedActionData
			if err := json.Unmarshal(event.Data, &action); err != nil {
				return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("decode governed action: %w", err)
			}
			governedActions = append(governedActions, GovernedActionRecord{
				ActionType:          action.ActionType,
				Target:              action.Target,
				Resource:            action.Resource,
				Method:              action.Method,
				Decision:            action.Decision,
				Reason:              action.Reason,
				RuleID:              action.RuleID,
				PolicyDigest:        action.PolicyDigest,
				Brokered:            action.Brokered,
				BrokeredCredentials: action.BrokeredCredentials,
				BindingName:         action.BindingName,
				ResponseDigest:      action.ResponseDigest,
				ResponseDigestAlgo:  action.ResponseDigestAlgo,
				DenialMarker:        action.DenialMarker,
				AuditPayload:        cloneStringMap(action.AuditPayload),
			})
		case telemetry.KindCredentialAllowed:
			var bd telemetry.CredentialBrokerData
			if json.Unmarshal(event.Data, &bd) == nil {
				brokerReqCount++
				brokerAllowedCount++
				if bd.TargetDomain != "" {
					allowedDomainsSet[bd.TargetDomain] = struct{}{}
				}
				if bd.BindingName != "" {
					bindingsUsedSet[bd.BindingName] = struct{}{}
				}
			}
		case telemetry.KindCredentialDenied:
			var bd telemetry.CredentialBrokerData
			if json.Unmarshal(event.Data, &bd) == nil {
				brokerReqCount++
				brokerDeniedCount++
				if bd.TargetDomain != "" {
					deniedDomainsSet[bd.TargetDomain] = struct{}{}
				}
			}
		}
	}
	bytes, err := json.Marshal(canonical)
	if err != nil {
		return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("marshal evidence summary: %w", err)
	}
	digest := sha256.Sum256(bytes)
	var bs *BrokerSummary
	if brokerReqCount > 0 {
		bs = &BrokerSummary{
			RequestCount:   brokerReqCount,
			AllowedCount:   brokerAllowedCount,
			DeniedCount:    brokerDeniedCount,
			DomainsAllowed: setToSortedSlice(allowedDomainsSet),
			DomainsDenied:  setToSortedSlice(deniedDomainsSet),
			BindingsUsed:   setToSortedSlice(bindingsUsedSet),
		}
	}
	var gs *GovernedActionSummary
	if len(governedActions) > 0 {
		gs = &GovernedActionSummary{Count: len(governedActions), Actions: governedActions}
	}
	return hex.EncodeToString(digest[:]), runtimeEventCount, pointSummary, divergenceSummary, bs, gs, nil
}

func hasReadOnlyFileSemantics(events []telemetry.Event) bool {
	for _, event := range events {
		if event.Kind != telemetry.KindPolicyPointDecision {
			continue
		}
		var point models.PolicyPointDecision
		if err := json.Unmarshal(event.Data, &point); err != nil {
			continue
		}
		if point.EventType == models.EventFileOpen {
			return true
		}
	}
	return false
}

func trustPostureForSigner(signer *Signer) TrustPosture {
	limitations := []string{"host_attestation_absent"}
	if signer.Mode == SigningModeDev {
		limitations = append(limitations, "dev_signing_mode")
	}
	if signer.KeySource == KeySourceDevFallback {
		limitations = append(limitations, "fallback_dev_seed")
	}
	return TrustPosture{
		SigningMode:          signer.Mode,
		KeySource:            signer.KeySource,
		Attestation:          "absent",
		VerificationMaterial: "ed25519_public_key",
		Limitations:          limitations,
	}
}

func digestBytes(raw []byte) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), "sha256"
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func trustLimitationsText(trust TrustPosture) string {
	if len(trust.Limitations) == 0 {
		return "none"
	}
	ordered := append([]string(nil), trust.Limitations...)
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func setToSortedSlice(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

package escalation

import (
	"reflect"
	"testing"
)

func TestSummarizeIsDeterministicUnderOrderingNoise(t *testing.T) {
	attemptsA := []Attempt{
		{Source: SourceGovernedAction, Signals: []Signal{SignalUnsupportedDestructiveClassAccess}, RuleID: "broker.host_action_unsupported", ActionType: "host_repo_apply_patch", CapabilityPath: "broker", HostActionClass: "host_file_delete"},
		{Source: SourceAuthorityMutation, Signals: []Signal{SignalAuthorityBroadeningAttempt}, MutationField: "rootfs_image", EnforcementPoint: "post_vm_acquisition"},
		{Source: SourceGovernedAction, Signals: []Signal{SignalDestructiveBoundaryProbe}, RuleID: "broker.host_action_path_escape", ActionType: "host_repo_apply_patch", CapabilityPath: "broker", Target: "repo:demo", Resource: "demo", HostActionClass: "host_repo_apply_patch"},
	}
	attemptsB := []Attempt{attemptsA[2], attemptsA[0], attemptsA[1]}

	summaryA := Summarize(attemptsA, terminationReasonAuthorityMutation)
	summaryB := Summarize(attemptsB, terminationReasonAuthorityMutation)

	if !reflect.DeepEqual(summaryA, summaryB) {
		t.Fatalf("summaries differ:\nA=%+v\nB=%+v", summaryA, summaryB)
	}
	if summaryA == nil || summaryA.EscalationAttempts == nil || summaryA.EscalationAttempts.Count != 3 {
		t.Fatalf("summary = %+v", summaryA)
	}
	if summaryA.TerminationReason != terminationReasonAuthorityMutation {
		t.Fatalf("termination_reason = %q", summaryA.TerminationReason)
	}
	if got, want := summaryA.DeniedDestructiveActions, []DestructiveActionClass{DestructiveActionHostFileDelete, DestructiveActionHostRepoApplyPatch}; !reflect.DeepEqual(got, want) {
		t.Fatalf("denied destructive actions = %v, want %v", got, want)
	}
}

func TestSummarizeCapsSampleAndSetsTruncationTruthfully(t *testing.T) {
	attempts := make([]Attempt, 0, SampleLimit+2)
	for i := 0; i < SampleLimit+2; i++ {
		attempts = append(attempts, Attempt{
			Source:           SourceGovernedAction,
			Signals:          []Signal{SignalDestructiveBoundaryProbe},
			RuleID:           "broker.host_action_path_escape",
			ActionType:       "host_repo_apply_patch",
			CapabilityPath:   "broker",
			Target:           "repo:demo",
			Resource:         "demo",
			HostActionClass:  "host_repo_apply_patch",
			MutationField:    "",
			EnforcementPoint: "",
		})
		attempts[i].Target = attempts[i].Target + string(rune('a'+i))
	}
	summary := Summarize(attempts, "")
	if summary == nil || summary.EscalationAttempts == nil {
		t.Fatalf("summary = %+v", summary)
	}
	if !summary.EscalationAttempts.SampleTruncated {
		t.Fatalf("sample_truncated = false, want true")
	}
	if len(summary.EscalationAttempts.Sample) != SampleLimit {
		t.Fatalf("sample len = %d, want %d", len(summary.EscalationAttempts.Sample), SampleLimit)
	}
}

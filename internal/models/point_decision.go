package models

type CedarAction string

const (
	ActionExec    CedarAction = "exec"
	ActionRead    CedarAction = "read"
	ActionWrite   CedarAction = "write"
	ActionConnect CedarAction = "connect"
)

type PointDecision string

const (
	DecisionAllow         PointDecision = "allow"
	DecisionDeny          PointDecision = "deny"
	DecisionNotApplicable PointDecision = "not_applicable"
)

type PolicyPointDecision struct {
	ExecutionID string            `json:"execution_id"`
	EventSeq    uint64            `json:"event_seq"`
	EventType   EventType         `json:"event_type"`
	CedarAction CedarAction       `json:"cedar_action"`
	Decision    PointDecision     `json:"decision"`
	Reason      string            `json:"reason"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

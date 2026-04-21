package hostaction

import (
	"errors"
	"fmt"
)

type Error struct {
	RuleID       string
	Detail       string
	AuditPayload map[string]string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail != "" {
		return e.Detail
	}
	return e.RuleID
}

func errorf(ruleID string, audit map[string]string, format string, args ...any) error {
	return &Error{
		RuleID:       ruleID,
		Detail:       fmt.Sprintf(format, args...),
		AuditPayload: audit,
	}
}

func NewError(ruleID string, audit map[string]string, format string, args ...any) error {
	return errorf(ruleID, audit, format, args...)
}

func AsError(err error, target **Error) bool {
	return err != nil && target != nil && errors.As(err, target)
}

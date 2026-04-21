package lease

import (
	"errors"
	"fmt"
)

var (
	ErrLeaseMissing      = errors.New("lease missing")
	ErrBudgetExhausted   = errors.New("lease budget exhausted")
	ErrLeaseUnavailable  = errors.New("lease unavailable")
)

func IsLeaseMissing(err error) bool {
	return err != nil && errors.Is(err, ErrLeaseMissing)
}

func IsBudgetExhausted(err error) bool {
	return err != nil && errors.Is(err, ErrBudgetExhausted)
}

func IsLeaseUnavailable(err error) bool {
	return err != nil && errors.Is(err, ErrLeaseUnavailable)
}

func WrapLeaseMissing(leaseID string) error {
	return fmt.Errorf("%w: %s", ErrLeaseMissing, leaseID)
}


package approval

import (
	"errors"
)

var (
	ErrTicketAlreadyUsed = errors.New("approval ticket already used")
	ErrTicketUnavailable = errors.New("approval ticket persistence unavailable")
)

func IsTicketAlreadyUsed(err error) bool {
	return errors.Is(err, ErrTicketAlreadyUsed)
}

func IsTicketUnavailable(err error) bool {
	return errors.Is(err, ErrTicketUnavailable)
}

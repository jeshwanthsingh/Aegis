package executor

import (
	"context"
)

// StartProxyHandler is a placeholder for the future vsock HTTP proxy feature.
// Not yet implemented — deferred to v2.
func StartProxyHandler(ctx context.Context, guestCID uint32, executionID string) error {
	<-ctx.Done()
	return nil
}

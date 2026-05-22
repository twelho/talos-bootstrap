// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package talos

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// permanentCodes lists gRPC status codes that signal an unrecoverable failure
// for the talos-bootstrap flow: no amount of retrying will turn them into
// success. Anything else (Unavailable, FailedPrecondition during boot, network
// hiccups surfaced as Unavailable) is treated as transient.
var permanentCodes = map[codes.Code]struct{}{
	codes.Unauthenticated:  {},
	codes.PermissionDenied: {},
	codes.InvalidArgument:  {},
	codes.NotFound:         {},
	codes.Unimplemented:    {},
}

// IsPermanent reports whether err is a non-retryable gRPC error.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	_, ok := permanentCodes[status.Code(err)]
	return ok
}

// retryUntil runs op repeatedly until it returns nil, a permanent error, or
// ctx expires. Transient errors are logged at debug level so an operator
// running with -v can see what is happening; without -v the loop is silent.
// Sleeps between attempts honour ctx cancellation.
func retryUntil(ctx context.Context, what string, retry time.Duration, op func() error) error {
	for {
		err := op()
		if err == nil {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if IsPermanent(err) {
			return fmt.Errorf("%s: %w", what, err)
		}
		log.Debug().Err(err).Str("op", what).Msg("retrying after transient error")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retry):
		}
	}
}

// alreadyExists reports whether err is a gRPC AlreadyExists. Used by
// Bootstrap to treat a re-bootstrap of an already-initialised etcd as
// success.
func alreadyExists(err error) bool {
	return err != nil && status.Code(err) == codes.AlreadyExists
}

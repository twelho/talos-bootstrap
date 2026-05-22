// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package talos

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsPermanent(t *testing.T) {
	cases := []struct {
		code codes.Code
		want bool
	}{
		{codes.Unauthenticated, true},
		{codes.PermissionDenied, true},
		{codes.InvalidArgument, true},
		{codes.NotFound, true},
		{codes.Unimplemented, true},
		{codes.Unavailable, false},
		{codes.FailedPrecondition, false},
		{codes.DeadlineExceeded, false},
		{codes.Internal, false},
		{codes.OK, false},
	}
	for _, c := range cases {
		err := status.Error(c.code, "test")
		if got := IsPermanent(err); got != c.want {
			t.Errorf("IsPermanent(%s) = %v, want %v", c.code, got, c.want)
		}
	}
	if IsPermanent(nil) {
		t.Error("IsPermanent(nil) must be false")
	}
	if IsPermanent(errors.New("plain")) {
		t.Error("a non-gRPC error must not be classified as permanent")
	}
}

func TestRetryUntil_AbortsOnPermanentError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	err := retryUntil(ctx, "test", time.Millisecond, func() error {
		calls++
		return status.Error(codes.Unauthenticated, "bad creds")
	})
	if err == nil {
		t.Fatal("expected error on permanent failure")
	}
	if calls != 1 {
		t.Errorf("permanent error should abort after one attempt, got %d", calls)
	}
}

func TestRetryUntil_SucceedsAfterTransient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	calls := 0
	err := retryUntil(ctx, "test", time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return status.Error(codes.Unavailable, "transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryUntil_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := retryUntil(ctx, "test", time.Millisecond, func() error {
		return status.Error(codes.Unavailable, "transient")
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestAlreadyExists(t *testing.T) {
	if alreadyExists(nil) {
		t.Error("alreadyExists(nil) must be false")
	}
	if !alreadyExists(status.Error(codes.AlreadyExists, "")) {
		t.Error("AlreadyExists status should match")
	}
	if alreadyExists(status.Error(codes.Unavailable, "")) {
		t.Error("non-AlreadyExists code should not match")
	}
	if alreadyExists(fmt.Errorf("plain")) {
		t.Error("a plain error must not match")
	}
}

// Copyright 2019 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package retry provides exponential-backoff retry helpers.
//
// Adapted from go-containerregistry's retry package; the kubernetes-derived
// wait machinery is folded in here so we don't need a sub-package.
package retry

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// Backoff parameters used by ExponentialBackoff.
type Backoff struct {
	Duration time.Duration
	Factor   float64
	Jitter   float64
	Steps    int
	Cap      time.Duration
}

// Step returns the next sleep duration and advances the backoff state.
func (b *Backoff) Step() time.Duration {
	if b.Steps < 1 {
		if b.Jitter > 0 {
			return jitter(b.Duration, b.Jitter)
		}
		return b.Duration
	}
	b.Steps--

	duration := b.Duration
	if b.Factor != 0 {
		b.Duration = time.Duration(float64(b.Duration) * b.Factor)
		if b.Cap > 0 && b.Duration > b.Cap {
			b.Duration = b.Cap
			b.Steps = 0
		}
	}
	if b.Jitter > 0 {
		duration = jitter(duration, b.Jitter)
	}
	return duration
}

// jitter returns a duration between duration and duration + maxFactor*duration.
func jitter(duration time.Duration, maxFactor float64) time.Duration {
	if maxFactor <= 0.0 {
		maxFactor = 1.0
	}
	return duration + time.Duration(rand.Float64()*maxFactor*float64(duration))
}

// ErrWaitTimeout is returned when the condition exited without success.
var ErrWaitTimeout = errors.New("timed out waiting for the condition")

// ConditionFunc returns true if the condition is satisfied, or an error if
// the loop should abort.
type ConditionFunc func() (done bool, err error)

// ExponentialBackoff repeats a condition check, sleeping between attempts.
func ExponentialBackoff(backoff Backoff, condition ConditionFunc) error {
	for backoff.Steps > 0 {
		if ok, err := condition(); err != nil || ok {
			return err
		}
		if backoff.Steps == 1 {
			break
		}
		time.Sleep(backoff.Step())
	}
	return ErrWaitTimeout
}

type temporary interface {
	Temporary() bool
}

// IsTemporary reports whether err is a transient/Temporary error.
func IsTemporary(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if te, ok := err.(temporary); ok && te.Temporary() {
		return true
	}
	return false
}

// Predicate determines whether an error should be retried.
type Predicate func(error) (retry bool)

// Retry retries f with exponential backoff until p says to stop or the
// backoff is exhausted.
func Retry(f func() error, p Predicate, backoff Backoff) (err error) {
	if f == nil {
		return fmt.Errorf("nil f passed to retry")
	}
	if p == nil {
		return fmt.Errorf("nil p passed to retry")
	}

	condition := func() (bool, error) {
		err = f()
		if p(err) {
			return false, nil
		}
		return true, err
	}

	ExponentialBackoff(backoff, condition)
	return
}

type contextKey string

var key = contextKey("never")

// Ever reports whether ctx was wrapped by Never (it was not, by default).
func Ever(ctx context.Context) bool {
	return ctx.Value(key) == nil
}

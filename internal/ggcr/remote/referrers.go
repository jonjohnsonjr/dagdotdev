// Copyright 2023 Google LLC All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

package remote

import (
	"github.com/jonjohnsonjr/dagdotdev/internal/ggcr/name"
)

// Referrers returns a Descriptor for the OCI image index that lists artifacts
// referring to the given subject digest.
//
// The subject manifest doesn't have to exist in the registry for there to be
// descriptors that refer to it.
func Referrers(d name.Digest, options ...Option) (*Descriptor, error) {
	o, err := makeOptions(d.Context(), options...)
	if err != nil {
		return nil, err
	}
	f, err := makeFetcher(d, o)
	if err != nil {
		return nil, err
	}
	return f.fetchReferrers(o.context, d)
}

// Copyright 2018 Google LLC All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

package v1

// Platform represents the target os/arch for an image. We only carry the
// fields that appear in OCI manifest JSON; the comparison helpers from the
// upstream package are unused.
type Platform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
	Features     []string `json:"features,omitempty"`
}

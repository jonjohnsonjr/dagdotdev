// Copyright 2018 Google LLC All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

package v1

import (
	"encoding/json"
	"io"
)

// ConfigFile is the Docker / OCI config blob. We only model the History list
// since that's the only field external callers read; json.Decoder silently
// drops the rest.
type ConfigFile struct {
	History []History `json:"history,omitempty"`
}

// History is one entry of a list recording how this container image was built.
type History struct {
	CreatedBy  string `json:"created_by,omitempty"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

// ParseConfigFile decodes the JSON config bytes into a ConfigFile.
func ParseConfigFile(r io.Reader) (*ConfigFile, error) {
	cf := ConfigFile{}
	if err := json.NewDecoder(r).Decode(&cf); err != nil {
		return nil, err
	}
	return &cf, nil
}

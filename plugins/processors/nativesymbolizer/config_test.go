// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateMaxCachedBinaries pins the single-source-of-truth contract for the
// cache floor: max_cached_binaries must be > 0. 0 is rejected rather than
// silently rewritten to a default -- an operator who sets it explicitly gets a
// startup error, not a surprising 256 (or a clamped 1) chosen elsewhere.
func TestValidateMaxCachedBinaries(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"negative rejected", -1, true},
		{"zero rejected", 0, true},
		{"one accepted", 1, false},
		{"default accepted", 256, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := (&Config{MaxCachedBinaries: c.value}).Validate()
			if c.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestCreateDefaultConfigIsValid guarantees the factory default passes its own
// Validate -- so `nativesymbolizer: {}` is always a startable configuration.
func TestCreateDefaultConfigIsValid(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	require.NoError(t, cfg.Validate())
	require.Equal(t, 256, cfg.MaxCachedBinaries)
}

// TestValidateMaxCachedBytes pins max_cached_bytes: negative is rejected, 0 turns
// the byte bound off (the entry bound still holds), and the default of 256 MiB
// is valid.
func TestValidateMaxCachedBytes(t *testing.T) {
	cases := []struct {
		name    string
		value   int64
		wantErr bool
	}{
		{"negative rejected", -1, true},
		{"zero accepted, no byte bound", 0, false},
		{"default accepted", 256 << 20, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := (&Config{MaxCachedBinaries: 256, MaxCachedBytes: c.value}).Validate()
			if c.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	require.Equal(t, int64(256<<20), createDefaultConfig().(*Config).MaxCachedBytes)
}

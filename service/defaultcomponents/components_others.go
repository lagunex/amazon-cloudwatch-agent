// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build !linux

package defaultcomponents

import (
	"go.opentelemetry.io/collector/processor"
)

// osProcessors returns the processors that exist only on this OS.
func osProcessors() []processor.Factory {
	return nil
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package defaultcomponents

import (
	"go.opentelemetry.io/collector/processor"

	"github.com/aws/amazon-cloudwatch-agent/plugins/processors/nativesymbolizer"
)

// osProcessors returns the processors that exist only on this OS.
func osProcessors() []processor.Factory {
	return []processor.Factory{
		nativesymbolizer.NewFactory(),
	}
}

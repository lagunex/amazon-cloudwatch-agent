// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper/xprocessorhelper"
	"go.opentelemetry.io/collector/processor/xprocessor"
)

// TypeStr is the component type, as written under `processors:`. Profiles is
// still a development-stage signal, so its plumbing lives in the experimental
// x* collector packages.
var TypeStr = component.MustNewType("nativesymbolizer")

// NewFactory returns the processor factory.
func NewFactory() processor.Factory {
	return xprocessor.NewFactory(
		TypeStr,
		createDefaultConfig,
		xprocessor.WithProfiles(createProfilesProcessor, component.StabilityLevelDevelopment),
	)
}

// createDefaultConfig returns the defaults, which are all the safe choice, so
// `nativesymbolizer: {}` is a correct configuration.
func createDefaultConfig() component.Config {
	return &Config{
		MaxCachedBinaries:   256,
		MaxCachedBytes:      256 << 20,
		RequireBuildIDMatch: true,
		Demangle:            true,
	}
}

// createProfilesProcessor builds one instance. The collector calls it once per
// pipeline that lists the processor, with the same cfg. Every instance of one
// cfg shares one symbol-table cache and one privilege probe (see sharedState),
// which the last instance to shut down releases.
func createProfilesProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next xconsumer.Profiles,
) (xprocessor.Profiles, error) {
	pCfg := cfg.(*Config)
	shared := acquireShared(pCfg)
	var release sync.Once
	releaseOnce := func() { release.Do(func() { releaseShared(pCfg) }) }

	s := newSymbolizerShared(pCfg, set.Logger, shared)
	if err := s.registerMetrics(set.MeterProvider); err != nil {
		releaseOnce()
		return nil, err
	}
	p, err := xprocessorhelper.NewProfiles(
		ctx,
		set,
		cfg,
		next,
		s.processProfiles,
		// processProfiles edits the payload in place: it appends to the shared
		// string and function tables and appends a Line onto locations. With the
		// helper's default MutatesData:false, an upstream fan-out would hand the
		// same pdata to a sibling consumer without cloning it.
		xprocessorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
		xprocessorhelper.WithStart(func(context.Context, component.Host) error {
			shared.started.Do(s.logMode)
			return nil
		}),
		xprocessorhelper.WithShutdown(func(context.Context) error {
			releaseOnce()
			return nil
		}),
	)
	if err != nil {
		releaseOnce()
		return nil, err
	}
	return p, nil
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/xprocessor"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// newTestProcessor builds a processor through the factory, as the collector
// does for each pipeline, with metrics read by tel.
func newTestProcessor(t *testing.T, tel *componenttest.Telemetry, cfg *Config, next *consumertest.ProfilesSink) xprocessor.Profiles {
	t.Helper()
	set := processor.Settings{
		ID:                component.NewID(TypeStr),
		TelemetrySettings: tel.NewTelemetrySettings(),
		BuildInfo:         component.NewDefaultBuildInfo(),
	}
	p, err := createProfilesProcessor(context.Background(), set, cfg, next)
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background(), componenttest.NewNopHost()))
	return p
}

// metricTotal sums the data points of a counter.
func metricTotal(t *testing.T, tel *componenttest.Telemetry, key string) int64 {
	t.Helper()
	m, err := tel.GetMetric(metricPrefix + key)
	require.NoError(t, err)
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "%s must be an int64 sum", key)
	require.True(t, sum.IsMonotonic, "%s must be a counter", key)
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	return total
}

// htlhashPayload is one frame of bin, a binary with no GNU build ID, at addr.
func htlhashPayload(t *testing.T, bin string, addr uint64) pprofile.Profiles {
	t.Helper()
	return buildPayload(
		[]fxMapping{{filename: bin, htlhash: htlhashOf(t, bin)}},
		[]fxLocation{{mapping: 0, addr: addr}},
		[]fxResource{{locs: []int{0}}},
	)
}

// TestCountersAreCollectorMetrics proves that the counters reach the
// collector's own telemetry through the processor's MeterProvider, including
// the new frames_resolved_by_htlhash. Before, they were only in a Debug log,
// which a collector at its default Info level never writes. The frame goes
// through three passes, and each pass must add only what changed since the
// pass before: each total equals the number of passes, and the file is parsed
// once.
func TestCountersAreCollectorMetrics(t *testing.T) {
	tel := componenttest.NewTelemetry()
	t.Cleanup(func() { require.NoError(t, tel.Shutdown(context.Background())) })
	sink := new(consumertest.ProfilesSink)
	p := newTestProcessor(t, tel, createDefaultConfig().(*Config), sink)

	bin, addr := buildNoBuildIDBinary(t)
	const passes = 3
	for i := 0; i < passes; i++ {
		require.NoError(t, p.ConsumeProfiles(context.Background(), htlhashPayload(t, bin, addr)))
	}
	require.NoError(t, p.Shutdown(context.Background()))

	require.Len(t, sink.AllProfiles(), passes)
	for _, pd := range sink.AllProfiles() {
		require.Equal(t, "hot_leaf", locationName(pd, 0))
	}
	require.Equal(t, int64(passes), metricTotal(t, tel, "frames_seen"))
	require.Equal(t, int64(passes), metricTotal(t, tel, "frames_resolved"))
	require.Equal(t, int64(passes), metricTotal(t, tel, "frames_resolved_by_htlhash"))
	require.Equal(t, int64(1), metricTotal(t, tel, "symbol_tables_parsed"), "one parse, then the cache")
	require.Equal(t, int64(0), metricTotal(t, tel, "htlhash_mismatch"))
}

// TestEveryCounterHasItsOwnMetric proves that each metric reads its own
// counter. Each counter gets another value, and each metric must show the value
// of its counter. The list below names the counter of each key a second time,
// apart from counterSpecs, so that a key wired to the wrong counter fails.
func TestEveryCounterHasItsOwnMetric(t *testing.T) {
	tel := componenttest.NewTelemetry()
	t.Cleanup(func() { require.NoError(t, tel.Shutdown(context.Background())) })
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zap.NewNop())
	require.NoError(t, s.registerMetrics(tel.NewTelemetrySettings().MeterProvider))

	want := []struct {
		key string
		val *atomic.Uint64
	}{
		{"frames_seen", &s.framesSeen},
		{"frames_resolved", &s.framesResolved},
		{"frames_resolved_by_htlhash", &s.framesResolvedByHtlhash},
		{"no_candidate", &s.framesNoCandidate},
		{"no_symbol", &s.framesNoSymbol},
		{"no_build_id", &s.framesNoBuildID},
		{"build_id_mismatch", &s.buildIDMismatch},
		{"htlhash_mismatch", &s.htlhashMismatch},
		{"mapping_bias_unexpected", &s.mappingBiasUnexpected},
		{"permission_denied", &s.permissionDenied},
		{"symbol_tables_parsed", &s.symbolTablesParsed},
		{"symbol_table_panics", &s.symbolTablePanics},
		{"proc_maps_reads", &s.procMapsReads},
	}
	require.Len(t, s.counterSpecs(), len(want), "every counter is in the list")
	for i, w := range want {
		w.val.Store(uint64(i + 1))
	}
	s.endPass(context.Background())
	for i, w := range want {
		require.Equal(t, int64(i+1), metricTotal(t, tel, w.key), w.key)
	}
}

// TestConfigBoundsReachTheSharedCache proves that max_cached_binaries and
// max_cached_bytes of the config bound the cache that the factory builds. The
// values are not the defaults, so a bound that the code sets on its own fails.
func TestConfigBoundsReachTheSharedCache(t *testing.T) {
	tel := componenttest.NewTelemetry()
	t.Cleanup(func() { require.NoError(t, tel.Shutdown(context.Background())) })
	cfg := createDefaultConfig().(*Config)
	cfg.MaxCachedBinaries = 7
	cfg.MaxCachedBytes = 12345
	p := newTestProcessor(t, tel, cfg, new(consumertest.ProfilesSink))

	sharedStates.mu.Lock()
	cache := sharedStates.byConfig[cfg].cache
	sharedStates.mu.Unlock()
	require.Equal(t, 7, cache.capacity)
	require.Equal(t, int64(12345), cache.maxBytes)
	require.NoError(t, p.Shutdown(context.Background()))
}

// TestPipelinesShareTheCacheThroughTheFactory builds the processor twice from
// one config, as the collector does for the two pipelines of the IP config.
// Both instances name the frame, the file is parsed once between them, and the
// last shutdown releases the shared cache.
func TestPipelinesShareTheCacheThroughTheFactory(t *testing.T) {
	tel := componenttest.NewTelemetry()
	t.Cleanup(func() { require.NoError(t, tel.Shutdown(context.Background())) })
	cfg := createDefaultConfig().(*Config)
	first := newTestProcessor(t, tel, cfg, new(consumertest.ProfilesSink))
	second := newTestProcessor(t, tel, cfg, new(consumertest.ProfilesSink))

	sharedStates.mu.Lock()
	require.Equal(t, 2, sharedStates.byConfig[cfg].refs)
	sharedStates.mu.Unlock()

	bin, addr := buildNoBuildIDBinary(t)
	pd := htlhashPayload(t, bin, addr)
	for _, p := range []xprocessor.Profiles{first, second} {
		clone := pprofile.NewProfiles()
		pd.CopyTo(clone)
		require.NoError(t, p.ConsumeProfiles(context.Background(), clone))
	}
	require.Equal(t, int64(2), metricTotal(t, tel, "frames_resolved"))
	require.Equal(t, int64(1), metricTotal(t, tel, "symbol_tables_parsed"), "one parse for both pipelines")

	require.NoError(t, first.Shutdown(context.Background()))
	require.NoError(t, first.Shutdown(context.Background()), "a second shutdown releases nothing more")
	sharedStates.mu.Lock()
	require.Equal(t, 1, sharedStates.byConfig[cfg].refs)
	sharedStates.mu.Unlock()
	require.NoError(t, second.Shutdown(context.Background()))
	sharedStates.mu.Lock()
	_, present := sharedStates.byConfig[cfg]
	sharedStates.mu.Unlock()
	require.False(t, present, "the last shutdown releases the shared cache")
}

// TestInfoSummaryEveryNPasses proves the Info summary: on the first pass, and
// then every summaryEvery passes, with the counters as fields.
func TestInfoSummaryEveryNPasses(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	bin, buildID, addr := buildTestBinary(t)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zap.New(core))
	s.summaryEvery = 3

	for i := 0; i < 4; i++ {
		_, err := s.processProfiles(context.Background(), makeProfiles(bin, buildID, addr))
		require.NoError(t, err)
	}

	summaries := logs.FilterMessage("nativesymbolizer summary").All()
	require.Len(t, summaries, 2, "passes 1 and 3 log a summary, passes 2 and 4 do not")
	last := summaries[1].ContextMap()
	require.Equal(t, uint64(3), last["passes"])
	require.Equal(t, uint64(3), last["frames_resolved"])
	require.Equal(t, uint64(0), last["no_candidate"])
	require.EqualValues(t, 1, last["cache_entries"])
}

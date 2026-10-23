// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

// Self-telemetry: the symbolizer's counters become collector metrics, and a
// summary of them is logged at Info level.

package nativesymbolizer

import (
	"context"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

const (
	// meterName follows the collector's convention: the component's import path.
	meterName = "github.com/aws/amazon-cloudwatch-agent/plugins/processors/nativesymbolizer"
	// metricPrefix follows the collector's own component metrics
	// (otelcol_processor_batch_..., otelcol_exporter_sent_...). A Prometheus
	// reader shows these names with no _total suffix.
	metricPrefix = "otelcol_processor_nativesymbolizer_"
	// summaryEveryPasses is how often the Info summary is logged: on the first
	// pass, and then every 60th, which is every 5 minutes at a 5 s report
	// interval.
	summaryEveryPasses = 60
)

// counterSpec names one counter of the symbolizer. key is both the metric name
// after metricPrefix and the field name in the pass logs.
type counterSpec struct {
	key  string
	unit string
	desc string
	val  *atomic.Uint64
}

func (s *symbolizer) counterSpecs() []counterSpec {
	return []counterSpec{
		{"frames_seen", "{frame}", "Native frames with no name that the processor tried to name.", &s.framesSeen},
		{"frames_resolved", "{frame}", "Native frames that the processor named.", &s.framesResolved},
		{"frames_resolved_by_htlhash", "{frame}", "Named frames whose file has no GNU build ID and was matched by its htlhash.", &s.framesResolvedByHtlhash},
		{"no_candidate", "{frame}", "Frames left unnamed: no file was found, or the file that matched has no usable symbols.", &s.framesNoCandidate},
		{"no_symbol", "{frame}", "Frames left unnamed: the file matched, but no function covers the address.", &s.framesNoSymbol},
		{"no_build_id", "{frame}", "Frames left unnamed: neither a GNU build ID nor an htlhash could prove the file.", &s.framesNoBuildID},
		{"build_id_mismatch", "{frame}", "Frames left unnamed: every file found had a different GNU build ID.", &s.buildIDMismatch},
		{"htlhash_mismatch", "{frame}", "Frames left unnamed: the file has no GNU build ID, and every file found had a different htlhash.", &s.htlhashMismatch},
		{"mapping_bias_unexpected", "{frame}", "Frames left unnamed: the address is outside its mapping, or the mapping is in no executable segment.", &s.mappingBiasUnexpected},
		{"permission_denied", "{frame}", "Frames left unnamed: the agent may not read the process or the file that would name them.", &s.permissionDenied},
		{"symbol_tables_parsed", "{table}", "Symbol tables read. With require_build_id_match on, only from files that proved their identity.", &s.symbolTablesParsed},
		{"symbol_table_panics", "{panic}", "Panics recovered while reading an ELF file. That file version is not read again.", &s.symbolTablePanics},
		{"proc_maps_reads", "{read}", "Reads of /proc/<pid>/maps to find a shared object. With require_build_id_match on, only for one that is not resolved yet.", &s.procMapsReads},
	}
}

// selfMetrics holds the instruments of one symbolizer. Each counter is updated
// once per pass with what changed since the last pass, rather than once per
// frame.
type selfMetrics struct {
	mu       sync.Mutex
	counters []reportedCounter
	flushed  bool // false until the first flush
}

type reportedCounter struct {
	val      *atomic.Uint64
	inst     metric.Int64Counter
	reported uint64
}

// registerMetrics creates the instruments on mp, the MeterProvider of the
// processor's TelemetrySettings, so that the counters reach the collector's own
// telemetry. In the agent that telemetry is exported only when self-telemetry
// is enabled, which is why the mode and the summary are also logged.
//
// The counters carry no attributes. The collector adds the component and the
// pipeline to a component's meter only with its alpha feature gate
// telemetry.newPipelineTelemetry. Without that gate, the instances of all
// pipelines get the same meter, so they add into one series per counter. The
// Info summary line is per instance, and its logger carries otelcol.pipeline.id.
func (s *symbolizer) registerMetrics(mp metric.MeterProvider) error {
	meter := mp.Meter(meterName)
	modeGauge, err := meter.Int64Gauge(metricPrefix+"mode",
		metric.WithDescription("What the processor can read: 2 full (CAP_SYS_PTRACE), 1 limited (processes of the agent's own user, and world-readable binaries), 0 inactive."),
		metric.WithUnit("{mode}"),
	)
	if err != nil {
		return err
	}
	modeGauge.Record(context.Background(), int64(s.priv.mode))
	m := &selfMetrics{}
	for _, spec := range s.counterSpecs() {
		inst, err := meter.Int64Counter(metricPrefix+spec.key,
			metric.WithDescription(spec.desc),
			metric.WithUnit(spec.unit),
		)
		if err != nil {
			return err
		}
		m.counters = append(m.counters, reportedCounter{val: spec.val, inst: inst})
	}
	s.metrics = m
	return nil
}

// flush adds to each instrument what its counter gained since the last flush.
// The lock makes two concurrent passes report each increment exactly once.
//
// The first flush adds to every counter, 0 included, so that each series exists
// from the first pass. A miss counter that has never moved then reads 0 rather
// than being absent, which a dashboard or an alarm cannot tell from "no data".
func (m *selfMetrics) flush(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.counters {
		c := &m.counters[i]
		cur := c.val.Load()
		if cur > c.reported || !m.flushed {
			c.inst.Add(ctx, int64(cur-c.reported)) //nolint:gosec // G115: the increase of one pass
			c.reported = cur
		}
	}
	m.flushed = true
}

func (s *symbolizer) counterFields() []zap.Field {
	specs := s.counterSpecs()
	fields := make([]zap.Field, 0, len(specs)+3)
	for _, spec := range specs {
		fields = append(fields, zap.Uint64(spec.key, spec.val.Load()))
	}
	return fields
}

// endPass reports the counters at the end of a pass: to the metrics, to a Debug
// line every pass, and to an Info line on the first pass and every
// summaryEvery passes. The Info line is what shows the outcome on a host where
// the agent logs at its default level, without self-telemetry.
func (s *symbolizer) endPass(ctx context.Context) {
	if s.metrics != nil {
		s.metrics.flush(ctx)
	}
	n := s.passes.Add(1)
	if ce := s.log.Check(zap.DebugLevel, "native symbolization pass complete"); ce != nil {
		ce.Write(s.counterFields()...)
	}
	if n == 1 || (s.summaryEvery > 0 && n%s.summaryEvery == 0) {
		entries, bytes := s.cache.stats()
		fields := append(s.counterFields(),
			zap.Uint64("passes", n),
			zap.Int("cache_entries", entries),
			zap.Int64("cache_bytes", bytes),
			zap.Stringer("mode", s.priv.mode),
			zap.Bool("map_files", s.priv.mapFiles),
		)
		s.log.Info("nativesymbolizer summary", fields...)
	}
}

// logMode logs, once per Config at startup, what the privilege probe found when
// it limits the processor. Nothing is logged in full mode: the summary line
// carries the mode.
func (s *symbolizer) logMode() {
	switch s.priv.mode {
	case modeLimited:
		s.log.Warn("nativesymbolizer runs in limited mode: the agent lacks CAP_SYS_PTRACE, so it names only the native frames of processes that run as its own uid and gid, and of world-readable binaries at the paths the sender reports in the agent's own filesystem. Run the agent as root, or grant it CAP_SYS_PTRACE, to name the frames of every process.",
			zap.String("mode", s.priv.mode.String()),
			zap.Uint32("uid", s.priv.uid),
			zap.Uint32("gid", s.priv.gid),
		)
	case modeInactive:
		s.log.Warn("nativesymbolizer is inactive: the agent cannot reopen files through /proc/self/fd, so it cannot read any binary. Native frames pass through unnamed.",
			zap.String("mode", s.priv.mode.String()),
		)
	}
}

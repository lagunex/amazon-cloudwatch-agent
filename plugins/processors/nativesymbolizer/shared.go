// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

// State that the processor instances of one `nativesymbolizer` config share.

package nativesymbolizer

import (
	"path/filepath"
	"sync"
	"time"
)

// sharedState is what every processor instance built from one Config shares.
//
// The collector builds one processor instance PER PIPELINE that lists the
// processor. When two pipelines (say, one per destination) receive the same
// profiles, a cache per instance would parse and hold every file twice. With
// this, the first instance parses a file and the second finds it in the cache.
type sharedState struct {
	cache  *resolverCache
	misses *missMemo
	// priv is what the agent may read, probed once per Config.
	priv privileges
	// started makes the startup log line appear once per Config, not once per
	// pipeline.
	started sync.Once
	refs    int // instances that use this state; guarded by sharedStates.mu
}

func newSharedState(cfg *Config) *sharedState {
	return &sharedState{
		cache:  newResolverCacheBytes(cfg.MaxCachedBinaries, cfg.MaxCachedBytes),
		misses: newMissMemo(missRetryAfter, missMemoMaxEntries, time.Now),
		priv:   probePrivileges(filepath.Join(cfg.RootPathPrefix, "/proc")),
	}
}

// sharedStates maps a Config to its shared state. The key is the *Config
// pointer: the collector hands the same Config value to the factory for every
// pipeline that lists the same component ID, and a reloaded config is a new
// value, which gets fresh state (the same rule as the collector's own
// sharedcomponent helper).
var sharedStates = struct {
	mu       sync.Mutex
	byConfig map[*Config]*sharedState
}{byConfig: make(map[*Config]*sharedState)}

// acquireShared returns the shared state of cfg and counts one more user.
func acquireShared(cfg *Config) *sharedState {
	sharedStates.mu.Lock()
	defer sharedStates.mu.Unlock()
	st, ok := sharedStates.byConfig[cfg]
	if !ok {
		st = newSharedState(cfg)
		sharedStates.byConfig[cfg] = st
	}
	st.refs++
	return st
}

// releaseShared counts one user less, and forgets the state of cfg (and so frees
// its cache) when the last instance has shut down.
func releaseShared(cfg *Config) {
	sharedStates.mu.Lock()
	defer sharedStates.mu.Unlock()
	st, ok := sharedStates.byConfig[cfg]
	if !ok {
		return
	}
	st.refs--
	if st.refs <= 0 {
		delete(sharedStates.byConfig, cfg)
	}
}

const (
	// missRetryAfter is how long a mapping that could not be resolved in one
	// process context is not tried again in that context. A minute is 12 passes
	// at a 5 s report interval.
	missRetryAfter = time.Minute
	// missMemoMaxEntries bounds the memo. Past it, expired entries are dropped,
	// and if none expired the memo starts over: forgetting a miss only costs one
	// more walk.
	missMemoMaxEntries = 4096
)

// missKey is one mapping in one process context.
type missKey struct {
	identity string
	procDir  string
	root     string
	exePath  string
}

type missEntry struct {
	outcome resolveOutcome
	until   time.Time
}

// missMemo remembers, for a short time, that a mapping could not be resolved in
// a process context. Without it, a mapping whose file is gone for good -- the
// vDSO is in every process and is never a file, and a deleted library of an
// exited process cannot come back -- would cost a walk over every candidate and
// a /proc/<pid>/maps read in every pass of every pipeline.
type missMemo struct {
	mu      sync.Mutex
	entries map[missKey]missEntry
	ttl     time.Duration
	max     int
	now     func() time.Time
}

func newMissMemo(ttl time.Duration, maxEntries int, now func() time.Time) *missMemo {
	return &missMemo{entries: make(map[missKey]missEntry), ttl: ttl, max: maxEntries, now: now}
}

// get returns the remembered outcome of k while it has not expired.
func (m *missMemo) get(k missKey) (resolveOutcome, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[k]
	if !ok {
		return resolveOK, false
	}
	if !m.now().Before(e.until) {
		delete(m.entries, k)
		return resolveOK, false
	}
	return e.outcome, true
}

// put remembers the outcome of k for the memo's ttl.
func (m *missMemo) put(k missKey, outcome resolveOutcome) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if len(m.entries) >= m.max {
		for key, e := range m.entries {
			if !now.Before(e.until) {
				delete(m.entries, key)
			}
		}
		if len(m.entries) >= m.max {
			m.entries = make(map[missKey]missEntry)
		}
	}
	m.entries[k] = missEntry{outcome: outcome, until: now.Add(m.ttl)}
}

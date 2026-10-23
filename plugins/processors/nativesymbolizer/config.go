// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import "fmt"

// Config is the processor configuration.
//
// There is deliberately no `enabled` flag: the processor is turned on by
// listing it in a profiles pipeline and off by removing it, like
// memory_limiter, resource or batch. An `enabled` field would let it sit in a
// pipeline doing nothing.
type Config struct {
	// MaxCachedBinaries bounds the number of parsed ELF symbol tables held in
	// memory at once (LRU). A host runs many distinct binaries, and the symbol
	// table of a large one takes tens of MiB. Default 256.
	MaxCachedBinaries int `mapstructure:"max_cached_binaries"`

	// MaxCachedBytes bounds the memory of the parsed symbol tables, as an
	// estimate of their heap size in bytes. It works together with
	// MaxCachedBinaries: the least recently used table is evicted when either
	// bound is passed. The table stored last is never evicted, but a table that
	// is larger than this bound on its own evicts every other table, and the next
	// table stored evicts it. So keep the bound well above the tables that one
	// report needs (the binaries and libraries of the profiled processes).
	// Below that, those tables evict each other, and every pass of each pipeline
	// parses them again; symbol_tables_parsed shows it. The processor instances
	// of all pipelines share the one cache. 0 turns the byte bound off, so that
	// only max_cached_binaries applies. Default 256 MiB.
	MaxCachedBytes int64 `mapstructure:"max_cached_bytes"`

	// RootPathPrefix is prepended to every /proc path and to the paths of
	// processes that carry no process.pid. With a prefix, the processor reads
	// <prefix>/proc/<pid>/{exe,maps,map_files,root}, which is where an agent in
	// a container sees the host's /proc when it is mounted there. Empty means
	// resolve paths as-is. Optional.
	RootPathPrefix string `mapstructure:"root_path_prefix"`

	// RequireBuildIDMatch, when true (the default), refuses to resolve a frame
	// whose on-disk binary has a GNU build ID other than the one the sender
	// recorded, and, for a binary with no GNU build ID, an htlhash other than the
	// recorded one. Turning it off is unsafe: a stale binary then yields
	// confidently wrong names, which is worse than no names because a wrong
	// flame graph gets trusted. It exists only for diagnostics.
	//
	// It also costs more file work: with it off, no table is found by its
	// content, so every pass walks the candidate files of each mapping again,
	// and the walk of a shared object reads /proc/<pid>/maps again. A parsed
	// table is still cached by path, so its file is not parsed again.
	RequireBuildIDMatch bool `mapstructure:"require_build_id_match"`

	// Demangle, when true (the default), decodes Rust (v0 and legacy) and C++
	// symbol names (e.g. _ZN8sum_loop8hot_leaf17h..E) into readable form
	// (sum_loop::hot_leaf). Plain C symbols pass through unchanged. Set false
	// to store raw linker symbols and let the backend demangle.
	Demangle bool `mapstructure:"demangle"`
}

// Validate rejects a nonsensical setting at startup.
//
// max_cached_binaries must be > 0: resolving any frame needs its parsed symbol
// table to be held at least for the pass, so there is no "no cache" setting.
// The default of 256 comes from createDefaultConfig, so an explicitly set 0 is
// a startup error rather than a value silently rewritten downstream.
//
// max_cached_bytes must be >= 0. Its 0 is not "no cache" but "no byte bound":
// the entry bound above still holds the cache to a finite size.
func (c *Config) Validate() error {
	if c.MaxCachedBinaries <= 0 {
		return fmt.Errorf("max_cached_binaries must be > 0, got %d", c.MaxCachedBinaries)
	}
	if c.MaxCachedBytes < 0 {
		return fmt.Errorf("max_cached_bytes must be >= 0, got %d", c.MaxCachedBytes)
	}
	return nil
}

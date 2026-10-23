// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	// Aliased: the package-level func below is also named demangle.
	libdemangle "github.com/ianlancetaylor/demangle"
)

// demangleMaxLength caps a demangled name at 2^16 = 65536 bytes.
//
// A Rust v0 backward reference expands to text printed earlier in the same
// symbol, so a crafted symbol can describe an output far larger than itself.
// The cap keeps one hostile symbol from turning into an unbounded allocation
// inside the agent. Real names are orders of magnitude shorter.
const demangleMaxLength = 16

// demangle turns a linker symbol into a human-readable name using
// github.com/ianlancetaylor/demangle -- the demangler behind `go tool pprof`.
// It decodes Rust v0 (`_R...`), Rust GNU-legacy (`_ZN...17h<hash>E`) and C++
// Itanium names; anything it cannot decode (plain C symbols such as `main`,
// already-demangled names, malformed input) is returned unchanged.
//
// Two library behaviours are worth knowing when reading a flame graph:
//
//   - Clone suffixes (`.llvm.<hash>`, `.cold.N`, `.0`) are dropped from Rust
//     names, so a function and its compiler-generated copies render as one
//     frame.
//   - A legacy-mangled segment that begins with `_` loses that underscore
//     (`__rust_begin_short_backtrace` renders `_rust_begin_short_backtrace`).
//     This is an upstream defect in the legacy decoder; v0 names, which modern
//     toolchains emit by default, are not affected.
//
// The library signals a malformed symbol by panicking with its own error type
// and recovering it internally; any OTHER panic is re-raised. Symbol names come
// off an on-disk ELF that may be truncated or crafted, and this runs on the
// agent's profile-processing goroutine, where a panic would stop the agent. So
// any panic that escapes the library is caught here and the raw symbol is
// returned: an undecoded name is honest, a crash is not.
func demangle(sym string) string {
	out := sym
	if recoverPanic(func() { out = libdemangle.Filter(sym, libdemangle.MaxLength(demangleMaxLength)) }) != nil {
		return sym
	}
	return out
}

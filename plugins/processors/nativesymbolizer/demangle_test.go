// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDemangle covers the non-v0 inputs: GNU-legacy Rust, C++, and symbols
// that must pass through unchanged. Rust v0 is covered in demangle_v0_test.go.
func TestDemangle(t *testing.T) {
	cases := []struct{ in, want string }{
		// Legacy Rust with trailing hash disambiguator, which is dropped.
		{"_ZN8sum_loop8hot_leaf17h761119b89d855a8aE", "sum_loop::hot_leaf"},
		{"_ZN8sum_loop7level_a17h83cbaa448f4d1b15E", "sum_loop::level_a"},
		// KNOWN UPSTREAM DEFECT: a legacy segment starting with `_` loses that
		// underscore (rustfilt prints `__rust_begin_short_backtrace`). Pinned
		// so an upstream fix is noticed and this expectation corrected.
		{"_ZN3std3sys9backtrace28__rust_begin_short_backtrace17h682b8d41a32724e0E",
			"std::sys::backtrace::_rust_begin_short_backtrace"},
		// $..$ escapes in a trait impl: $LT$ -> '<', $u20$ -> ' ', $GT$ -> '>',
		// and `..` inside a segment -> '::'.
		{"_ZN52$LT$sum_loop..Widget$u20$as$u20$core..fmt..Debug$GT$3fmt17h0123456789abcdefE",
			"<sum_loop::Widget as core::fmt::Debug>::fmt"},
		// Generic instantiation with a comma-separated type list ($C$ -> ',').
		{"_ZN4core3ptr74drop_in_place$LT$alloc..vec..Vec$LT$u8$C$$u20$alloc..alloc..Global$GT$$GT$17h00000000deadbeefE",
			"core::ptr::drop_in_place<alloc::vec::Vec<u8, alloc::alloc::Global>>"},
		// A legacy-shaped symbol the Rust decoder rejects falls back to the C++
		// demangler, which keeps the hash segment rather than guessing it away.
		{"_ZN3foo7bar.baz17h1111111111111111E", "foo::bar.baz::h1111111111111111"},
		// C++ Itanium.
		{"_ZN3foo3barEv", "foo::bar()"},
		// Plain C symbol -- untouched.
		{"main", "main"},
		// Rust v0 is dispatched to the same entry point.
		{"_RNvNtCsfQfHhyvAE2O_3std2rt19lang_start_internal",
			"std::rt::lang_start_internal"},
		// Already-readable -- untouched.
		{"tokio::runtime::task::harness::Harness", "tokio::runtime::task::harness::Harness"},
		// Malformed legacy -- returned as-is rather than corrupted.
		{"_ZNbogus", "_ZNbogus"},
		{"_ZN0E", "_ZN0E"},
		{"_ZN99abcE", "_ZN99abcE"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, demangle(c.in), "demangle(%q)", c.in)
	}
}

// TestDemangleHostileSymbolDoesNotPanic covers the malformed-input class for
// the `_ZN` path. Symbol names come off an on-disk ELF that may be corrupt or
// crafted, and a panic here would take down the collector's processing
// goroutine, so every one of these must return rather than crash.
func TestDemangleHostileSymbolDoesNotPanic(t *testing.T) {
	hostile := []string{
		"_ZN" + strings.Repeat("9", 19) + "abcE",  // overflows int64 when accumulated
		"_ZN" + strings.Repeat("9", 100) + "abcE", // far past any bound
		"_ZN" + strings.Repeat("1", 30) + "E",
		"_ZN9223372036854775807abcE", // exactly math.MaxInt64
		"_ZN9223372036854775808abcE", // MaxInt64 + 1
		"_ZN18446744073709551616E",   // 2^64
		"_ZN-1abcE",                  // not digits at all after _ZN
		"_ZN",                        // truncated
		"_ZNE",                       // empty body
		"_ZN00000000000000000005helloE",
		"_ZN\x00\xff\xfeE", // non-UTF8 garbage
		"_ZN" + strings.Repeat("9", 19) + "abc17h0123456789abcdefE", // legacy-Rust shaped
	}
	for _, sym := range hostile {
		require.NotPanics(t, func() { _ = demangle(sym) }, "demangle(%q) panicked", sym)
	}
}

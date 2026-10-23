// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every expectation in this file is a REAL Rust v0 symbol taken from a compiled
// binary -- from public crates (std, core, alloc, tokio, libc, aws-smithy and
// others) and from two purpose-built crates that force the rarer grammar
// productions (function pointers, const generics, non-ASCII identifiers) that
// ordinary code does not emit. Two symbols came from a private crate: its
// identifiers were replaced by neutral names of the same length, which keeps
// every back-reference offset in those symbols valid. Each expected string is the output of `rustfilt` (the rustc-demangle
// crate) unless a case says otherwise, so these pin agreement between
// github.com/ianlancetaylor/demangle and the reference implementation, one case
// per grammar production. A library upgrade that regresses a production fails
// here rather than as a wrong frame name in production.
//
// Where the library deliberately differs from rustfilt, the case says so and
// asserts the library's output.
//
// Non-ASCII expectations are written as Go escapes rather than literal
// characters to keep the source ASCII-only.
func TestDemangleRustV0(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{{
		name: "crate and function",
		in:   "_RNvCs5pO2ZDQbyWM_8v0exotic2id",
		want: "v0exotic::id",
	}, {
		// The crate disambiguator (`Cs5pO2...`) is parsed and dropped: it
		// distinguishes two crates of the same name but is noise to a reader.
		name: "nested modules",
		in:   "_RNvNtCsfQfHhyvAE2O_3std2rt19lang_start_internal",
		want: "std::rt::lang_start_internal",
	}, {
		name: "static rather than function",
		in:   "_RNvNtCsfQfHhyvAE2O_3std5alloc4HOOK",
		want: "std::alloc::HOOK",
	}, {
		// `M` is an inherent impl. Its defining scope is parsed but not printed,
		// which is why this reads `<Context>::run` and not
		// `tokio::runtime::...::worker<Context>::run`.
		name: "inherent impl method",
		in:   "_RNvMs_NtNtNtNtCslf5agbebQAy_5tokio7runtime9scheduler12multi_thread6workerNtB4_7Context3run",
		want: "<tokio::runtime::scheduler::multi_thread::worker::Context>::run",
	}, {
		// `X` is a trait impl, printed `<Type as Trait>`. Also the densest
		// backref case in the table: B7_, B9_, Bf_ and friends each re-use a
		// path printed earlier in the same symbol.
		name: "trait impl method with generics and backrefs",
		in:   "_RNCNvXs0_NtNtNtNtCs5ZnZjEIdUua_35telemetry_example_ingestion_service18ingestion_frontend6server8services25put_record_common_serviceINtB7_22PutRecordCommonServiceNtNtB9_18put_record_service18PutRecordOperationEINtCs4UIWkd5yVLG_13tower_service7ServiceNtNtCsbhb7qqwPx1r_39telemetry_example_ingestion_service_sdk5input14PutRecordInputE4call0Bf_",
		want: "<telemetry_example_ingestion_service::ingestion_frontend::server::services::put_record_common_service::PutRecordCommonService<telemetry_example_ingestion_service::ingestion_frontend::server::services::put_record_service::PutRecordOperation> as tower_service::Service<telemetry_example_ingestion_service_sdk::input::PutRecordInput>>::call::{closure#0}",
	}, {
		// `Y` is a trait definition, and `{shim:vtable#0}` is the uppercase-`S`
		// special namespace with a name attached.
		name: "trait definition path and vtable shim",
		in:   "_RNSNvYNCINvCskNq9NTsQZAU_20signal_hook_registry8registerNCNCNvNtNtCsfr2PKNwlTJZ_5tokio6signal4unix13signal_enable00E0INtNtNtCsjemqvGMJH9i_4core3ops8function6FnOnceTRNtNtNtNtNtNtNtCscEMAiCoyOC_4libc4unix10linux_like5linux3gnu3b647aarch649siginfo_tEE9call_once6vtableB12_.llvm.8410622920506837730",
		want: "<signal_hook_registry::register<tokio::signal::unix::signal_enable::{closure#0}::{closure#0}>::{closure#0} as core::ops::function::FnOnce<(&libc::unix::linux_like::linux::gnu::b64::aarch64::siginfo_t,)>>::call_once::{shim:vtable#0}",
	}, {
		// A closure with NO disambiguator is #0.
		name: "closure without disambiguator",
		in:   "_RNCNvNtNtCsdFriw2myz1L_18aws_smithy_runtime6client12orchestrator11try_attempt0CskLyqREJ70E3_43telemetry_example_ingestion_services_client",
		want: "aws_smithy_runtime::client::orchestrator::try_attempt::{closure#0}",
	}, {
		// ...and `s_` is #1, not #0. The base-62 encoding biases by one so the
		// common value fits in a single byte, and getting that bias wrong shifts
		// every disambiguated closure in a binary by one.
		name: "closure with disambiguator s_ is one",
		in:   "_RINvMs4_NtCsa7IDAnTpL3R_14rustc_demangle2v0NtB6_7Printer13print_backrefNCNvB2_10print_paths_0EB8_",
		want: "<rustc_demangle::v0::Printer>::print_backref::<<rustc_demangle::v0::Printer>::print_path::{closure#1}>",
	}, {
		name: "array with const length",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7genericAhj4_EB2_",
		want: "v0exotic::generic::<[u8; 4]>",
	}, {
		name: "reference to slice",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7genericRShEB2_",
		want: "v0exotic::generic::<&[u8]>",
	}, {
		name: "tuple",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7genericThcbEEB2_",
		want: "v0exotic::generic::<(u8, char, bool)>",
	}, {
		name: "raw pointers const and mut",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic8generic2PhOxEB2_",
		want: "v0exotic::generic2::<*const u8, *mut i64>",
	}, {
		name: "unit and u128 primitives",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic8generic2uoEB2_",
		want: "v0exotic::generic2::<(), u128>",
	}, {
		name: "i128 primitive",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7genericnEB2_",
		want: "v0exotic::generic::<i128>",
	}, {
		// A unit return type is elided, so this is `fn(i32) -> i32` for the
		// first and a bare `fn(...)` would appear for a unit-returning one.
		name: "function pointers plain and unsafe extern C",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic8generic2FlElFUKClElEB2_",
		want: `v0exotic::generic2::<fn(i32) -> i32, unsafe extern "C" fn(i32) -> i32>`,
	}, {
		// The binder introduces 'a, and the lifetime index inside the signature
		// resolves against it. Note the space after `for<'a>`.
		name: "higher ranked function pointer with binder",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic8generic2FG_RL0_eERL0_euEB2_",
		want: "v0exotic::generic2::<for<'a> fn(&'a str) -> &'a str, ()>",
	}, {
		name: "trait object single bound",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7genericRDNtNtCsjemqvGMJH9i_4core3fmt5DebugEL_EB2_",
		want: "v0exotic::generic::<&dyn core::fmt::Debug>",
	}, {
		name: "trait object with auto trait bounds",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic8generic2INtNtCsbSVVNPxiylx_5alloc5boxed3BoxDNtB2_2TrNtNtCsjemqvGMJH9i_4core6marker4SyncNtB1i_4SendEL_EuEB2_",
		want: "v0exotic::generic2::<alloc::boxed::Box<dyn v0exotic::Tr + core::marker::Sync + core::marker::Send>, ()>",
	}, {
		// The associated-type binding has to merge into the trait's own generic
		// argument list -- one `<...>` holding both -- and the argument is a
		// one-element tuple, which needs its trailing comma.
		name: "trait object with associated binding and one element tuple",
		in:   "_RINvNtCsjemqvGMJH9i_4core3ptr13drop_in_placeINtNtCsbSVVNPxiylx_5alloc3vec3VecINtNtBL_5boxed3BoxDINtNtNtB4_3ops8function6FnOnceuEp6OutputuNtNtB4_6marker4SendEL_EEECsfQfHhyvAE2O_3std",
		want: "core::ptr::drop_in_place::<alloc::vec::Vec<alloc::boxed::Box<dyn core::ops::function::FnOnce<(), Output = ()> + core::marker::Send>>>",
	}, {
		name: "trait object with binder inside a tuple",
		in:   "_RINvNtCsjemqvGMJH9i_4core3ptr13drop_in_placeINtNtCsbSVVNPxiylx_5alloc3vec3VecTNtCskNq9NTsQZAU_20signal_hook_registry8ActionIdINtNtBL_4sync3ArcDG_INtNtNtB4_3ops8function2FnTRL0_NtNtNtNtNtNtNtCscEMAiCoyOC_4libc4unix10linux_like5linux3gnu3b647aarch649siginfo_tEEp6OutputuNtNtB4_6marker4SyncNtB4k_4SendEL_EEEEB1g_.llvm.8474066517012294637",
		want: "core::ptr::drop_in_place::<alloc::vec::Vec<(signal_hook_registry::ActionId, alloc::sync::Arc<dyn for<'a> core::ops::function::Fn<(&'a libc::unix::linux_like::linux::gnu::b64::aarch64::siginfo_t,), Output = ()> + core::marker::Sync + core::marker::Send>)>>",
	}, {
		name: "const generic usize",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic8cg_usizeKj7_EB2_",
		want: "v0exotic::cg_usize::<7>",
	}, {
		// An empty hex body is the value zero, not a parse error.
		name: "const generic zero has empty hex body",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic8cg_usizeKj0_EB2_",
		want: "v0exotic::cg_usize::<0>",
	}, {
		name: "const generic bool true",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7cg_boolKb1_EB2_",
		want: "v0exotic::cg_bool::<true>",
	}, {
		name: "const generic bool false",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7cg_boolKb0_EB2_",
		want: "v0exotic::cg_bool::<false>",
	}, {
		name: "const generic char ascii",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7cg_charKc78_EB2_",
		want: "v0exotic::cg_char::<'x'>",
	}, {
		// A char outside the BMP is printed as a `\u{..}` escape. rustfilt
		// prints the character itself; the library escapes it.
		name: "const generic char astral",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic7cg_charKc1f600_EB2_",
		want: "v0exotic::cg_char::<'\\u{1f600}'>",
	}, {
		// The `n` prefix carries the sign, so the magnitude decodes the same way
		// as an unsigned value.
		name: "const generic negative i32",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic6cg_i32Kln2a_EB2_",
		want: "v0exotic::cg_i32::<-42>",
	}, {
		name: "const generic negative i8",
		in:   "_RINvCs5pO2ZDQbyWM_8v0exotic5cg_i8Kan1_EB2_",
		want: "v0exotic::cg_i8::<-1>",
	}, {
		// Two punycoded path components in one symbol: a Latin-with-diacritics
		// module and a Greek one. The mangling is pure ASCII, so these have to
		// be reconstructed by the punycode decoder.
		name: "punycode identifiers with generic",
		in:   "_RINvNtNtCs5pO2ZDQbyWM_8v0exoticu13ncd_dma1a7bzbu5wxacdu10wgv71a119ehEB6_",
		want: "v0exotic::\u00fcn\u00efc\u00f6d\u00e9::\u03bb\u03bc\u03bd::\u65e5\u672c\u8a9e::<u8>",
	}, {
		name: "punycode module with ascii leaf",
		in:   "_RNvNtNtCs5pO2ZDQbyWM_8v0exoticu13ncd_dma1a7bzbu5wxacd20plain_in_unicode_mod",
		want: "v0exotic::\u00fcn\u00efc\u00f6d\u00e9::\u03bb\u03bc\u03bd::plain_in_unicode_mod",
	}, {
		// LLVM's clone marker is dropped so two clones of one function collapse
		// into a single flame graph frame.
		name: "llvm clone marker dropped",
		in:   "_RNvCs5pO2ZDQbyWM_8v0exotic2id.llvm.12345678901234567890",
		want: "v0exotic::id",
	}, {
		// The library drops the WHOLE suffix, including the `.0` the clone
		// marker was applied on top of. rustfilt keeps `.0`.
		name: "llvm clone marker dropped with earlier suffix",
		in:   "_RNvNtNtCslf5agbebQAy_5tokio4time5clock15DID_PAUSE_CLOCK.0.llvm.16133919855429372288",
		want: "tokio::time::clock::DID_PAUSE_CLOCK",
	}, {
		// A cold-split half is folded into its function, so the hot and cold
		// halves render as one frame. rustfilt keeps `.cold.1`.
		name: "cold split suffix dropped",
		in:   "_RNvCs5pO2ZDQbyWM_8v0exotic2id.cold.1",
		want: "v0exotic::id",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, demangle(c.in))
		})
	}
}

// TestDemangleRustV0Rejects covers input that must come back untouched. Returning
// the raw symbol is the correct outcome for anything the demangler cannot read:
// a partially-decoded name would be confidently wrong, and a reader cannot tell
// a wrong name from a right one.
func TestDemangleRustV0Rejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"not a rust symbol", "main"},
		{"prefix only", "_R"},
		{"tag but nothing else", "_RC"},
		{"lowercase first tag is not a path", "_Rbogus"},
		{"digit after _R is a future encoding version", "_R0NvC8v0exotic2id"},
		{"identifier length longer than the symbol", "_RNvC99v0exotic2id"},
		{"identifier length one byte too long", "_RNvCs5pO2ZDQbyWM_9v0exotic2id"},
		{"truncated mid path", "_RNvCs5pO2ZDQbyWM_8v0exotic"},
		{"unterminated generic argument list", "_RINvCs5pO2ZDQbyWM_8v0exotic7genericAhj4_"},
		{"non ascii byte in body", "_RNvCs5pO2ZDQbyWM_8v0exotic2\u00e9d"},
		{"vendor suffix must start with a dot", "_RNvCs5pO2ZDQbyWM_8v0exotic2id$X"},
		{"unknown type tag", "_RINvCs5pO2ZDQbyWM_8v0exotic7genericWEB2_"},
		{"const with unsupported structural form", "_RINvCs5pO2ZDQbyWM_8v0exotic8cg_usizeKAj1_EB2_"},
		{"bool const with a non boolean value", "_RINvCs5pO2ZDQbyWM_8v0exotic7cg_boolKb7_EB2_"},
		// A char is a Unicode scalar value. Eight hex nibbles reach 0xFFFFFFFF,
		// and narrowing that to Go's int32-based rune yields a NEGATIVE value,
		// which would slip past a range check written against the rune and
		// render as U+FFFD. These must be refused, matching rustc-demangle.
		{"char const above the unicode maximum", "_RINvCs5pO2ZDQbyWM_8v0exotic7cg_charKcffffffff_EB2_"},
		{"char const with the sign bit set", "_RINvCs5pO2ZDQbyWM_8v0exotic7cg_charKc80000000_EB2_"},
		// A backref must point strictly backwards. A self-reference
		// is what a decoder could otherwise follow into an endless loop.
		{"self referential backref", "_RB0_"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.in, demangle(c.in), "expected %q to be returned unchanged", c.in)
		})
	}
}

// TestDemangleRustV0HostileDoesNotPanic is the safety test for the demangler.
//
// These symbols come off an on-disk ELF that can be truncated or crafted, and
// demangling runs inside the collector's profile-processing goroutine, so a
// panic takes profiling down for the whole host and a hang stalls the pipeline.
// Every input here must return -- whatever it returns -- rather than crash or
// spin.
func TestDemangleRustV0HostileDoesNotPanic(t *testing.T) {
	hostile := []string{
		"_R",
		"_RN",
		"_RNv",
		"_RI",
		"_RB",
		"_RB_",
		"_RB__",
		"_RK",
		"_RD",
		"_RF",
		"_RT",
		"_RA",
		"_RM",
		"_RX",
		"_RY",
		"_RG",
		// Deeply nested openers with no terminators: exercises the depth cap.
		"_R" + strings.Repeat("I", 10000),
		"_R" + strings.Repeat("N", 10000),
		"_R" + strings.Repeat("T", 10000),
		"_R" + strings.Repeat("R", 10000),
		"_RI" + strings.Repeat("A", 5000),
		// Backref chains: each must be rejected or move strictly backwards.
		"_R" + strings.Repeat("B", 5000),
		"_RNvC8v0exotic" + strings.Repeat("B1_", 3000),
		// Integers designed to overflow an accumulator.
		"_RNvC" + strings.Repeat("9", 40) + "abc",
		"_RB" + strings.Repeat("Z", 40) + "_",
		"_RIC" + strings.Repeat("z", 30) + "_E",
		"_RNvCs" + strings.Repeat("Z", 30) + "_8v0exotic2id",
		// A binder count large enough to spin a naive print loop.
		"_RIC8v0exoticFG" + strings.Repeat("Z", 12) + "_EuE",
		// Const bodies: unterminated, over-wide, and non-hex.
		"_RIC8v0exoticKj" + strings.Repeat("f", 5000),
		"_RIC8v0exoticKc" + strings.Repeat("f", 40) + "_E",
		"_RIC8v0exoticKjzzzz_E",
		// Punycode: unterminated and adversarial deltas.
		"_RNvCu" + strings.Repeat("9", 20) + "_abc",
		"_RNvCu10abc_" + strings.Repeat("z", 200),
		"_RNvNtCs5pO2ZDQbyWM_8v0exoticu13ncd_" + strings.Repeat("9", 100),
		// Identifier length prefixes at and beyond the integer boundary.
		"_RNvC9223372036854775807abc",
		"_RNvC9223372036854775808abc",
		"_RNvC18446744073709551616abc",
		// Invalid symbols the library is LENIENT on rather than rejecting, so
		// they are only required not to panic: a surrogate char const prints
		// as `'\u{d800}'`, and a forward backref yields the truncated
		// `v0exotic::`. rustc never emits either.
		"_RINvCs5pO2ZDQbyWM_8v0exotic7cg_charKcd800_EB2_",
		"_RNvCs5pO2ZDQbyWM_8v0exoticB999_",
		// Raw bytes that are not valid UTF-8 at all.
		"_RNvC\x00\xff\xfe",
		"_R\xff\xfe\x00",
	}
	for _, sym := range hostile {
		require.NotPanics(t, func() { _ = demangle(sym) }, "demangle(%q) panicked", sym)
	}
}

// TestDemangleRustV0MutationsDoNotPanic walks a valid symbol and, at every byte
// position, truncates it and substitutes a range of bytes. Truncation covers
// every "input ended here" path, and substitution covers every "unexpected tag
// here" path, which together reach failure branches that hand-written cases
// tend to miss.
func TestDemangleRustV0MutationsDoNotPanic(t *testing.T) {
	seeds := []string{
		"_RNvMs_NtNtNtNtCslf5agbebQAy_5tokio7runtime9scheduler12multi_thread6workerNtB4_7Context3run",
		"_RINvCs5pO2ZDQbyWM_8v0exotic8generic2FG_RL0_eERL0_euEB2_",
		"_RINvNtNtCs5pO2ZDQbyWM_8v0exoticu13ncd_dma1a7bzbu5wxacdu10wgv71a119ehEB6_",
		"_RINvCs5pO2ZDQbyWM_8v0exotic8generic2INtNtCsbSVVNPxiylx_5alloc5boxed3BoxDNtB2_2TrNtNtCsjemqvGMJH9i_4core6marker4SyncNtB1i_4SendEL_EuEB2_",
		"_RINvCs5pO2ZDQbyWM_8v0exotic7cg_charKc1f600_EB2_",
	}
	// A spread of structurally meaningful bytes: tags, terminators, separators,
	// digits, and the base-62 extremes.
	subs := []byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'I', 'K', 'L', 'M', 'N',
		'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'j', 'n', 'p', 's', 'u', 'v', 'z',
		'_', '0', '1', '9', '.', '$', 0x00, 0xff}

	for _, seed := range seeds {
		for i := range seed {
			trunc := seed[:i]
			require.NotPanics(t, func() { _ = demangle(trunc) }, "truncation at %d of %q", i, seed)
			for _, b := range subs {
				mutated := seed[:i] + string(b) + seed[i+1:]
				require.NotPanics(t, func() { _ = demangle(mutated) },
					"substitution %q at %d of %q", b, i, seed)
			}
		}
	}
}

// TestDemangleRustV0BackrefChainIsDepthBounded pins termination on long chains
// of backward references.
//
// The strictly-backwards rule makes a cycle impossible, but on its own it bounds
// a chain only by the length of the input: a recursive decoder spends a Go stack
// frame per hop, and a goroutine stack overflow is fatal -- recover() in
// demangle cannot catch it. These chains enter through a trait object's bounds,
// a const, and a generic argument list, so a library upgrade that loses its
// depth limit on any of those routes fails here rather than on a host.
func TestDemangleRustV0BackrefChainIsDepthBounded(t *testing.T) {
	var chain strings.Builder
	for i := 0; i < 20000; i++ {
		chain.WriteString("B1_")
	}
	seeds := []string{
		// Through a trait object's bounds.
		"_RIC8v0exoticD" + chain.String() + "EL_E",
		// Through a const.
		"_RIC8v0exoticK" + chain.String() + "E",
		// Through a generic argument list.
		"_RIC8v0exotic" + chain.String() + "E",
	}
	for _, sym := range seeds {
		require.NotPanics(t, func() { _ = demangle(sym) }, "backref chain must terminate")
	}
}

// TestDemangleRustV0OutputIsBounded proves the size cap holds. A backward reference
// expands to the text it points at, so a chain of them can describe an output far
// larger than the symbol that encodes it -- the classic decompression bomb. The
// cap is what keeps a crafted symbol from turning into an unbounded allocation
// inside the collector.
func TestDemangleRustV0OutputIsBounded(t *testing.T) {
	// Nest generic lists that each re-reference an earlier one, so the notional
	// expansion grows far faster than the input.
	var b strings.Builder
	b.WriteString("_RIC8v0exotic")
	for i := 0; i < 400; i++ {
		b.WriteString("IB4_B4_E")
	}
	b.WriteString("E")
	out := demangle(b.String())
	require.LessOrEqual(t, len(out), (1<<demangleMaxLength)+len(b.String()),
		"output must stay bounded by the cap (or be the raw symbol)")
}

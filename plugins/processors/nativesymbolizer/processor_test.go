// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.uber.org/zap/zaptest"
)

// buildTestBinary compiles a NON-PIE fixture. Non-PIE is used for the default
// fixture because a symbol's link-time value then equals its runtime-relative
// address, which keeps the arithmetic in these tests trivially checkable.
// TestResolvePIEParseAndResolve covers the PIE case explicitly, since PIE is
// what most binaries are.
func buildTestBinary(t *testing.T) (string, string, uint64) {
	t.Helper()
	return buildTestBinaryWith(t, "-no-pie")
}

// buildTestBinaryPIE compiles a position-independent fixture (ELF ET_DYN).
func buildTestBinaryPIE(t *testing.T) (string, string, uint64) {
	t.Helper()
	return buildTestBinaryWith(t, "-fPIE", "-pie")
}

// buildTestBinaryWith compiles a tiny C program with a named, non-inlined
// function and a GNU build ID, returning its path, GNU build ID (hex), and an
// address a few bytes inside that function. C keeps the test cheap (a C
// compiler is far more common on a build host than a Rust toolchain) while
// exercising the exact same .symtab + .note.gnu.build-id path a Rust binary
// hits -- the resolver is language-agnostic by construction.
func buildTestBinaryWith(t *testing.T, extra ...string) (string, string, uint64) {
	t.Helper()
	cc := cCompiler(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "prog.c")
	bin := filepath.Join(dir, "prog")
	// -O0 -fno-inline keeps hot_leaf a real, addressable symbol.
	// -Wl,--build-id forces a GNU build-id note.
	require.NoError(t, os.WriteFile(src, []byte(`
#include <stdio.h>
__attribute__((noinline)) long hot_leaf(long n){ long a=0; for(long i=0;i<n;i++) a+=i; return a; }
int main(void){ printf("%ld\n", hot_leaf(1000)); return 0; }
`), 0o600))
	args := append([]string{"-O0", "-fno-inline", "-g", "-Wl,--build-id"}, extra...)
	args = append(args, "-o", bin, src)
	out, err := exec.Command(cc, args...).CombinedOutput()
	require.NoError(t, err, "compile failed: %s", out)

	st, err := newSymbolTable(bin)
	require.NoError(t, err)
	require.NotEmpty(t, st.buildID, "test binary must have a build id")

	// Find hot_leaf's start address so the synthetic sample can point at it.
	for _, r := range st.ranges {
		if r.name == "hot_leaf" {
			return bin, st.buildID, r.start + 4 // a few bytes into the function
		}
	}
	t.Fatalf("hot_leaf not found in symbol table of %s", bin)
	return "", "", 0
}

// makeProfiles builds a minimal Profiles payload: a shared dictionary with one
// mapping (whose build_id.gnu attribute is set) and no address range, one
// native location with NO lines, one stack referencing it, and one sample
// referencing that stack.
func makeProfiles(binName, buildID string, addr uint64) pprofile.Profiles {
	pd := pprofile.NewProfiles()
	dict := pd.Dictionary()

	strTab := dict.StringTable()
	// index 0 is conventionally the empty string
	strTab.Append("")                    // 0
	strTab.Append(binName)               // 1 mapping filename
	strTab.Append(attrMappingBuildIDGnu) // 2 attr key: build id
	strTab.Append(buildID)               // 3 attr val: build id
	strTab.Append(attrFrameType)         // 4 attr key: frame type
	strTab.Append(frameTypeNative)       // 5 attr val: native

	attrTab := dict.AttributeTable()
	kvBuild := attrTab.AppendEmpty() // attr 0: build id
	kvBuild.SetKeyStrindex(2)
	kvBuild.Value().SetStr(buildID)
	kvFrame := attrTab.AppendEmpty() // attr 1: frame type = native
	kvFrame.SetKeyStrindex(4)
	kvFrame.Value().SetStr(frameTypeNative)

	mapTab := dict.MappingTable()
	m := mapTab.AppendEmpty()
	m.SetFilenameStrindex(1)
	m.AttributeIndices().Append(0) // -> build id attr

	locTab := dict.LocationTable()
	loc := locTab.AppendEmpty()
	loc.SetMappingIndex(0)
	loc.SetAddress(addr)
	loc.AttributeIndices().Append(1) // -> frame type = native
	// NO lines -- this is how a sender reports a native frame it did not name.

	stackTab := dict.StackTable()
	stk := stackTab.AppendEmpty()
	stk.LocationIndices().Append(0)

	rp := pd.ResourceProfiles().AppendEmpty()
	sp := rp.ScopeProfiles().AppendEmpty()
	prof := sp.Profiles().AppendEmpty()
	smp := prof.Samples().AppendEmpty()
	smp.SetStackIndex(0)

	return pd
}

func firstLocationName(t *testing.T, pd pprofile.Profiles) (string, bool) {
	t.Helper()
	dict := pd.Dictionary()
	loc := dict.LocationTable().At(0)
	if loc.Lines().Len() == 0 {
		return "", false
	}
	fi := loc.Lines().At(0).FunctionIndex()
	fn := dict.FunctionTable().At(int(fi))
	return dict.StringTable().At(int(fn.NameStrindex())), true
}

// TestSymbolizesNativeFrame is the headline test: a native location with no
// lines gets `hot_leaf` written into it, matching build IDs.
func TestSymbolizesNativeFrame(t *testing.T) {
	bin, buildID, addr := buildTestBinary(t)
	pd := makeProfiles(bin, buildID, addr)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	name, ok := firstLocationName(t, pd)
	require.True(t, ok, "expected the native location to gain a line")
	require.Equal(t, "hot_leaf", name)
	require.Equal(t, uint64(1), s.framesResolved.Load())
}

// TestBuildIDMismatchRefuses proves the guard: a wrong build ID leaves the
// frame unresolved rather than emitting a confidently-wrong name.
func TestBuildIDMismatchRefuses(t *testing.T) {
	bin, _, addr := buildTestBinary(t)
	pd := makeProfiles(bin, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", addr)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	_, ok := firstLocationName(t, pd)
	require.False(t, ok, "mismatched build id must NOT be symbolized")
	require.Equal(t, uint64(1), s.buildIDMismatch.Load())
	require.Equal(t, uint64(0), s.framesResolved.Load())
}

// TestAlreadySymbolizedUntouched confirms kernel/Go frames (which arrive WITH
// lines) are left exactly as-is.
func TestAlreadySymbolizedUntouched(t *testing.T) {
	bin, buildID, addr := buildTestBinary(t)
	pd := makeProfiles(bin, buildID, addr)
	// Pre-populate a line so the location looks already-symbolized.
	dict := pd.Dictionary()
	dict.StringTable().Append("preexisting_symbol")
	preIdx := i32(dict.StringTable().Len() - 1)
	fn := dict.FunctionTable().AppendEmpty()
	fn.SetNameStrindex(preIdx)
	fnIdx := i32(dict.FunctionTable().Len() - 1)
	dict.LocationTable().At(0).Lines().AppendEmpty().SetFunctionIndex(fnIdx)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	name, ok := firstLocationName(t, pd)
	require.True(t, ok)
	require.Equal(t, "preexisting_symbol", name, "must not overwrite existing symbolization")
	require.Equal(t, uint64(0), s.framesResolved.Load())
}

// TestNativeNameTakesNoSourceFileOfAnInterpretedFunction covers a report that
// also holds an interpreted frame with the name of a C function. A sender may
// write a Function with a name and a source file for each interpreted frame,
// and one dictionary serves every process of a report. So a Python function
// named read and the libc function read have the same name string. The native
// frame must get a Function of its own, with no source file: a libc frame
// shown as "read /usr/lib64/python3.7/ssl.py" is a wrong frame. A Function of
// the sender that holds only a name (a kernel frame, for example) is still
// reused.
func TestNativeNameTakesNoSourceFileOfAnInterpretedFunction(t *testing.T) {
	t.Run("libc read next to a Python read", func(t *testing.T) {
		prefix := t.TempDir()
		proc := newFakeProc(t, prefix, fakePID)
		lib := proc.inRoot("/usr/lib64/libc-2.26.so")
		fx := classicLayout([]byte("libc-2.26-build-id"))
		fx.funcs = []fixtureFunc{{name: "read", off: 0x1000, size: 0x40}, {name: "write", off: 0x1800, size: 0x80}}
		writeELFFixture(t, lib, fx)
		off, length := kernelMapping(fx)
		m := senderMapping(t, lib, off, length)
		start := uint64(0x7f3a1c000000)
		end := proc.mapExec(start, m.offset, m.limit-m.start, "/usr/lib64/libc-2.26.so")
		proc.writeMaps()
		proc.linkMapFile(start, end, lib)

		pd := buildPayload(
			[]fxMapping{m},
			[]fxLocation{{mapping: 0, addr: fx.addr(t, "read", 4)}},
			[]fxResource{{pid: fakePID, exe: "/usr/bin/python3.7", locs: []int{0}}},
		)
		python := addNamedFrame(pd, 0, 0, "read", "/usr/lib64/python3.7/ssl.py", "python")
		before := pd.Dictionary().FunctionTable().Len()

		s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
		_, err := s.processProfiles(context.Background(), pd)
		require.NoError(t, err)

		fi, name, file := locationFunction(t, pd, 0)
		require.Equal(t, "read", name)
		require.Empty(t, file, "the libc frame must not take the source file of the Python function")
		require.NotEqual(t, python, fi)
		require.Equal(t, before+1, pd.Dictionary().FunctionTable().Len(), "the libc frame gets a Function of its own")
	})

	t.Run("a Function of the sender with only a name is reused", func(t *testing.T) {
		bin, buildID, addr := buildTestBinary(t)
		pd := buildPayload(
			[]fxMapping{{filename: bin, gnu: buildID}},
			[]fxLocation{{mapping: 0, addr: addr}},
			[]fxResource{{locs: []int{0}}},
		)
		kernel := addNamedFrame(pd, 0, 0, "hot_leaf", "", "kernel")
		before := pd.Dictionary().FunctionTable().Len()

		s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
		_, err := s.processProfiles(context.Background(), pd)
		require.NoError(t, err)

		fi, name, _ := locationFunction(t, pd, 0)
		require.Equal(t, "hot_leaf", name)
		require.Equal(t, kernel, fi)
		require.Equal(t, before, pd.Dictionary().FunctionTable().Len(), "no second Function for the same name")
	})
}

// TestResolvePIEParseAndResolve confirms a position-independent binary (ELF
// ET_DYN, the Rust and modern C default) parses and resolves. It does NOT prove
// the address convention -- the sample address is derived from the same
// st_value the resolver compares against, so the lookup is self-referential and
// would pass with or without any bias arithmetic. Its value is narrower but
// real: PIE binaries parse through debug/elf and produce non-empty symbol
// ranges, which a regression that mishandled ET_DYN section layout would break.
// The address convention itself is asserted by TestAddressConventionIsFileRelative.
func TestResolvePIEParseAndResolve(t *testing.T) {
	bin, buildID, addr := buildTestBinaryPIE(t)

	ef, err := elf.Open(bin)
	require.NoError(t, err)
	require.Equal(t, elf.ET_DYN, ef.Type, "fixture must be PIE (ET_DYN)")
	require.NoError(t, ef.Close())

	pd := makeProfiles(bin, buildID, addr)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	_, err = s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	name, ok := firstLocationName(t, pd)
	require.True(t, ok, "a PIE binary's native frame must resolve")
	require.Equal(t, "hot_leaf", name)
}

// TestAddressConventionIsFileRelative is the actual convention regression test.
// It proves resolve() treats the incoming address as a FILE-RELATIVE ELF
// virtual address (no load bias), independently of newSymbolTable's own ranges:
//
//   - An address inside hot_leaf's [start, start+size) extent resolves to it.
//   - That SAME address plus a large "runtime base" (as an absolute-address
//     convention would produce) resolves to nothing -- proving the resolver is
//     NOT silently applying or tolerating a bias.
//
// If resolve() ever started subtracting a base, the biased address would
// wrongly resolve and this test would fail -- which the self-referential PIE
// test could not detect.
func TestAddressConventionIsFileRelative(t *testing.T) {
	bin, _, _ := buildTestBinary(t)
	st, err := newSymbolTable(bin)
	require.NoError(t, err)

	// Locate hot_leaf's extent directly from the symbol table.
	var start, size uint64
	for _, r := range st.ranges {
		if r.name == "hot_leaf" {
			start, size = r.start, r.size
		}
	}
	require.NotZero(t, size, "hot_leaf must have a nonzero extent")

	// A file-relative address inside the function resolves.
	name, _, ok := st.resolve(start + size/2)
	require.True(t, ok)
	require.Equal(t, "hot_leaf", name)

	// The same offset shifted by a plausible runtime load base must NOT resolve
	// -- the resolver does no bias subtraction, so a biased address is off the
	// end of every known range.
	const runtimeBase = 0x555555554000 // a typical PIE load base
	_, _, ok = st.resolve(runtimeBase + start + size/2)
	require.False(t, ok, "a load-biased address must not resolve; resolver is file-relative")
}

// TestFrameOutsideItsMappingIsRefused proves the range check: a frame whose
// address is not inside [memory_start, memory_limit) of its mapping is refused
// before any file is read, rather than placed in a file by a guess. The address
// is a few bytes into hot_leaf of the non-PIE fixture. memory_limit is the
// first address past the mapping, so the case with memory_limit equal to the
// address is outside too. The last case is a mapping with a file offset but no
// memory_limit: its range is empty.
//
// This test was TestMappingBiasRefused, for the old rule that refused every
// mapping with a non-zero memory_start or file_offset. That rule is gone: such
// a mapping resolves when its range holds the address (see
// TestLibraryWhoseTextIsNotAtOffsetZero).
func TestFrameOutsideItsMappingIsRefused(t *testing.T) {
	bin, buildID, addr := buildTestBinary(t)
	for _, tc := range []struct {
		name        string
		memoryStart uint64
		memoryLimit uint64
		fileOffset  uint64
	}{
		{"address below memory_start", 0x40000000, 0x40001000, 0},
		{"address past memory_limit", 0x1000, 0x2000, 0},
		{"address equal to memory_limit", addr - 0x100, addr, 0},
		{"file_offset set but no memory_limit, so the range is empty", 0, 0, 0x1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pd := makeProfiles(bin, buildID, addr)
			m := pd.Dictionary().MappingTable().At(0)
			m.SetMemoryStart(tc.memoryStart)
			m.SetMemoryLimit(tc.memoryLimit)
			m.SetFileOffset(tc.fileOffset)

			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
			_, err := s.processProfiles(context.Background(), pd)
			require.NoError(t, err)

			_, ok := firstLocationName(t, pd)
			require.False(t, ok, "a frame outside its mapping must not be resolved")
			require.Equal(t, uint64(1), s.mappingBiasUnexpected.Load())
			require.Equal(t, uint64(0), s.framesResolved.Load())
			require.Equal(t, uint64(0), s.candidateWalks.Load(), "the frame is refused before any file is read")
		})
	}
}

// TestTransientFailureNotLatched proves a transient open failure is retried
// rather than permanently negative-cached: a path that does not exist yet must
// resolve once it appears.
func TestTransientFailureNotLatched(t *testing.T) {
	realBin, _, _ := buildTestBinary(t)
	missing := filepath.Join(t.TempDir(), "appears-later")

	c := newResolverCache(8)
	st, _ := c.get(missing)
	require.Nil(t, st, "missing file must not resolve")
	require.Equal(t, 0, c.len(), "a transient open failure must NOT be cached")

	// Now the file appears (as a container mount / late write would).
	data, err := os.ReadFile(realBin)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(missing, data, 0o600)) //nolint:gosec // G703: test-controlled temp file

	st, _ = c.get(missing)
	require.NotNil(t, st, "path must be retried once it becomes readable")
}

// TestStrippedIsLatched is the counterpart: a definitively unsymbolizable file
// IS negative-cached, so a hot stripped mapping is not re-parsed every report.
func TestStrippedIsLatched(t *testing.T) {
	bin, _, _ := buildTestBinary(t)
	stripped := filepath.Join(t.TempDir(), "stripped")
	data, err := os.ReadFile(bin)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(stripped, data, 0o600)) //nolint:gosec // G703: test-controlled temp file
	out, err := exec.Command("strip", "--strip-all", stripped).CombinedOutput()
	if err != nil {
		t.Skipf("strip unavailable: %v: %s", err, out)
	}

	c := newResolverCache(8)
	st, _ := c.get(stripped)
	require.Nil(t, st)
	require.Equal(t, 1, c.len(), "a stripped binary must be negative-cached")
}

// TestNoCandidateIsCounted covers the miss that had no counter before: the
// binary is absent at every candidate path (the sampled process exited, or its
// container root is not visible). It must be attributed, not silently dropped.
func TestNoCandidateIsCounted(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "never-existed")
	pd := makeProfiles(absent, "aabbccddeeff00112233445566778899aabbccdd", 0x1000)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	_, ok := firstLocationName(t, pd)
	require.False(t, ok)
	require.Equal(t, uint64(1), s.framesSeen.Load())
	require.Equal(t, uint64(1), s.framesNoCandidate.Load())
	require.Equal(t, uint64(0), s.framesResolved.Load())
}

// TestNoSymbolIsCounted covers the other previously-unattributed miss: the
// binary is found and build-ID-matched, but the address lands in no function
// extent. Address 0 is guaranteed to be below every symbol.
func TestNoSymbolIsCounted(t *testing.T) {
	bin, buildID, _ := buildTestBinary(t)
	pd := makeProfiles(bin, buildID, 0) // address in no function

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Equal(t, uint64(1), s.framesNoSymbol.Load())
	require.Equal(t, uint64(0), s.framesResolved.Load())
}

// TestCountersAccountForEverySeenFrame is the invariant AutoSDE's finding was
// really about: every frame the processor SEES must land in exactly one bucket,
// so an operator subtracting them gets zero rather than an unexplained residual.
// A new miss path added without a counter fails this test.
func TestCountersAccountForEverySeenFrame(t *testing.T) {
	goodBin, goodID, goodAddr := buildTestBinary(t)
	absent := filepath.Join(t.TempDir(), "never-existed")

	// The cases share one symbolizer, and so one cache, which is keyed by the
	// content of the sampled file. So the no candidate case names a build ID
	// that no other case resolves. With goodID, the table that the first case
	// cached would name it.
	cases := []struct {
		name        string
		binPath     string
		buildID     string
		addr        uint64
		memoryStart uint64
	}{
		{"resolved", goodBin, goodID, goodAddr, 0},
		{"no candidate", absent, "aabbccddeeff00112233445566778899aabbccdd", goodAddr, 0},
		{"build id mismatch", goodBin, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", goodAddr, 0},
		{"no symbol at address", goodBin, goodID, 0, 0},
		{"address outside the mapping", goodBin, goodID, goodAddr, 0x40000000},
	}

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	for _, c := range cases {
		pd := makeProfiles(c.binPath, c.buildID, c.addr)
		if c.memoryStart != 0 {
			// memory_limit stays 0, so the range is empty.
			pd.Dictionary().MappingTable().At(0).SetMemoryStart(c.memoryStart)
		}
		_, err := s.processProfiles(context.Background(), pd)
		require.NoError(t, err, c.name)
	}
	require.Equal(t, uint64(1), s.framesResolved.Load(), "resolved")
	require.Equal(t, uint64(1), s.framesNoCandidate.Load(), "no candidate")
	require.Equal(t, uint64(1), s.buildIDMismatch.Load(), "build id mismatch")
	require.Equal(t, uint64(1), s.framesNoSymbol.Load(), "no symbol at address")
	require.Equal(t, uint64(1), s.mappingBiasUnexpected.Load(), "address outside the mapping")

	seen := s.framesSeen.Load()
	accounted := s.framesResolved.Load() +
		s.framesNoCandidate.Load() +
		s.framesNoBuildID.Load() +
		s.buildIDMismatch.Load() +
		s.framesNoSymbol.Load() +
		s.mappingBiasUnexpected.Load()

	require.Equal(t, uint64(len(cases)), seen, "each case contributes one seen frame")
	require.Equal(t, seen, accounted,
		"every seen frame must be accounted for; a miss path without a counter leaves a residual")
}

// TestHotStackCountedOncePerLocation covers the per-pass dedup: a location
// referenced by MANY samples (a hot stack) must be symbolized and counted
// exactly once, not once per sample. This is the case the single-sample tests
// above miss -- without dedup an unresolved native frame re-runs the candidate
// walk and re-increments a miss counter on every sample, mixing per-location
// and per-occurrence counting bases.
func TestHotStackCountedOncePerLocation(t *testing.T) {
	bin, buildID, addr := buildTestBinary(t)
	pd := makeProfiles(bin, buildID, addr)

	// makeProfiles created one sample referencing stack 0 (which references
	// location 0). Add 99 more samples referencing the same stack, simulating a
	// hot frame sampled 100 times.
	prof := pd.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles().At(0)
	for i := 0; i < 99; i++ {
		prof.Samples().AppendEmpty().SetStackIndex(0)
	}
	require.Equal(t, 100, prof.Samples().Len())

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	// Exactly one location exists; it must be seen and resolved once, not 100x.
	require.Equal(t, uint64(1), s.framesSeen.Load(), "hot location counted once per pass")
	require.Equal(t, uint64(1), s.framesResolved.Load())
}

// TestHotStackMissCountedOnce is the miss-path counterpart: an UNRESOLVED hot
// location (build-ID mismatch) must also be counted once, not once per sample.
// This is the specific over-counting the AutoSDE finding described, since a miss
// never mutates the location to trip the already-symbolized short-circuit.
func TestHotStackMissCountedOnce(t *testing.T) {
	bin, _, addr := buildTestBinary(t)
	pd := makeProfiles(bin, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", addr)
	prof := pd.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles().At(0)
	for i := 0; i < 99; i++ {
		prof.Samples().AppendEmpty().SetStackIndex(0)
	}

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Equal(t, uint64(1), s.framesSeen.Load())
	require.Equal(t, uint64(1), s.buildIDMismatch.Load(), "hot miss counted once, not per-sample")
}

// TestResolverCacheEvicts checks the LRU bound holds.
func TestResolverCacheEvicts(t *testing.T) {
	c := newResolverCache(2)
	c.insert("a", cacheEntry{})
	c.insert("b", cacheEntry{})
	c.insert("c", cacheEntry{}) // should evict "a"
	require.Equal(t, 2, c.len())
	_, ok := c.entries["a"]
	require.False(t, ok, "a should have been evicted")
}

// TestRedeployInvalidatesNegativeCache proves a stripped verdict does NOT
// outlive the file: after a stripped binary is negative-cached, replacing it
// with an unstripped one at the same path (a redeploy) must re-parse and
// resolve, rather than staying blinded for the collector's lifetime.
func TestRedeployInvalidatesNegativeCache(t *testing.T) {
	stripped, _, _ := buildTestBinary(t)
	// Strip a copy at a stable path.
	path := filepath.Join(t.TempDir(), "app")
	data, err := os.ReadFile(stripped)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600)) //nolint:gosec // G703: test-controlled temp file
	if out, err := exec.Command("strip", "--strip-all", path).CombinedOutput(); err != nil {
		t.Skipf("strip unavailable: %v: %s", err, out)
	}

	c := newResolverCache(8)
	st, _ := c.get(path)
	require.Nil(t, st, "stripped binary resolves to nothing")
	require.Equal(t, 1, c.len(), "stripped verdict is latched")

	// Redeploy: an unstripped binary lands at the same path. Its mtime/size
	// differ, so the fingerprint changes and the negative entry is invalidated.
	// Sleep past filesystem mtime granularity so the timestamp is guaranteed
	// distinct even on a coarse clock.
	time.Sleep(10 * time.Millisecond)
	full, _, _ := buildTestBinary(t)
	fullData, err := os.ReadFile(full)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, fullData, 0o600)) //nolint:gosec // G703: test-controlled temp file

	st, _ = c.get(path)
	require.NotNil(t, st, "redeployed unstripped binary must be re-parsed, not stay blinded")
	require.NotEmpty(t, st.ranges)
}

// TestResolveOffsets checks address->name+offset containment, including gaps.
func TestResolveOffsets(t *testing.T) {
	bin, _, addr := buildTestBinary(t)
	st, err := newSymbolTable(bin)
	require.NoError(t, err)
	name, off, ok := st.resolve(addr)
	require.True(t, ok)
	require.Equal(t, "hot_leaf", name)
	require.Equal(t, uint64(4), off)

	// An address below everything resolves to nothing.
	_, _, ok = st.resolve(1)
	require.False(t, ok)
}

// TestResolveOverlappingSymbols is the r2 AutoSDE regression test. ELF symbol
// tables routinely carry overlapping/aliased function symbols: a small alias
// sharing (or nested within) a larger enclosing function's address range. A
// naive resolver that trusts only the single `last start <= addr` binary-search
// hit reports a FALSE "no symbol" when that hit is a short alias and addr lies
// in the alias's gap but still inside the enclosing function. resolve() must
// find the covering symbol regardless, and prefer the tightest (most specific)
// cover when several overlap.
func TestResolveOverlappingSymbols(t *testing.T) {
	// Layout (all file-relative):
	//   enclosing [0x1000, 0x1200)  size 0x200  -- large enclosing function
	//   alias     [0x1000, 0x1010)  size 0x010  -- zero-ish alias sharing start
	//   tight     [0x1080, 0x10a0)  size 0x020  -- a tighter nested symbol
	//   later     [0x2000, 0x2040)  size 0x040  -- unrelated, non-overlapping
	st := &symbolTable{ranges: []funcRange{
		{start: 0x1000, size: 0x200, name: "enclosing"},
		{start: 0x1000, size: 0x010, name: "alias"},
		{start: 0x1080, size: 0x020, name: "tight"},
		{start: 0x2000, size: 0x040, name: "later"},
	}}
	st.finalize()

	cases := []struct {
		name     string
		addr     uint64
		wantName string
		wantOK   bool
	}{
		// Inside the alias AND the enclosing: tightest cover wins.
		{"shared start picks smallest cover", 0x1008, "alias", true},
		// Past the alias's end (0x1010) but inside enclosing: the exact false
		// miss the finding described -- must still resolve to enclosing.
		{"in alias gap resolves to enclosing", 0x1020, "enclosing", true},
		// Inside the nested tight symbol: tightest cover wins over enclosing.
		{"nested tighter symbol wins", 0x1090, "tight", true},
		// Inside enclosing, past tight: enclosing.
		{"past nested still enclosing", 0x1100, "enclosing", true},
		// A genuine gap between clusters resolves to nothing.
		{"gap between clusters", 0x1500, "", false},
		// The unrelated later symbol resolves independently.
		{"later symbol", 0x2010, "later", true},
		// Below everything.
		{"below all", 0x0800, "", false},
	}
	for _, c := range cases {
		name, _, ok := st.resolve(c.addr)
		require.Equal(t, c.wantOK, ok, "%s: addr 0x%x ok", c.name, c.addr)
		if c.wantOK {
			require.Equal(t, c.wantName, name, "%s: addr 0x%x name", c.name, c.addr)
		}
	}
}

// TestResolveSortIsDeterministic guards the tie-break: among ranges sharing a
// start, finalize() must order larger extent first (then by name) so the
// surviving cover is stable rather than dependent on sort.Slice's unstable
// order. Building the same ranges in several input orders must yield the same
// resolution.
func TestResolveSortIsDeterministic(t *testing.T) {
	mk := func(order []funcRange) *symbolTable {
		st := &symbolTable{ranges: append([]funcRange(nil), order...)}
		st.finalize()
		return st
	}
	a := []funcRange{
		{start: 0x100, size: 0x80, name: "big"},
		{start: 0x100, size: 0x10, name: "small"},
	}
	b := []funcRange{
		{start: 0x100, size: 0x10, name: "small"},
		{start: 0x100, size: 0x80, name: "big"},
	}
	// Address inside big but past small: both orders must resolve to big.
	for _, st := range []*symbolTable{mk(a), mk(b)} {
		name, _, ok := st.resolve(0x140)
		require.True(t, ok)
		require.Equal(t, "big", name)
		// The largest-first tie-break also makes ranges[0] deterministic.
		require.Equal(t, "big", st.ranges[0].name)
	}
}

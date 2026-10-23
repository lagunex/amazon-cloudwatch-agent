// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestNoBuildIDResolvesByHtlhash covers a binary linked with no GNU build ID.
// Its mapping carries only the htlhash, and the frame must be named when the
// file's htlhash is the same.
func TestNoBuildIDResolvesByHtlhash(t *testing.T) {
	bin, addr := buildNoBuildIDBinary(t)
	pd := buildPayload(
		[]fxMapping{{filename: bin, htlhash: htlhashOf(t, bin)}},
		[]fxLocation{{mapping: 0, addr: addr}},
		[]fxResource{{locs: []int{0}}},
	)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Equal(t, "hot_leaf", locationName(pd, 0))
	require.Equal(t, uint64(1), s.framesResolved.Load())
	require.Equal(t, uint64(1), s.framesResolvedByHtlhash.Load(), "the htlhash proved this file")
	require.Equal(t, uint64(0), s.framesNoBuildID.Load())
}

// TestNoBuildIDChangedHeaderByteIsRefused proves that the htlhash is a real
// identity check, not a formality. The file on disk differs from the sampled
// one in a single byte in its first 4 KiB: same path, same size, still a valid
// ELF whose symbols still name the address. Only the identity check can refuse
// it, and it must, and count the refusal.
func TestNoBuildIDChangedHeaderByteIsRefused(t *testing.T) {
	bin, addr := buildNoBuildIDBinary(t)
	sampled := htlhashOf(t, bin) // what the sender recorded

	data, err := os.ReadFile(bin)
	require.NoError(t, err)
	data[elf.EI_PAD] ^= 0xff                           // ELF header padding: no reader looks at it
	require.NoError(t, os.WriteFile(bin, data, 0o600)) //nolint:gosec // G703: test-controlled temp file

	st, err := newSymbolTable(bin)
	require.NoError(t, err, "the changed file must still parse")
	name, _, ok := st.resolve(addr)
	require.True(t, ok)
	require.Equal(t, "hot_leaf", name, "the changed file still names the address, so the test cannot pass by a parse failure")
	require.NotEqual(t, sampled, htlhashOf(t, bin))

	pd := buildPayload(
		[]fxMapping{{filename: bin, htlhash: sampled}},
		[]fxLocation{{mapping: 0, addr: addr}},
		[]fxResource{{locs: []int{0}}},
	)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	_, err = s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Empty(t, locationName(pd, 0), "a file with another htlhash must NOT be symbolized")
	require.Equal(t, uint64(1), s.htlhashMismatch.Load())
	require.Equal(t, uint64(0), s.framesResolved.Load())
}

// TestNoIdentityAtAllStaysUnresolved keeps the old rule for a mapping that
// carries neither a GNU build ID nor an htlhash: nothing can prove the file, so
// it is not used, and the frame is counted no_build_id.
func TestNoIdentityAtAllStaysUnresolved(t *testing.T) {
	bin, addr := buildNoBuildIDBinary(t)
	pd := buildPayload(
		[]fxMapping{{filename: bin}},
		[]fxLocation{{mapping: 0, addr: addr}},
		[]fxResource{{locs: []int{0}}},
	)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Empty(t, locationName(pd, 0))
	require.Equal(t, uint64(1), s.framesNoBuildID.Load())
}

// TestGNUBuildIDStaysStrictWhenTheHtlhashMatches proves that the htlhash does
// not loosen the strict rule. When the mapping has a GNU build ID, a file with
// another GNU build ID is refused even if the mapping's htlhash is the file's.
func TestGNUBuildIDStaysStrictWhenTheHtlhashMatches(t *testing.T) {
	bin, _, addr := buildTestBinary(t)
	pd := buildPayload(
		[]fxMapping{{filename: bin, gnu: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", htlhash: htlhashOf(t, bin)}},
		[]fxLocation{{mapping: 0, addr: addr}},
		[]fxResource{{locs: []int{0}}},
	)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Empty(t, locationName(pd, 0))
	require.Equal(t, uint64(1), s.buildIDMismatch.Load())
	require.Equal(t, uint64(0), s.framesResolvedByHtlhash.Load())
}

// TestCountersAccountForTheNewOutcomes extends the accounting invariant of
// TestCountersAccountForEverySeenFrame to the outcomes this processor added:
// every seen frame lands in exactly one bucket, including the htlhash and
// address-range outcomes.
//
// The cases share one symbolizer, and so one cache. The mismatch case
// therefore names a sampled htlhash that no earlier case resolved: that of
// another build, which is not the file at the path.
func TestCountersAccountForTheNewOutcomes(t *testing.T) {
	noID, noIDAddr := buildNoBuildIDBinary(t)
	otherBuild, _ := buildNoBuildIDBinaryWith(t, "long other_leaf(long n){ return n * 3; }\n")
	require.NotEqual(t, htlhashOf(t, noID), htlhashOf(t, otherBuild))
	withID, withIDValue, withIDAddr := buildTestBinary(t)

	cases := []struct {
		name string
		m    fxMapping
		addr uint64
	}{
		{"resolved by htlhash", fxMapping{filename: noID, htlhash: htlhashOf(t, noID)}, noIDAddr},
		{"htlhash mismatch", fxMapping{filename: noID, htlhash: htlhashOf(t, otherBuild)}, noIDAddr},
		{"no identity", fxMapping{filename: noID}, noIDAddr},
		{"no candidate", fxMapping{filename: filepath.Join(t.TempDir(), "absent"), htlhash: "00112233445566778899aabbccddeeff"}, 0x1000},
		{"address outside the mapping", fxMapping{filename: withID, gnu: withIDValue, start: 0x1000, limit: 0x2000}, withIDAddr},
		// A sender may put an htlhash on every mapping, so a mapping with a GNU
		// build ID can have both. Only the GNU build ID proves it, so it does
		// not count as resolved by htlhash.
		{"resolved by GNU build ID", fxMapping{filename: withID, gnu: withIDValue, htlhash: htlhashOf(t, withID)}, withIDAddr},
	}

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	for _, c := range cases {
		pd := buildPayload([]fxMapping{c.m}, []fxLocation{{mapping: 0, addr: c.addr}}, []fxResource{{locs: []int{0}}})
		_, err := s.processProfiles(context.Background(), pd)
		require.NoError(t, err, c.name)
	}

	require.Equal(t, uint64(2), s.framesResolved.Load())
	require.Equal(t, uint64(1), s.framesResolvedByHtlhash.Load())
	require.Equal(t, uint64(1), s.htlhashMismatch.Load())
	require.Equal(t, uint64(1), s.framesNoBuildID.Load())
	require.Equal(t, uint64(1), s.framesNoCandidate.Load())
	require.Equal(t, uint64(1), s.mappingBiasUnexpected.Load())

	seen := s.framesSeen.Load()
	accounted := s.framesResolved.Load() +
		s.framesNoCandidate.Load() +
		s.framesNoBuildID.Load() +
		s.buildIDMismatch.Load() +
		s.htlhashMismatch.Load() +
		s.framesNoSymbol.Load() +
		s.mappingBiasUnexpected.Load()
	require.Equal(t, uint64(len(cases)), seen)
	require.Equal(t, seen, accounted, "every seen frame must be accounted for")
}

// TestHtlhashGoldenVectors pins htlhash to the semantic-convention definition
// at the boundaries where the head and the tail overlap or meet (4 KiB, 8 KiB).
// The expected values were produced once by the htlhash implementation of the
// OpenTelemetry eBPF profiler, a widely used sender of this attribute, on the
// same inputs, so the two agree byte for byte.
func TestHtlhashGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		size int
		want string
	}{
		{1, "52807a4607ea5debf0b7d4ccb452f4af"},
		{100, "ff9061fbd8a92dc691e14343e5fc1bd2"},
		{4095, "2163b454a35d188200935087260408c1"},
		{4096, "7e9a755dfdcc88b11037ffaf0aff0527"},
		{4097, "5572f2aa5f6a81f41fb41a983e79f37a"},
		{8191, "16476651edaf7f518d0e91fe3951efb1"},
		{8192, "8410e712063d5774fece43c81468ebfd"},
		{8193, "0956c4bd6d1f58aac7773020b516cb78"},
		{20000, "97d1f1703fa33eaf6f60becb4af2090a"},
	} {
		t.Run(fmt.Sprint(tc.size), func(t *testing.T) {
			data := make([]byte, tc.size)
			for i := range data {
				data[i] = byte(i*7 + i/251)
			}
			path := filepath.Join(t.TempDir(), "file")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			f, err := os.Open(path)
			require.NoError(t, err)
			defer f.Close()
			got, err := htlhash(f)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.want, htlhashOf(t, path), "the test helper agrees")
		})
	}
}

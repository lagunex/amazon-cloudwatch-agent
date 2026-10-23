// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"debug/elf"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// splitLayouts are libraries whose executable segment does NOT start at file
// offset 0. The processor used to refuse every frame of such a file, because it
// took a non-zero memory_start or file_offset for a load bias.
var splitLayouts = []struct {
	name string
	fx   elfFixture
}{
	{
		// glibc 2.34 libc.so.6 on aarch64: R E LOAD at offset 0x30000, VA
		// 0x30000 (readelf -lW).
		name: "glibc 2.34 aarch64 layout",
		fx: elfFixture{
			machine: elf.EM_AARCH64, textOff: 0x30000, textVaddr: 0x30000, textSize: 0x11000,
			buildID: []byte("glibc-2.34-like"),
			funcs: []fixtureFunc{
				{name: "hot_leaf", off: 0x400, size: 0x40},
				{name: "second_fn", off: 0x800, size: 0x80},
			},
		},
	},
	{
		// lld's default layout: a read-only segment for the headers, then the
		// R E segment at offset 0x5a0 and VA 0x15a0. Its VA is not its offset,
		// and the kernel maps it from offset 0, the page that holds 0x5a0.
		name: "lld layout, segment vaddr differs from its offset",
		fx: elfFixture{
			machine: elf.EM_X86_64, textOff: 0x5a0, textVaddr: 0x15a0, textSize: 0x1000,
			buildID: []byte("lld-like"),
			funcs: []fixtureFunc{
				{name: "hot_leaf", off: 0x60, size: 0x40},
				{name: "second_fn", off: 0x200, size: 0x80},
			},
		},
	},
}

// TestLibraryWhoseTextIsNotAtOffsetZero proves the address rule for libraries
// whose executable segment does not start at file offset 0 (recent glibc, and
// lld's default layout without --no-rosegment). The mapping carries a GNU build
// ID and an htlhash, so the frame is proved by the GNU build ID and is not
// counted as resolved by htlhash.
//
// Each fixture's program headers are checked first, so the test cannot pass by
// accident on a layout that starts at offset 0. The frame is then sent in both
// conventions a sender may use: addresses in the file's ELF virtual-address
// space, and runtime addresses (memory range and address both moved by a load
// bias). Both must get the same name, which proves the processor computes the
// ELF address from the mapping rather than using the frame address as is.
func TestLibraryWhoseTextIsNotAtOffsetZero(t *testing.T) {
	for _, tc := range splitLayouts {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "libsplit.so")
			writeELFFixture(t, path, tc.fx)

			ef, err := elf.Open(path)
			require.NoError(t, err)
			loads := execLoadSegments(ef)
			require.NoError(t, ef.Close())
			require.Len(t, loads, 1)
			require.NotZero(t, loads[0].off, "the R E segment must not start at offset 0")

			mapsOffset, length := kernelMapping(tc.fx)
			m := senderMapping(t, path, mapsOffset, length)
			m.filename = path // found by its path; finding files is tested elsewhere
			require.False(t, m.start == 0 && m.offset == 0,
				"the mapping has a non-zero memory_start or file_offset here, which the old guard refused")
			addr := tc.fx.addr(t, "hot_leaf", 4)

			const base = 0x7f1234500000
			for _, conv := range []struct {
				name string
				m    fxMapping
				addr uint64
			}{
				{"ELF virtual addresses", m, addr},
				{"runtime addresses", runtimeView(m, base), runtimeAddr(m, base, addr)},
			} {
				pd := buildPayload([]fxMapping{conv.m}, []fxLocation{{mapping: 0, addr: conv.addr}}, []fxResource{{locs: []int{0}}})
				s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
				_, err := s.processProfiles(context.Background(), pd)
				require.NoError(t, err, conv.name)
				require.Equal(t, "hot_leaf", locationName(pd, 0), conv.name)
				require.Equal(t, uint64(0), s.mappingBiasUnexpected.Load(), conv.name)
				require.Zero(t, s.framesResolvedByHtlhash.Load(), conv.name)
			}
		})
	}
}

// TestAddressOutsideMappingIsRefused proves the range check. The frame address
// is inside a real function of the file, but outside the mapping that the frame
// names. Placing it in the file would be a guess, and a guess is a wrong name,
// so the frame is refused and counted. The same address with the whole mapping
// resolves, so the refusal is the range check and not a missing symbol.
func TestAddressOutsideMappingIsRefused(t *testing.T) {
	fx := splitLayouts[0].fx
	path := filepath.Join(t.TempDir(), "libsplit.so")
	writeELFFixture(t, path, fx)
	mapsOffset, length := kernelMapping(fx)
	full := senderMapping(t, path, mapsOffset, length)
	full.filename = path
	addr := fx.addr(t, "second_fn", 8)

	short := full
	short.limit = full.start + 0x500 // ends before second_fn at 0x800
	require.GreaterOrEqual(t, addr, short.limit)

	for _, tc := range []struct {
		name string
		m    fxMapping
		want string
	}{
		{"address outside the mapping is refused", short, ""},
		{"same address inside the whole mapping resolves", full, "second_fn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pd := buildPayload([]fxMapping{tc.m}, []fxLocation{{mapping: 0, addr: addr}}, []fxResource{{locs: []int{0}}})
			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
			_, err := s.processProfiles(context.Background(), pd)
			require.NoError(t, err)
			require.Equal(t, tc.want, locationName(pd, 0))
			if tc.want == "" {
				require.Equal(t, uint64(1), s.mappingBiasUnexpected.Load())
				require.Equal(t, uint64(0), s.candidateWalks.Load(), "a refused address costs no file access")
			}
		})
	}
}

// TestMappingOffsetInNoExecutableSegmentIsRefused covers the other way an
// address cannot be placed: the mapping's file offset is in no executable
// segment of the file that proved its identity, so there is no virtual address
// to compute from. The frame is refused, not guessed.
func TestMappingOffsetInNoExecutableSegmentIsRefused(t *testing.T) {
	fx := splitLayouts[0].fx
	path := filepath.Join(t.TempDir(), "libsplit.so")
	writeELFFixture(t, path, fx)
	mapsOffset, length := kernelMapping(fx)
	m := senderMapping(t, path, mapsOffset, length)
	m.filename = path
	m.offset = 0 // the read-only headers segment, not the R E one
	addr := fx.addr(t, "hot_leaf", 4)

	pd := buildPayload([]fxMapping{m}, []fxLocation{{mapping: 0, addr: addr}}, []fxResource{{locs: []int{0}}})
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Empty(t, locationName(pd, 0))
	require.Equal(t, uint64(1), s.mappingBiasUnexpected.Load())
}

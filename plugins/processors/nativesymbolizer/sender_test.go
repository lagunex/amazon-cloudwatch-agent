// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.uber.org/zap/zaptest"
)

// TestAnySenderShape builds a payload the way a sender other than an eBPF
// profiler may, for example a pprof profile converted to OTLP: no frame types
// at all, the mapping's absolute path, a GNU build ID and no htlhash, runtime
// addresses (the mapping loaded at a high base), and no process attributes.
// The native frame must be named. A kernel frame that is not named, and a frame
// the sender already named, must be left as they are and not counted.
func TestAnySenderShape(t *testing.T) {
	bin, buildID, va := buildTestBinaryPIE(t)
	st, err := newSymbolTable(bin)
	require.NoError(t, err)
	require.NotEmpty(t, st.loads)
	text := st.loads[0]
	const base = 0x55d0c0de0000
	mapStart := base + (text.vaddr &^ pageMask)
	runtime := mapStart + (va - (text.vaddr &^ pageMask))

	pd := pprofile.NewProfiles()
	dict := pd.Dictionary()
	strTab := dict.StringTable()
	strTab.Append("")
	str := func(s string) int32 {
		strTab.Append(s)
		return i32(strTab.Len() - 1)
	}
	attrTab := dict.AttributeTable()
	attrTab.AppendEmpty()
	attr := func(key, value string) int32 {
		kv := attrTab.AppendEmpty()
		kv.SetKeyStrindex(str(key))
		kv.Value().SetStr(value)
		return i32(attrTab.Len() - 1)
	}
	dict.MappingTable().AppendEmpty()
	m := dict.MappingTable().AppendEmpty()
	m.SetFilenameStrindex(str(bin))
	m.SetMemoryStart(mapStart)
	m.SetMemoryLimit(mapStart + text.filesz + (text.vaddr - text.vaddr&^pageMask))
	m.SetFileOffset(text.off &^ pageMask)
	m.AttributeIndices().Append(attr(attrMappingBuildIDGnu, buildID))

	locTab := dict.LocationTable()
	locTab.AppendEmpty()
	native := locTab.AppendEmpty() // 1: no frame type, no lines
	native.SetMappingIndex(1)
	native.SetAddress(runtime)
	kernel := locTab.AppendEmpty() // 2: a kernel frame the sender left unnamed
	kernel.SetAddress(0xffffffff81000000)
	kernel.AttributeIndices().Append(attr(attrFrameType, "kernel"))
	dict.FunctionTable().AppendEmpty()
	fn := dict.FunctionTable().AppendEmpty()
	fn.SetNameStrindex(str("main.main"))
	named := locTab.AppendEmpty() // 3: a frame the sender named
	named.SetAddress(0x401000)
	named.Lines().AppendEmpty().SetFunctionIndex(1)

	dict.StackTable().AppendEmpty()
	stack := dict.StackTable().AppendEmpty()
	stack.LocationIndices().Append(1, 2, 3)
	prof := pd.ResourceProfiles().AppendEmpty().ScopeProfiles().AppendEmpty().Profiles().AppendEmpty()
	prof.Samples().AppendEmpty().SetStackIndex(1)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, Demangle: true}, zaptest.NewLogger(t))
	_, err = s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	name := func(loc pprofile.Location) string {
		if loc.Lines().Len() == 0 {
			return ""
		}
		f := dict.FunctionTable().At(int(loc.Lines().At(0).FunctionIndex()))
		return strTab.At(int(f.NameStrindex()))
	}
	require.Equal(t, "hot_leaf", name(locTab.At(1)), "the native frame is named")
	require.Empty(t, name(locTab.At(2)), "a kernel frame is not ours to name")
	require.Equal(t, "main.main", name(locTab.At(3)), "a named frame is left as it is")
	require.Equal(t, 1, locTab.At(3).Lines().Len())
	require.Equal(t, uint64(1), s.framesSeen.Load(), "only the native frame is counted")
	require.Equal(t, uint64(1), s.framesResolved.Load())
	require.Zero(t, s.framesResolvedByHtlhash.Load())
}

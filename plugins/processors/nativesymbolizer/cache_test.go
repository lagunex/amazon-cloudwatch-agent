// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// sharedLibPayload builds the payload of two processes that both map
// libshared.so from their own roots: one mapping in the dictionary, as a
// sender that deduplicates mappings across processes sends it, and one sampled
// location per process.
func sharedLibPayload(t *testing.T, fx elfFixture, m fxMapping, pids ...int64) pprofile.Profiles {
	t.Helper()
	locs := []fxLocation{
		{mapping: 0, addr: fx.addr(t, "hot_leaf", 4)},
		{mapping: 0, addr: fx.addr(t, "second_fn", 4)},
	}
	var res []fxResource
	for i, pid := range pids {
		res = append(res, fxResource{pid: pid, exe: "/usr/bin/app", locs: []int{i % len(locs)}})
	}
	return buildPayload([]fxMapping{m}, locs, res)
}

// TestTwoProcessesShareOneParsedTable is the cross-PID dedup test. Two
// processes map the same library, each from its own root. The table is parsed
// once and cached once, by the content of the file, and the second process
// reads no /proc file at all. A second pass reads nothing either: it still
// names both frames after both maps files are gone, so maps is read only while
// the library is unresolved.
func TestTwoProcessesShareOneParsedTable(t *testing.T) {
	prefix := t.TempDir()
	fx := classicLayout([]byte("libshared-build-id"))
	var m fxMapping
	var procs []*fakeProc
	for i, pid := range []int64{101, 202} {
		proc := newFakeProc(t, prefix, pid)
		lib := proc.inRoot("/usr/lib64/libshared.so")
		writeELFFixture(t, lib, fx)
		off, length := kernelMapping(fx)
		m = senderMapping(t, lib, off, length)
		start := uint64(0x7f0000000000) + uint64(i)<<32
		end := proc.mapExec(start, off, length, "/usr/lib64/libshared.so")
		proc.writeMaps()
		proc.linkMapFile(start, end, lib)
		procs = append(procs, proc)
	}

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
	pd := sharedLibPayload(t, fx, m, 101, 202)
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)
	require.Equal(t, "hot_leaf", locationName(pd, 0))
	require.Equal(t, "second_fn", locationName(pd, 1))
	require.Equal(t, uint64(1), s.symbolTablesParsed.Load(), "one parse for both processes")
	require.Equal(t, 1, s.cache.len(), "one cache entry for both processes")
	require.Equal(t, uint64(1), s.procMapsReads.Load(), "the second process reuses the table and reads no maps")

	for _, proc := range procs {
		require.NoError(t, os.Remove(filepath.Join(proc.dir, "maps")))
		require.NoError(t, os.RemoveAll(filepath.Join(proc.dir, "map_files")))
	}
	pd = sharedLibPayload(t, fx, m, 101, 202)
	_, err = s.processProfiles(context.Background(), pd)
	require.NoError(t, err)
	require.Equal(t, "hot_leaf", locationName(pd, 0))
	require.Equal(t, "second_fn", locationName(pd, 1))
	require.Equal(t, uint64(1), s.symbolTablesParsed.Load())
	require.Equal(t, uint64(1), s.procMapsReads.Load(), "a resolved file costs no maps read")
}

// TestOneMappingIsResolvedOncePerPass covers a hot binary: many locations in
// one mapping. Before, every location walked the candidate files (a stat per
// candidate and, for a cache miss, a parse). Now the mapping is resolved once
// and its table serves every location. With require_build_id_match: false
// there is no content key to cache by, so there the per-pass memo alone keeps
// it to one walk.
func TestOneMappingIsResolvedOncePerPass(t *testing.T) {
	bin, buildID, _ := buildTestBinary(t)
	st, err := newSymbolTable(bin)
	require.NoError(t, err)

	var locs []fxLocation
	var sampled []int
	for i, r := range st.ranges {
		if i == 50 {
			break
		}
		locs = append(locs, fxLocation{mapping: 0, addr: r.start})
		sampled = append(sampled, len(locs)-1)
	}
	require.Greater(t, len(locs), 1)

	for _, requireMatch := range []bool{true, false} {
		t.Run(fmt.Sprintf("require_build_id_match %v", requireMatch), func(t *testing.T) {
			pd := buildPayload([]fxMapping{{filename: bin, gnu: buildID}}, locs, []fxResource{{locs: sampled}})
			s := newSymbolizer(&Config{RequireBuildIDMatch: requireMatch, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
			_, err := s.processProfiles(context.Background(), pd)
			require.NoError(t, err)
			require.Equal(t, uint64(len(locs)), s.framesResolved.Load())
			require.Equal(t, uint64(1), s.candidateWalks.Load(), "one walk for the whole mapping")
		})
	}
}

// TestUnresolvedMappingIsNotWalkedAgainForAMinute covers a file that is gone for
// good, such as the vDSO, which every process maps and which is never a file.
// After one walk finds nothing, the mapping is not walked again in that process
// for missRetryAfter, so it costs no /proc/<pid>/maps read on every pass. After
// that it is tried again.
func TestUnresolvedMappingIsNotWalkedAgainForAMinute(t *testing.T) {
	prefix := t.TempDir()
	proc := newFakeProc(t, prefix, fakePID)
	proc.mapLine("7ffd1c000000-7ffd1c002000 r-xp 00000000 00:00 0                          [vdso]")
	proc.writeMaps()
	m := fxMapping{filename: "linux-vdso.1.so", gnu: "aabbccdd", htlhash: "00112233445566778899aabbccddeeff", start: 0, limit: 0x2000}
	payload := func() pprofile.Profiles {
		return buildPayload([]fxMapping{m}, []fxLocation{{mapping: 0, addr: 0x100}}, []fxResource{{pid: fakePID, exe: "/usr/bin/app", locs: []int{0}}})
	}

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
	now := time.Now()
	s.shared.misses.now = func() time.Time { return now }
	for pass := 0; pass < 3; pass++ {
		_, err := s.processProfiles(context.Background(), payload())
		require.NoError(t, err)
	}
	require.Equal(t, uint64(3), s.framesNoCandidate.Load(), "every pass still counts the frame")
	require.Equal(t, uint64(1), s.candidateWalks.Load())
	require.Equal(t, uint64(1), s.procMapsReads.Load())

	now = now.Add(missRetryAfter)
	_, err := s.processProfiles(context.Background(), payload())
	require.NoError(t, err)
	require.Equal(t, uint64(2), s.candidateWalks.Load(), "tried again after missRetryAfter")
	require.Equal(t, uint64(2), s.procMapsReads.Load())
}

// TestMissInAnExitedProcessDoesNotHideALiveOne covers two processes that map
// the same library, where the first process of the report has exited. The
// sender deduplicates locations across processes, so one location is sampled
// by both. The walk for the exited process finds nothing, and that
// miss is remembered for that process only: the live process is still walked,
// and the shared location gets its name.
func TestMissInAnExitedProcessDoesNotHideALiveOne(t *testing.T) {
	prefix := t.TempDir()
	fx := classicLayout([]byte("libshared-build-id"))
	live := newFakeProc(t, prefix, 202)
	lib := live.inRoot("/usr/lib64/libshared.so")
	writeELFFixture(t, lib, fx)
	off, length := kernelMapping(fx)
	m := senderMapping(t, lib, off, length)
	start := uint64(0x7f0000000000)
	end := live.mapExec(start, off, length, "/usr/lib64/libshared.so")
	live.writeMaps()
	live.linkMapFile(start, end, lib)

	// pid 101 has exited, so it has no /proc entry. It comes first.
	pd := buildPayload(
		[]fxMapping{m},
		[]fxLocation{{mapping: 0, addr: fx.addr(t, "hot_leaf", 4)}},
		[]fxResource{{pid: 101, exe: "/usr/bin/app", locs: []int{0}}, {pid: 202, exe: "/usr/bin/app", locs: []int{0}}},
	)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Equal(t, "hot_leaf", locationName(pd, 0), "the miss in pid 101 must not hide pid 202")
	require.Equal(t, uint64(2), s.candidateWalks.Load(), "both processes are walked")
	require.Equal(t, uint64(1), s.framesNoCandidate.Load(), "pid 101 finds nothing")
	require.Equal(t, uint64(1), s.framesResolved.Load())
}

// TestMissMemoIsBounded proves the bound of the miss memo. Its keys carry the
// process, and a process that has exited never asks for its key again, so
// without the bound the memo grows for as long as processes come and go. When
// the memo is full, it drops the expired entries first, and it starts over only
// when none has expired.
func TestMissMemoIsBounded(t *testing.T) {
	size := func(m *missMemo) int {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.entries)
	}
	now := time.Now()
	clock := func() time.Time { return now }

	memo := newMissMemo(time.Minute, 4, clock)
	for pid := 1; pid <= 10; pid++ {
		memo.put(missKey{identity: "vdso", procDir: fmt.Sprintf("/proc/%d", pid)}, resolveNoCandidate)
	}
	require.LessOrEqual(t, size(memo), 4, "ten exited processes leave at most four entries")

	memo = newMissMemo(time.Minute, 4, clock)
	for i := 0; i < 3; i++ {
		memo.put(missKey{identity: fmt.Sprint("old-", i)}, resolveNoCandidate)
	}
	now = now.Add(2 * time.Minute) // the three old entries expire
	live := missKey{identity: "live"}
	memo.put(live, resolveBuildIDMismatch)                  // 4 entries: the memo is not full yet
	memo.put(missKey{identity: "next"}, resolveNoCandidate) // full: the three expired entries go
	require.Equal(t, 2, size(memo))
	outcome, ok := memo.get(live)
	require.True(t, ok, "an entry that has not expired stays")
	require.Equal(t, resolveBuildIDMismatch, outcome)
}

// TestPipelinesShareOneParsedTable covers the two pipelines of the IP config:
// two processor instances with one shared state parse a file once between
// them.
func TestPipelinesShareOneParsedTable(t *testing.T) {
	bin, buildID, addr := buildTestBinary(t)
	cfg := &Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}
	shared := newSharedState(cfg)
	first := newSymbolizerShared(cfg, zaptest.NewLogger(t), shared)
	second := newSymbolizerShared(cfg, zaptest.NewLogger(t), shared)

	for _, s := range []*symbolizer{first, second} {
		pd := makeProfiles(bin, buildID, addr)
		_, err := s.processProfiles(context.Background(), pd)
		require.NoError(t, err)
		name, ok := firstLocationName(t, pd)
		require.True(t, ok)
		require.Equal(t, "hot_leaf", name)
	}
	require.Equal(t, uint64(1), first.symbolTablesParsed.Load())
	require.Equal(t, uint64(0), second.symbolTablesParsed.Load(), "the second pipeline finds the table in the shared cache")
}

// TestConcurrentPassesShareTheCache runs passes of two pipelines' instances at
// the same time over one shared state, and checks that every pass names every
// frame. It is an end-to-end smoke test: the race detector cannot run in this
// package's build (bmg.json sets CGO_ENABLED=0), and TestCacheAndMemoAreSafeForConcurrentUse
// is the test that catches a missing lock.
func TestConcurrentPassesShareTheCache(t *testing.T) {
	binA, idA, addrA := buildTestBinary(t)
	binB, idB, addrB := buildTestBinary(t)
	cfg := &Config{RequireBuildIDMatch: true, MaxCachedBinaries: 1}
	shared := newSharedState(cfg) // one entry: the two files keep evicting each other
	instances := []*symbolizer{newSymbolizerShared(cfg, zap.NewNop(), shared), newSymbolizerShared(cfg, zap.NewNop(), shared)}

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			s := instances[g%2]
			for i := 0; i < 20; i++ {
				bin, id, addr := binA, idA, addrA
				if (g+i)%2 == 1 {
					bin, id, addr = binB, idB, addrB
				}
				pd := makeProfiles(bin, id, addr)
				if _, err := s.processProfiles(context.Background(), pd); err != nil {
					errs <- err.Error()
					return
				}
				if pd.Dictionary().LocationTable().At(0).Lines().Len() != 1 {
					errs <- "a frame was not named"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	require.Equal(t, uint64(160), instances[0].framesResolved.Load()+instances[1].framesResolved.Load())
}

// TestCacheAndMemoAreSafeForConcurrentUse hammers the shared cache and the miss
// memo from several goroutines, as the processor instances of two pipelines
// use them. Without their locks, the Go runtime stops the test binary with
// "concurrent map writes" or "concurrent map read and map write". The byte
// accounting must also still be exact afterwards.
func TestCacheAndMemoAreSafeForConcurrentUse(t *testing.T) {
	cache := newResolverCacheBytes(4, 1<<20)
	memo := newMissMemo(missRetryAfter, 64, time.Now)
	tables := []*symbolTable{syntheticTable(10), syntheticTable(200), syntheticTable(3000)}
	keys := make([]string, 7)
	for i := range keys {
		keys[i] = fmt.Sprintf("\x00key-%d", i)
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				key := keys[(g+i)%len(keys)]
				cache.store(key, cacheEntry{table: tables[i%len(tables)]})
				cache.lookupContent(key)
				cache.lookupFile(key, fileFingerprint{ok: true, size: int64(i % 3)})
				memo.put(missKey{identity: key}, resolveNoCandidate)
				memo.get(missKey{identity: key})
			}
		}(g)
	}
	wg.Wait()

	cache.mu.Lock()
	defer cache.mu.Unlock()
	require.LessOrEqual(t, len(cache.entries), 4)
	require.Len(t, cache.order, len(cache.entries))
	var sum int64
	for _, e := range cache.entries {
		sum += e.size
	}
	require.Equal(t, sum, cache.bytes, "the byte accounting stays exact under concurrent use")
}

// syntheticTable returns a finalized table whose size is driven by one long name.
func syntheticTable(nameLen int) *symbolTable {
	name := make([]byte, nameLen)
	for i := range name {
		name[i] = 'f'
	}
	st := &symbolTable{ranges: []funcRange{{start: 0x1000, size: 0x10, name: string(name)}}}
	st.finalize()
	return st
}

// TestCacheIsBoundedByBytes proves the byte bound: the least recently used
// table is evicted when the estimated bytes pass max_cached_bytes, even with
// entry slots to spare, and the accounting of bytes stays exact.
func TestCacheIsBoundedByBytes(t *testing.T) {
	a, b, c := syntheticTable(4000), syntheticTable(4000), syntheticTable(4000)
	entry := func(key string, st *symbolTable) int64 { return cacheEntryOverhead + int64(len(key)) + st.size }

	cache := newResolverCacheBytes(8, entry("a", a)+entry("b", b)+100)
	cache.store("a", cacheEntry{table: a})
	cache.store("b", cacheEntry{table: b})
	_, ok := cache.lookupContent("a") // a is now the most recently used
	require.True(t, ok)
	cache.store("c", cacheEntry{table: c})

	entries, bytes := cache.stats()
	require.Equal(t, 2, entries, "8 entry slots, but only two tables fit the byte bound")
	require.Equal(t, entry("a", a)+entry("c", c), bytes)
	_, ok = cache.lookupContent("b")
	require.False(t, ok, "b was the least recently used")

	// One table larger than the whole bound is kept while it is the newest
	// entry, and storing it evicts every other entry. The next store evicts it,
	// because it is then the oldest entry and the bound is still passed. So a
	// bound below one table makes that table parse again on every pass.
	huge := syntheticTable(int(cache.maxBytes) * 2)
	cache.store("huge", cacheEntry{table: huge})
	entries, bytes = cache.stats()
	require.Equal(t, 1, entries)
	require.Equal(t, entry("huge", huge), bytes)
	cache.store("a", cacheEntry{table: a})
	_, ok = cache.lookupContent("huge")
	require.False(t, ok, "the next store evicts the oversized table")
	entries, bytes = cache.stats()
	require.Equal(t, 1, entries)
	require.Equal(t, entry("a", a), bytes)
}

// panicOnBuild makes every symbol-table build panic until the test ends.
func panicOnBuild(t *testing.T) {
	t.Helper()
	buildSymbolTable = func(*elf.File) (*symbolTable, error) { panic("crafted ELF") }
	t.Cleanup(func() { buildSymbolTable = parseSymbolTable })
}

// TestSymbolTablePanicIsRecoveredAndCached proves that a panic while reading
// a file's symbols does not escape, is counted, and caches that file version as
// failed: it is not read again, even after the parser works again. A new file
// version (another build) is read normally.
func TestSymbolTablePanicIsRecoveredAndCached(t *testing.T) {
	bin, buildID, addr := buildTestBinary(t)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	run := func(bin, buildID string, addr uint64) (string, bool) {
		pd := makeProfiles(bin, buildID, addr)
		_, err := s.processProfiles(context.Background(), pd)
		require.NoError(t, err)
		return firstLocationName(t, pd)
	}

	// Each pass starts past missRetryAfter, so that the miss memo does not
	// answer for the cache: what is tested is that the failure is cached.
	now := time.Now()
	s.shared.misses.now = func() time.Time { now = now.Add(2 * missRetryAfter); return now }

	panicOnBuild(t)
	require.NotPanics(t, func() { _, _ = run(bin, buildID, addr) })
	require.Equal(t, uint64(1), s.symbolTablePanics.Load())
	require.Equal(t, uint64(1), s.framesNoCandidate.Load())

	_, ok := run(bin, buildID, addr)
	require.False(t, ok)
	require.Equal(t, uint64(1), s.symbolTablePanics.Load(), "the failed file version is not read again")
	require.Equal(t, uint64(1), s.candidateWalks.Load(), "the cached failure answers without a walk")

	buildSymbolTable = parseSymbolTable
	_, ok = run(bin, buildID, addr)
	require.False(t, ok, "the failure is cached for this file version")

	next, nextID, nextAddr := buildTestBinary(t)
	require.NotEqual(t, buildID, nextID)
	name, ok := run(next, nextID, nextAddr)
	require.True(t, ok, "another file version is read")
	require.Equal(t, "hot_leaf", name)
}

// TestPanicBeforeTheIdentityIsProvenLatchesOnlyThatFile covers a panic in a
// wrong file, before it has proved the mapping's identity: here the ELF header
// read panics. The first candidate (the file under the root) holds another
// build, and the second (the plain path) is missing at first. That panic says
// nothing about the sampled content, so only that file version is cached as
// failed. After missRetryAfter the walk runs again, and it does not read the
// panicking file again. When the right file is back at the second candidate,
// the frame gets its name.
func TestPanicBeforeTheIdentityIsProvenLatchesOnlyThatFile(t *testing.T) {
	requireOpenat2(t)
	bin, buildID, addr := buildTestBinary(t)
	other, otherID, _ := buildTestBinary(t)
	require.NotEqual(t, buildID, otherID)
	otherData, err := os.ReadFile(other)
	require.NoError(t, err)

	root := t.TempDir()
	wrong := filepath.Join(root, bin) // the first candidate: root + the mapping filename
	require.NoError(t, os.MkdirAll(filepath.Dir(wrong), 0o755))
	require.NoError(t, os.WriteFile(wrong, otherData, 0o600)) //nolint:gosec // G703: test-controlled temp file
	wrongInfo, err := os.Stat(wrong)
	require.NoError(t, err)
	newELFFile = func(r io.ReaderAt) (*elf.File, error) {
		if f, ok := r.(*os.File); ok {
			if fi, err := f.Stat(); err == nil && os.SameFile(fi, wrongInfo) {
				panic("crafted ELF header")
			}
		}
		return elf.NewFile(r)
	}
	t.Cleanup(func() { newELFFile = elf.NewFile })
	hidden := bin + ".hidden"
	require.NoError(t, os.Rename(bin, hidden))

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: root}, zaptest.NewLogger(t))
	now := time.Now()
	s.shared.misses.now = func() time.Time { return now }
	run := func() (string, bool) {
		pd := makeProfiles(bin, buildID, addr)
		_, err := s.processProfiles(context.Background(), pd)
		require.NoError(t, err)
		return firstLocationName(t, pd)
	}

	require.NotPanics(t, func() { _, _ = run() })
	require.Equal(t, uint64(1), s.symbolTablePanics.Load())
	require.Equal(t, uint64(1), s.framesNoCandidate.Load())
	require.Equal(t, 1, s.cache.len(), "only the panicking file version is cached, not the sampled content")

	now = now.Add(missRetryAfter)
	_, ok := run()
	require.False(t, ok)
	require.Equal(t, uint64(2), s.candidateWalks.Load(), "the walk runs again after missRetryAfter")
	require.Equal(t, uint64(1), s.symbolTablePanics.Load(), "the panicking file version is not read again")

	require.NoError(t, os.Rename(hidden, bin))
	now = now.Add(missRetryAfter)
	name, ok := run()
	require.True(t, ok, "the sampled content is not cached as failed")
	require.Equal(t, "hot_leaf", name)
	require.Equal(t, uint64(1), s.symbolTablePanics.Load())
}

// TestGetLatchesAPanickingFile is the same rule for the path-keyed get, which
// require_build_id_match: false uses: a panicking file version is latched like
// a stripped one, and a redeploy at the same path is read again.
func TestGetLatchesAPanickingFile(t *testing.T) {
	bin, _, _ := buildTestBinary(t)
	c := newResolverCache(8)

	panicOnBuild(t)
	var st *symbolTable
	require.NotPanics(t, func() { st, _ = c.get(bin) })
	require.Nil(t, st)
	require.Equal(t, 1, c.len(), "the panicking file version is latched")

	buildSymbolTable = parseSymbolTable
	st, cached := c.get(bin)
	require.Nil(t, st)
	require.True(t, cached, "same file version, same verdict")

	// A redeploy: another build lands at the same path. Sleep past the
	// filesystem's mtime granularity, as TestRedeployInvalidatesNegativeCache does.
	time.Sleep(10 * time.Millisecond)
	other, _, _ := buildTestBinary(t)
	data, err := os.ReadFile(other)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bin, data, 0o600)) //nolint:gosec // G703: test-controlled temp file
	st, _ = c.get(bin)
	require.NotNil(t, st, "a new file version at the path is read again")
}

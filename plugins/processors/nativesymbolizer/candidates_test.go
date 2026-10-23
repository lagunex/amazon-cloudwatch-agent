// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.uber.org/zap/zaptest"
)

const fakePID = 4242

// libFixture writes the classic-layout library fixture (text at offset 0) at
// path and returns the mapping a sender would report for it.
func libFixture(t *testing.T, path string, buildID []byte) (elfFixture, fxMapping) {
	t.Helper()
	fx := classicLayout(buildID)
	writeELFFixture(t, path, fx)
	off, length := kernelMapping(fx)
	return fx, senderMapping(t, path, off, length)
}

// TestSharedObjectFoundThroughProcMaps is the libc case. The sender sends only
// the basename of a shared object, and the library lives at /usr/lib64 in the
// process's root, where neither the root + basename nor the bare basename
// candidate looks. The full path is in /proc/<pid>/maps, and
// /proc/<pid>/map_files/<range> is the exact inode.
func TestSharedObjectFoundThroughProcMaps(t *testing.T) {
	requireOpenat2(t)
	for _, tc := range []struct {
		name     string
		mapFiles bool
		replaced bool // the path now holds another build of the library
		want     string
	}{
		{name: "through map_files", mapFiles: true, want: "hot_leaf"},
		{name: "through the full path in the process root", mapFiles: false, want: "hot_leaf"},
		{name: "a library replaced on disk still resolves through map_files", mapFiles: true, replaced: true, want: "hot_leaf"},
		{name: "a different library at the maps path is refused", mapFiles: false, replaced: true, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := t.TempDir()
			proc := newFakeProc(t, prefix, fakePID)
			libPath := proc.inRoot("/usr/lib64/libfixture.so")
			fx, m := libFixture(t, libPath, []byte("libfixture-build-id-v1"))
			mapped := libPath
			if tc.replaced {
				// A glibc update while the process runs: the process keeps the old
				// inode (map_files reaches it, here a copy outside the root), and
				// the path holds the new build. The mapping still names v1.
				mapped = filepath.Join(t.TempDir(), "libfixture.so (deleted inode)")
				writeELFFixture(t, mapped, classicLayout([]byte("libfixture-build-id-v1")))
				writeELFFixture(t, libPath, classicLayout([]byte("libfixture-build-id-v2")))
			}
			start := uint64(0x7f3a1c000000)
			proc.mapLine("55d1c0000000-55d1c0001000 r-xp 00000000 103:01 900 /usr/bin/app")
			end := proc.mapExec(start, m.offset, m.limit-m.start, "/usr/lib64/libfixture.so")
			proc.mapLine("7ffd1c000000-7ffd1c002000 r-xp 00000000 00:00 0                          [vdso]")
			proc.writeMaps()
			if tc.mapFiles {
				proc.linkMapFile(start, end, mapped)
			}
			require.Equal(t, "libfixture.so", m.filename, "the sender sends only the basename")

			pd := buildPayload(
				[]fxMapping{m},
				[]fxLocation{{mapping: 0, addr: fx.addr(t, "hot_leaf", 4)}},
				[]fxResource{{pid: fakePID, exe: "/usr/bin/app", locs: []int{0}}},
			)
			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
			_, err := s.processProfiles(context.Background(), pd)
			require.NoError(t, err)

			require.Equal(t, tc.want, locationName(pd, 0))
			require.Equal(t, uint64(1), s.procMapsReads.Load())
			if tc.want == "" {
				require.Equal(t, uint64(1), s.buildIDMismatch.Load(), "the identity check holds on the full path from maps too")
			} else {
				require.Equal(t, uint64(1), s.framesResolved.Load())
			}
		})
	}
}

// TestMainExecutableFoundThroughProcExe covers a binary that was redeployed
// while its process runs: the path now holds the new build, and only
// /proc/<pid>/exe still reaches the inode that the process runs. Before, the
// processor found only the new build and refused it.
func TestMainExecutableFoundThroughProcExe(t *testing.T) {
	prefix := t.TempDir()
	proc := newFakeProc(t, prefix, fakePID)

	running := filepath.Join(t.TempDir(), "app (the inode the process runs)")
	fx := classicLayout([]byte("app-build-1"))
	writeELFFixture(t, running, fx)
	off, length := kernelMapping(fx)
	m := senderMapping(t, running, off, length)
	m.filename = "app"

	// The redeployed build at the executable path in the root.
	writeELFFixture(t, proc.inRoot("/opt/svc/bin/app"), classicLayout([]byte("app-build-2")))
	proc.linkExe(running)

	pd := buildPayload(
		[]fxMapping{m},
		[]fxLocation{{mapping: 0, addr: fx.addr(t, "second_fn", 0x10)}},
		[]fxResource{{pid: fakePID, exe: "/opt/svc/bin/app", locs: []int{0}}},
	)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Equal(t, "second_fn", locationName(pd, 0))
	require.Equal(t, uint64(0), s.buildIDMismatch.Load(), "the frame resolved, so no mismatch is counted")
	require.Equal(t, uint64(0), s.procMapsReads.Load(), "the main executable needs no maps read")

	// /proc/<pid>/exe comes first, so a walk opens the inode that the process
	// runs before it opens the redeployed build at the path.
	cands := s.candidates(&passState{maps: map[string][]mapsLine{}}, mappingInfo{filename: m.filename}, s.processContext(pd.ResourceProfiles().At(0)))
	require.NotEmpty(t, cands)
	require.Equal(t, filepath.Join(proc.dir, "exe"), cands[0].path, "/proc/<pid>/exe is tried first")
}

// otherBuild is another build of the classic-layout fixture: the same segment
// layout, but other functions at the sampled offsets. A file that is wrongly
// accepted then writes a visibly wrong name, not a lucky right one.
func otherBuild(buildID []byte) elfFixture {
	fx := classicLayout(buildID)
	fx.funcs = []fixtureFunc{
		{name: "other_build_fn", off: 0x1000, size: 0x40},
		{name: "other_build_fn2", off: 0x1800, size: 0x80},
	}
	return fx
}

// TestExactInodeLinkToAnotherBuildIsRefused covers /proc/<pid>/map_files/<range>
// and /proc/<pid>/exe when they reach another build. These links show the
// image that a pid runs now. After a re-exec, or after the pid is used again,
// that is not the file the sender sampled. So a file reached through them
// must prove its identity like any candidate: by its GNU build ID, or by its
// htlhash when the mapping has no GNU build ID. Nothing is at the
// path in the process root, so the link is the only file found. The two
// controls show that the same setup names the frame when the link reaches the
// sampled build.
func TestExactInodeLinkToAnotherBuildIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		link      string // "map_files" or "exe"
		gnu       bool   // the builds carry a GNU build ID; false: an htlhash only
		sameBuild bool   // control: the link reaches the sampled build
	}{
		{name: "map_files reaches another build, GNU build ID", link: "map_files", gnu: true},
		{name: "exe reaches another build, GNU build ID", link: "exe", gnu: true},
		{name: "map_files reaches another build, htlhash only", link: "map_files"},
		{name: "exe reaches another build, htlhash only", link: "exe"},
		{name: "control: map_files reaches the sampled build, htlhash only", link: "map_files", sameBuild: true},
		{name: "control: exe reaches the sampled build, htlhash only", link: "exe", sameBuild: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sampledID, otherID []byte
			if tc.gnu {
				sampledID, otherID = []byte("libfixture-build-id-v1"), []byte("libfixture-build-id-v2")
			}
			base, exe := "libfixture.so", "/usr/bin/app"
			if tc.link == "exe" {
				base, exe = "app", "/opt/svc/bin/app"
			}
			prefix := t.TempDir()
			proc := newFakeProc(t, prefix, fakePID)
			sampled := filepath.Join(t.TempDir(), base)
			fx := classicLayout(sampledID)
			writeELFFixture(t, sampled, fx)
			off, length := kernelMapping(fx)
			m := senderMapping(t, sampled, off, length)
			require.Equal(t, tc.gnu, m.gnu != "")

			target := sampled
			if !tc.sameBuild {
				target = filepath.Join(t.TempDir(), base)
				writeELFFixture(t, target, otherBuild(otherID))
				require.NotEqual(t, m.htlhash, htlhashOf(t, target))
			}
			if tc.link == "exe" {
				proc.linkExe(target)
			} else {
				start := uint64(0x7f3a1c000000)
				end := proc.mapExec(start, m.offset, m.limit-m.start, "/usr/lib64/"+base)
				proc.writeMaps()
				proc.linkMapFile(start, end, target)
			}

			pd := buildPayload(
				[]fxMapping{m},
				[]fxLocation{{mapping: 0, addr: fx.addr(t, "hot_leaf", 4)}},
				[]fxResource{{pid: fakePID, exe: exe, locs: []int{0}}},
			)
			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
			_, err := s.processProfiles(context.Background(), pd)
			require.NoError(t, err)

			if tc.sameBuild {
				require.Equal(t, "hot_leaf", locationName(pd, 0))
				require.Equal(t, uint64(1), s.framesResolvedByHtlhash.Load())
				return
			}
			require.Empty(t, locationName(pd, 0), "another build reached through %s must give no name", tc.link)
			require.Equal(t, uint64(0), s.framesResolved.Load())
			if tc.gnu {
				require.Equal(t, uint64(1), s.buildIDMismatch.Load())
			} else {
				require.Equal(t, uint64(1), s.htlhashMismatch.Load())
			}
			require.Equal(t, uint64(0), s.symbolTablesParsed.Load(), "a file that fails the identity check is not parsed")
		})
	}
}

// TestMapsIsReadOncePerProcessPerPass covers a process with two shared objects
// that are not resolved. Each one is walked, but /proc/<pid>/maps is read once
// for the process in the pass, because each read takes the target's mmap lock.
func TestMapsIsReadOncePerProcessPerPass(t *testing.T) {
	prefix := t.TempDir()
	proc := newFakeProc(t, prefix, fakePID)
	proc.writeMaps() // no file lines, so neither library is found
	pd := buildPayload(
		[]fxMapping{{filename: "liba.so", gnu: "aa", limit: 0x1000}, {filename: "libb.so", gnu: "bb", limit: 0x1000}},
		[]fxLocation{{mapping: 0, addr: 0x10}, {mapping: 1, addr: 0x10}},
		[]fxResource{{pid: fakePID, exe: "/usr/bin/app", locs: []int{0, 1}}},
	)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)

	require.Equal(t, uint64(2), s.candidateWalks.Load(), "each library is walked")
	require.Equal(t, uint64(1), s.procMapsReads.Load(), "maps is read once for the process")
	require.Equal(t, uint64(2), s.framesNoCandidate.Load())
}

// TestProcessPIDMustBeADecimalNumber covers the guard on process.pid, which
// comes off the wire like every other value. Only a positive decimal number
// gives /proc paths. Anything else gives none, so that a pid of "../../etc"
// cannot turn <prefix>/proc/<pid>/maps into another file.
func TestProcessPIDMustBeADecimalNumber(t *testing.T) {
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	contextOf := func(pid string) procContext {
		pd := pprofile.NewProfiles()
		rp := pd.ResourceProfiles().AppendEmpty()
		rp.Resource().Attributes().PutStr(attrPID, pid)
		return s.processContext(rp)
	}
	for _, pid := range []string{"../../etc", "-1", "0", "12x", ""} {
		pc := contextOf(pid)
		require.Empty(t, pc.procDir, "pid %q", pid)
		require.Empty(t, pc.root, "pid %q", pid)
	}
	require.Equal(t, "/proc/4242", contextOf("4242").procDir, "a decimal pid gives its /proc directory")
}

// TestSymlinkOutOfProcessRootIsNotFollowed proves that a path under a process
// root is opened inside that root. The only file that would match is outside
// the root, and a symlink inside the root points at it. A plain open would
// follow the link and read a host file for a container's process. The
// processor must not.
func TestSymlinkOutOfProcessRootIsNotFollowed(t *testing.T) {
	requireOpenat2(t)
	for _, tc := range []struct {
		name   string
		target func(outside string) string
	}{
		{name: "absolute symlink", target: func(outside string) string { return outside }},
		{name: "relative symlink with ..", target: func(string) string { return "../../../../../outside/libfixture.so" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := t.TempDir()
			proc := newFakeProc(t, prefix, fakePID)
			outside := filepath.Join(prefix, "outside", "libfixture.so")
			fx, m := libFixture(t, outside, []byte("libfixture-build-id-v1"))

			link := proc.inRoot("/usr/lib64/libfixture.so")
			require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
			require.NoError(t, os.Symlink(tc.target(outside), link))
			// The link does reach the file for anyone who follows it.
			_, err := os.Stat(link)
			require.NoError(t, err)

			proc.mapExec(0x7f3a1c000000, m.offset, m.limit-m.start, "/usr/lib64/libfixture.so")
			proc.writeMaps()

			pd := buildPayload(
				[]fxMapping{m},
				[]fxLocation{{mapping: 0, addr: fx.addr(t, "hot_leaf", 4)}},
				[]fxResource{{pid: fakePID, exe: "/usr/bin/app", locs: []int{0}}},
			)
			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
			_, err = s.processProfiles(context.Background(), pd)
			require.NoError(t, err)

			require.Empty(t, locationName(pd, 0), "a file outside the process root must not be read")
			require.Equal(t, uint64(1), s.framesNoCandidate.Load())
		})
	}
}

// TestParseExecMapsLine covers the maps lines that must not become candidates,
// and a path with a space and a deleted file, which must.
func TestParseExecMapsLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want mapsLine
		ok   bool
	}{
		{"7f3a1c000000-7f3a1c1b2000 r-xp 00000000 103:01 1234 /usr/lib64/libc-2.26.so",
			mapsLine{start: 0x7f3a1c000000, end: 0x7f3a1c1b2000, offset: 0, path: "/usr/lib64/libc-2.26.so"}, true},
		{"7f3a1c000000-7f3a1c001000 r-xp 00030000 103:01 1234     /opt/my app/lib x.so (deleted)",
			mapsLine{start: 0x7f3a1c000000, end: 0x7f3a1c001000, offset: 0x30000, path: "/opt/my app/lib x.so"}, true},
		{"7f3a1c000000-7f3a1c1b2000 r--p 00000000 103:01 1234 /usr/lib64/libc-2.26.so", mapsLine{}, false},
		{"7ffd1c000000-7ffd1c002000 r-xp 00000000 00:00 0 [vdso]", mapsLine{}, false},
		{"7ffd1c000000-7ffd1c002000 rwxp 00000000 00:00 0", mapsLine{}, false},
		{"garbage", mapsLine{}, false},
	} {
		got, ok := parseExecMapsLine(tc.line)
		require.Equal(t, tc.ok, ok, tc.line)
		require.Equal(t, tc.want, got, tc.line)
	}
}

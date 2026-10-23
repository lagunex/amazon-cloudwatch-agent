// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/unix"
)

// TestMain runs the tests in full mode by default: most of them use a fake
// /proc under root_path_prefix, which is about finding files, not about what
// the agent may read. The tests of the modes choose theirs with withPrivileges,
// and the tests against real processes use the real probe.
func TestMain(m *testing.M) {
	probePrivileges = func(string) privileges { return fullPrivileges() }
	os.Exit(m.Run())
}

func fullPrivileges() privileges {
	return privileges{mode: modeFull, uid: euid(), gid: egid(), mapFiles: true}
}

// withPrivileges makes the shared states that the test creates use p.
func withPrivileges(t *testing.T, p privileges) {
	t.Helper()
	prev := probePrivileges
	probePrivileges = func(string) privileges { return p }
	t.Cleanup(func() { probePrivileges = prev })
}

// withRealPrivileges makes the shared states that the test creates probe the
// running test process, and returns what the probe finds.
func withRealPrivileges(t *testing.T) privileges {
	t.Helper()
	prev := probePrivileges
	probePrivileges = probeHostPrivileges
	t.Cleanup(func() { probePrivileges = prev })
	return probeHostPrivileges("/proc")
}

func TestReadCapEff(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	require.NoError(t, os.WriteFile(status, []byte("Name:\tagent\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t0000010000080000\n"), 0o600))
	set, err := readCapEff(status)
	require.NoError(t, err)
	require.True(t, hasCap(set, capSysPtrace))
	require.True(t, hasCap(set, capCheckpointRestore))
	require.False(t, hasCap(set, capSysAdmin))

	require.NoError(t, os.WriteFile(status, []byte("Name:\tagent\n"), 0o600))
	_, err = readCapEff(status)
	require.Error(t, err, "a status file with no CapEff line is an error, not an empty set")
}

func TestProcHidesPIDs(t *testing.T) {
	line := func(mountPoint, superOpts string) string {
		return fmt.Sprintf("25 70 0:24 / %s rw,nosuid,nodev,noexec,relatime shared:13 - proc proc %s\n", mountPoint, superOpts)
	}
	for _, tc := range []struct {
		name       string
		mountinfo  string
		mountPoint string
		want       bool
	}{
		{"no hidepid", line("/proc", "rw"), "/proc", false},
		{"hidepid=2", line("/proc", "rw,hidepid=2"), "/proc", true},
		{"hidepid=invisible", line("/proc", "rw,hidepid=invisible"), "/proc", true},
		{"hidepid=ptraceable", line("/proc", "rw,hidepid=ptraceable"), "/proc", true},
		{"hidepid=1 denies instead of hiding", line("/proc", "rw,hidepid=1"), "/proc", false},
		{"hidepid=noaccess denies instead of hiding", line("/proc", "rw,hidepid=noaccess"), "/proc", false},
		{"another mount point", line("/host/proc", "rw,hidepid=2"), "/proc", false},
		{"the mount on top wins", line("/proc", "rw,hidepid=2") + line("/proc", "rw"), "/proc", false},
		{"an escaped mount point", line(`/host\040root/proc`, "rw,hidepid=2"), "/host root/proc", true},
		{"not a proc mount", "30 25 0:30 / /proc rw - tmpfs tmpfs rw,hidepid=2\n", "/proc", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mountinfo")
			require.NoError(t, os.WriteFile(path, []byte(tc.mountinfo), 0o600))
			require.Equal(t, tc.want, procHidesPIDs(path, tc.mountPoint))
		})
	}
}

// TestCheckProcAccess covers the limited-mode decision on a /proc entry, with
// the stat result injected: the owner the kernel shows for /proc/<pid>/maps is
// the process's effective uid and gid when it is dumpable, and root when not.
func TestCheckProcAccess(t *testing.T) {
	priv := privileges{mode: modeLimited, uid: 1000, gid: 1000}
	stat := func(uid, gid uint32, err error) func(string, *unix.Stat_t) error {
		return func(_ string, st *unix.Stat_t) error {
			st.Uid, st.Gid = uid, gid
			return err
		}
	}
	for _, tc := range []struct {
		name    string
		stat    func(string, *unix.Stat_t) error
		hidePID bool
		want    procAccess
	}{
		{"same uid and gid", stat(1000, 1000, nil), false, procReadable},
		{"another uid", stat(0, 0, nil), false, procDenied},
		{"same uid, another gid", stat(1000, 1001, nil), false, procDenied},
		{"refused, as with hidepid=noaccess", stat(0, 0, unix.EACCES), false, procDenied},
		{"absent: the process exited", stat(0, 0, unix.ENOENT), false, procGone},
		{"absent with hidepid=invisible: hidden", stat(0, 0, unix.ENOENT), true, procDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := statProc
			statProc = tc.stat
			t.Cleanup(func() { statProc = prev })
			p := priv
			p.hidePID = tc.hidePID
			require.Equal(t, tc.want, checkProcAccess("/proc/4242", p))
		})
	}
}

// TestProbeOnThisHost runs the real probe. The test process can always reopen
// files through /proc/self/fd, so it is never inactive, and its mode follows
// CAP_SYS_PTRACE.
func TestProbeOnThisHost(t *testing.T) {
	p := probeHostPrivileges("/proc")
	capEff, err := readCapEff("/proc/self/status")
	require.NoError(t, err)
	require.Equal(t, euid(), p.uid)
	require.Equal(t, egid(), p.gid)
	if hasCap(capEff, capSysPtrace) {
		require.Equal(t, modeFull, p.mode)
	} else {
		require.Equal(t, modeLimited, p.mode)
	}
	require.Equal(t, hasCap(capEff, capCheckpointRestore) || hasCap(capEff, capSysAdmin), p.mapFiles)
}

// TestLimitedModeSkipsTheProcEntryOfAnotherUser: the library of a process is
// reachable only through its /proc entry (a basename, and no executable path),
// and the entry belongs to another user. Limited mode does not touch it, so no
// maps file is read and nothing is opened under it, and the frame is counted
// permission_denied. The same process with the agent's own uid is read.
func TestLimitedModeSkipsTheProcEntryOfAnotherUser(t *testing.T) {
	for _, tc := range []struct {
		name   string
		uid    uint32
		want   string
		denied uint64
		reads  uint64
	}{
		{"another user: skipped", euid() + 1, "", 1, 0},
		{"the agent's own user: read", euid(), "hot_leaf", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireOpenat2(t)
			withPrivileges(t, privileges{mode: modeLimited, uid: tc.uid, gid: egid()})
			prefix := t.TempDir()
			proc := newFakeProc(t, prefix, fakePID)
			lib := proc.inRoot("/usr/lib64/libfixture.so")
			fx, m := libFixture(t, lib, []byte("limited-mode-lib"))
			const start = 0x7f0000000000
			end := proc.mapExec(start, m.offset, m.limit-m.start, "/usr/lib64/libfixture.so")
			proc.linkMapFile(start, end, lib)
			proc.writeMaps()

			pd := buildPayload(
				[]fxMapping{m},
				[]fxLocation{{mapping: 0, addr: fx.addr(t, "hot_leaf", 4)}},
				[]fxResource{{pid: fakePID, locs: []int{0}}},
			)
			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
			_, err := s.processProfiles(context.Background(), pd)
			require.NoError(t, err)
			require.Equal(t, tc.want, locationName(pd, 0))
			require.Equal(t, tc.denied, s.permissionDenied.Load())
			require.Zero(t, s.framesNoCandidate.Load())
			require.Equal(t, tc.reads, s.procMapsReads.Load())
		})
	}
}

// TestLimitedModeStillTriesTheReportedPaths: the /proc entry of the process is
// skipped (another user), but the sender reported the executable's path, and
// the agent can read that file. The frame is named, with its identity proved
// like any other.
func TestLimitedModeStillTriesTheReportedPaths(t *testing.T) {
	withPrivileges(t, privileges{mode: modeLimited, uid: euid() + 1, gid: egid()})
	bin, buildID, addr := buildTestBinary(t)
	prefix := t.TempDir()
	newFakeProc(t, prefix, fakePID).writeMaps()
	pd := buildPayload(
		[]fxMapping{{filename: filepath.Base(bin), gnu: buildID}},
		[]fxLocation{{mapping: 0, addr: addr}},
		[]fxResource{{pid: fakePID, exe: bin, locs: []int{0}}},
	)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)
	require.Equal(t, "hot_leaf", locationName(pd, 0))
	require.Zero(t, s.permissionDenied.Load())
}

// TestMapFilesNeedsTheCapability: map_files links are followed only when the
// agent may follow them; the other candidates of the library are unchanged.
func TestMapFilesNeedsTheCapability(t *testing.T) {
	for _, mapFiles := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapFiles=%v", mapFiles), func(t *testing.T) {
			p := fullPrivileges()
			p.mapFiles = mapFiles
			withPrivileges(t, p)
			prefix := t.TempDir()
			proc := newFakeProc(t, prefix, fakePID)
			const start = 0x7f0000000000
			proc.mapExec(start, 0, 0x3000, "/usr/lib64/libfixture.so")
			proc.writeMaps()
			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8, RootPathPrefix: prefix}, zaptest.NewLogger(t))
			pass := &passState{maps: map[string][]mapsLine{}, mapsErr: map[string]error{}}
			pc := procContext{procDir: proc.dir, root: proc.root}
			var paths []string
			for _, c := range s.candidates(pass, mappingInfo{filename: "libfixture.so"}, pc) {
				paths = append(paths, c.path)
			}
			mapFile := filepath.Join(proc.dir, "map_files", fmt.Sprintf("%x-%x", start, start+0x3000))
			if mapFiles {
				require.Contains(t, paths, mapFile)
			} else {
				require.NotContains(t, paths, mapFile)
			}
			require.Contains(t, paths, filepath.Join(proc.root, "/usr/lib64/libfixture.so"))
		})
	}
}

// TestInactiveModePassesThrough: an inactive processor forwards the payload
// exactly as it arrived and does no work.
func TestInactiveModePassesThrough(t *testing.T) {
	withPrivileges(t, privileges{mode: modeInactive})
	bin, buildID, addr := buildTestBinary(t)
	pd := makeProfiles(bin, buildID, addr)
	before, err := (&pprofile.ProtoMarshaler{}).MarshalProfiles(pd)
	require.NoError(t, err)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	out, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)
	after, err := (&pprofile.ProtoMarshaler{}).MarshalProfiles(out)
	require.NoError(t, err)
	require.True(t, bytes.Equal(before, after), "the payload is forwarded unchanged")
	require.Zero(t, s.framesSeen.Load())
	require.Zero(t, s.candidateWalks.Load())
	require.Zero(t, s.passes.Load(), "an inactive processor logs no summary")
}

// TestPermissionDeniedOnAnUnreadableFile: the file that would name the frame
// exists but the agent may not read it. That is permission_denied, not
// no_candidate.
func TestPermissionDeniedOnAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 0000")
	}
	bin, buildID, addr := buildTestBinary(t)
	require.NoError(t, os.Chmod(bin, 0))
	t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })
	pd := makeProfiles(bin, buildID, addr)
	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	_, err := s.processProfiles(context.Background(), pd)
	require.NoError(t, err)
	require.Equal(t, uint64(1), s.permissionDenied.Load())
	require.Zero(t, s.framesNoCandidate.Load())
	require.Equal(t, s.framesSeen.Load(), s.permissionDenied.Load(), "the frame is accounted for")
}

// TestModeIsLoggedOncePerConfigAndExported: the collector builds an instance
// per pipeline from one Config. A limited or inactive mode is logged once, at
// Warn, however many pipelines list the processor, and every mode is exported
// as the mode gauge. Full mode logs nothing at startup.
func TestModeIsLoggedOncePerConfigAndExported(t *testing.T) {
	for _, tc := range []struct {
		priv  privileges
		warns int
	}{
		{fullPrivileges(), 0},
		{privileges{mode: modeLimited, uid: 1000, gid: 1000}, 1},
		{privileges{mode: modeInactive}, 1},
	} {
		t.Run(tc.priv.mode.String(), func(t *testing.T) {
			withPrivileges(t, tc.priv)
			core, logs := observer.New(zapcore.WarnLevel)
			tel := componenttest.NewTelemetry()
			t.Cleanup(func() { require.NoError(t, tel.Shutdown(context.Background())) })
			cfg := createDefaultConfig().(*Config)
			for i := 0; i < 2; i++ {
				ts := tel.NewTelemetrySettings()
				ts.Logger = zap.New(core)
				set := processor.Settings{ID: component.NewID(TypeStr), TelemetrySettings: ts, BuildInfo: component.NewDefaultBuildInfo()}
				p, err := createProfilesProcessor(context.Background(), set, cfg, new(consumertest.ProfilesSink))
				require.NoError(t, err)
				require.NoError(t, p.Start(context.Background(), componenttest.NewNopHost()))
				t.Cleanup(func() { require.NoError(t, p.Shutdown(context.Background())) })
			}
			require.Len(t, logs.All(), tc.warns)
			for _, e := range logs.All() {
				require.Equal(t, tc.priv.mode.String(), e.ContextMap()["mode"])
			}

			m, err := tel.GetMetric(metricPrefix + "mode")
			require.NoError(t, err)
			g, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok, "mode must be an int64 gauge")
			require.NotEmpty(t, g.DataPoints)
			require.Equal(t, int64(tc.priv.mode), g.DataPoints[0].Value)
		})
	}
}

// --- real processes ---------------------------------------------------------
//
// The tests below run the real probe against real processes, to check the
// kernel behavior that limited mode relies on. They need a test process
// without CAP_SYS_PTRACE (an ordinary user), and skip otherwise.

// requireLimited skips a test that needs the real probe to find limited mode.
func requireLimited(t *testing.T) {
	t.Helper()
	if p := withRealPrivileges(t); p.mode != modeLimited {
		t.Skipf("needs a test process without CAP_SYS_PTRACE; the probe found mode %s", p.mode)
	}
}

// startSleeper builds and starts a PIE program with a hot_leaf function that
// then waits forever. With nonDumpable, it clears PR_SET_DUMPABLE first. It
// returns the binary, its GNU build ID, the ELF address of a byte in hot_leaf,
// and the process.
func startSleeper(t *testing.T, nonDumpable bool) (string, string, uint64, *os.Process) {
	t.Helper()
	cc := cCompiler(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "sleeper.c")
	bin := filepath.Join(dir, "sleeper")
	require.NoError(t, os.WriteFile(src, []byte(`
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
__attribute__((noinline)) long hot_leaf(long n){ long a=0; for(long i=0;i<n;i++) a+=i; return a; }
int main(int argc, char **argv){
	if (argc > 1) prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	printf("%ld\n", hot_leaf(10));
	fflush(stdout);
	for (;;) pause();
}
`), 0o600))
	out, err := exec.Command(cc, "-O0", "-fno-inline", "-g", "-fPIE", "-pie", "-Wl,--build-id", "-o", bin, src).CombinedOutput()
	require.NoError(t, err, "compile failed: %s", out)
	st, err := newSymbolTable(bin)
	require.NoError(t, err)
	var addr uint64
	for _, r := range st.ranges {
		if r.name == "hot_leaf" {
			addr = r.start + 4
		}
	}
	require.NotZero(t, addr)

	cmd := exec.Command(bin)
	if nonDumpable {
		cmd = exec.Command(bin, "nondumpable")
	}
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// The program prints once it has run past prctl.
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		require.Equal(t, "45", strings.TrimSpace(line))
	case <-time.After(10 * time.Second):
		t.Fatal("the test program did not start")
	}
	return bin, st.buildID, addr, cmd.Process
}

// runtimeMappingOf reads the executable mapping of bin from the maps file of a
// running process.
func runtimeMappingOf(t *testing.T, pid int, bin string) mapsLine {
	t.Helper()
	lines, err := readExecMaps(fmt.Sprintf("/proc/%d/maps", pid))
	require.NoError(t, err)
	for _, l := range lines {
		if l.path == bin {
			return l
		}
	}
	t.Fatalf("no executable mapping of %s in process %d", bin, pid)
	return mapsLine{}
}

// TestRealProcessOfTheAgentsUserResolvesThroughProc: without any capability,
// the agent reads /proc/<pid>/{maps,root} of a dumpable process of its own user.
// The sender reports runtime addresses and only the basename of the file, with
// no executable path, so /proc is the only way to the file.
func TestRealProcessOfTheAgentsUserResolvesThroughProc(t *testing.T) {
	requireLimited(t)
	requireOpenat2(t)
	bin, buildID, va, proc := startSleeper(t, false)
	l := runtimeMappingOf(t, proc.Pid, bin)

	s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
	require.Equal(t, modeLimited, s.priv.mode)
	require.False(t, s.priv.mapFiles, "an ordinary user may not follow map_files links")
	st, err := newSymbolTable(bin)
	require.NoError(t, err)
	fileVA, ok := st.fileOffsetToVA(l.offset)
	require.True(t, ok)
	pd := buildPayload(
		[]fxMapping{{filename: filepath.Base(bin), gnu: buildID, start: l.start, limit: l.end, offset: l.offset}},
		[]fxLocation{{mapping: 0, addr: l.start + (va - fileVA)}},
		[]fxResource{{pid: int64(proc.Pid), locs: []int{0}}},
	)
	_, err = s.processProfiles(context.Background(), pd)
	require.NoError(t, err)
	require.Equal(t, "hot_leaf", locationName(pd, 0))
	require.Equal(t, uint64(1), s.procMapsReads.Load(), "found through /proc/<pid>/maps")
}

// TestRealNonDumpableProcessIsSkipped: a process of the agent's own user that
// cleared PR_SET_DUMPABLE shows root as the owner of its /proc files, and the
// kernel refuses its maps. Limited mode skips it without touching its maps,
// counts its frame permission_denied, and still names it through the
// executable path that the sender reported.
func TestRealNonDumpableProcessIsSkipped(t *testing.T) {
	requireLimited(t)
	bin, buildID, va, proc := startSleeper(t, true)
	maps := fmt.Sprintf("/proc/%d/maps", proc.Pid)
	var st unix.Stat_t
	require.NoError(t, unix.Stat(maps, &st))
	require.Zero(t, st.Uid, "the kernel shows root as the owner of a non-dumpable process's /proc files")
	_, err := os.ReadFile(maps)
	require.ErrorIs(t, err, fs.ErrPermission, "the kernel refuses the maps of a non-dumpable process")

	for _, tc := range []struct {
		name   string
		exe    string
		want   string
		denied uint64
	}{
		{"no executable path: permission_denied", "", "", 1},
		{"executable path reported: named", bin, "hot_leaf", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
			pd := buildPayload(
				[]fxMapping{{filename: filepath.Base(bin), gnu: buildID}},
				[]fxLocation{{mapping: 0, addr: va}},
				[]fxResource{{pid: int64(proc.Pid), exe: tc.exe, locs: []int{0}}},
			)
			_, err := s.processProfiles(context.Background(), pd)
			require.NoError(t, err)
			require.Equal(t, tc.want, locationName(pd, 0))
			require.Equal(t, tc.denied, s.permissionDenied.Load())
			require.Zero(t, s.procMapsReads.Load(), "the maps of a skipped process are not read")
		})
	}
}

// TestRealProcessOfAnotherUserResolvesThroughReportedPaths uses pid 1, which
// on an ordinary host belongs to root: the kernel refuses its /proc entry to
// the agent. Its files are still named through the paths the sender reported,
// when they are world-readable: a shared object reported by its absolute path,
// and the executable reported as process.executable.path.
func TestRealProcessOfAnotherUserResolvesThroughReportedPaths(t *testing.T) {
	requireLimited(t)
	var st unix.Stat_t
	if err := unix.Stat("/proc/1/maps", &st); err != nil || st.Uid == euid() {
		t.Skip("needs a pid 1 that belongs to another user")
	}
	_, err := os.ReadFile("/proc/1/maps")
	require.ErrorIs(t, err, fs.ErrPermission, "the kernel refuses the maps of another user's process")

	// resolveFrom names one frame of pid 1 in the file at path, reported as the
	// mapping's filename and, with asExe, as the executable path.
	resolveFrom := func(t *testing.T, path string, asExe bool) {
		table, err := newSymbolTable(path)
		if err != nil || table.buildID == "" {
			t.Skipf("%s has no symbols or no GNU build ID: %v", path, err)
		}
		var fn funcRange
		for _, r := range table.ranges {
			if r.size > 1 {
				fn = r
				break
			}
		}
		require.NotEmpty(t, fn.name)
		res := fxResource{pid: 1, locs: []int{0}}
		mapping := fxMapping{filename: path, gnu: table.buildID}
		if asExe {
			res.exe = path
			mapping.filename = filepath.Base(path)
		}
		s := newSymbolizer(&Config{RequireBuildIDMatch: true, MaxCachedBinaries: 8}, zaptest.NewLogger(t))
		pd := buildPayload([]fxMapping{mapping}, []fxLocation{{mapping: 0, addr: fn.start + 1}}, []fxResource{res})
		_, err = s.processProfiles(context.Background(), pd)
		require.NoError(t, err)
		want, _, ok := table.resolve(fn.start + 1)
		require.True(t, ok)
		require.Equal(t, want, locationName(pd, 0))
		require.Zero(t, s.procMapsReads.Load(), "the maps of another user's process are not read")
	}

	t.Run("a shared object reported by its absolute path", func(t *testing.T) {
		// The C library that pid 1 maps is the host's, found here through the
		// maps of a process of the test's own user.
		bin, _, _, proc := startSleeper(t, false)
		var libc string
		lines, err := readExecMaps(fmt.Sprintf("/proc/%d/maps", proc.Pid))
		require.NoError(t, err)
		for _, l := range lines {
			if l.path != bin && strings.HasPrefix(filepath.Base(l.path), "libc") {
				libc = l.path
			}
		}
		if libc == "" {
			t.Skip("the test program maps no C library")
		}
		resolveFrom(t, libc, false)
	})

	t.Run("the executable reported as process.executable.path", func(t *testing.T) {
		cmdline, err := os.ReadFile("/proc/1/cmdline")
		if err != nil || len(cmdline) == 0 {
			t.Skip("cannot read the command line of pid 1")
		}
		exe, err := filepath.EvalSymlinks(string(bytes.SplitN(cmdline, []byte{0}, 2)[0]))
		if err != nil || !filepath.IsAbs(exe) {
			t.Skipf("cannot find the executable of pid 1: %v", err)
		}
		resolveFrom(t, exe, true)
	})
}

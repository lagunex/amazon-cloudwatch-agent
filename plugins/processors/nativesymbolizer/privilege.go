// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// mode is how much of the host the processor can read. It is probed once, when
// the shared state of a config is created, and does not change afterwards.
type mode int

const (
	// modeInactive: the agent cannot reopen a file through its own
	// /proc/self/fd, which every candidate open goes through, so no binary can
	// be read. The processor passes profiles through without looking at them.
	modeInactive mode = iota
	// modeLimited: the agent lacks CAP_SYS_PTRACE. The kernel's ptrace read
	// check on /proc/<pid>/{exe,maps,root} then passes only for a dumpable
	// process whose uids and gids are all the agent's own. Other processes are
	// still tried through the paths the sender reported (plain-path candidates),
	// so their world-readable binaries in the agent's own filesystem resolve.
	modeLimited
	// modeFull: the agent has CAP_SYS_PTRACE and can read /proc/<pid> of any
	// process it can see.
	modeFull
)

func (m mode) String() string {
	switch m {
	case modeFull:
		return "full"
	case modeLimited:
		return "limited"
	default:
		return "inactive"
	}
}

// Linux capability numbers (linux/capability.h).
const (
	capSysPtrace         = 19
	capSysAdmin          = 21
	capCheckpointRestore = 40
)

// privileges is what the probe found about the agent.
type privileges struct {
	mode mode
	// uid and gid are the agent's effective ids, which the kernel's ptrace
	// read check compares (as fsuid/fsgid) with the target's ids.
	uid, gid uint32
	// mapFiles reports whether /proc/<pid>/map_files links can be followed:
	// the kernel requires CAP_CHECKPOINT_RESTORE or CAP_SYS_ADMIN for that,
	// whatever the target's owner. Without it those candidates are skipped,
	// which only loses a binary replaced on disk since its process started.
	mapFiles bool
	// hidePID reports that the /proc the processor reads is mounted with
	// hidepid=invisible (or ptraceable): a process the agent may not read is
	// then absent from /proc, rather than present and denied.
	hidePID bool
}

// probePrivileges is the probe the shared state uses. It is a variable only so
// that a test can choose the mode; production code never assigns it.
var probePrivileges = probeHostPrivileges

// probeHostPrivileges probes the running agent. procDir is the /proc that the
// processor reads target processes from (<root_path_prefix>/proc).
func probeHostPrivileges(procDir string) privileges {
	p := privileges{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())} //nolint:gosec // G115: Linux uids and gids are 32-bit
	if !canReopenThroughProcSelf() {
		return p
	}
	capEff, err := readCapEff("/proc/self/status")
	if err != nil {
		return p
	}
	p.mode = modeLimited
	if hasCap(capEff, capSysPtrace) {
		p.mode = modeFull
	}
	p.mapFiles = hasCap(capEff, capCheckpointRestore) || hasCap(capEff, capSysAdmin)
	p.hidePID = procHidesPIDs("/proc/self/mountinfo", procDir)
	return p
}

// canReopenThroughProcSelf reports whether a descriptor can be reopened through
// /proc/self/fd, which is how reopenRegular reads every candidate.
func canReopenThroughProcSelf() bool {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	f, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// readCapEff returns the effective capability set from a /proc/<pid>/status
// file.
func readCapEff(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "CapEff:"); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("no CapEff line in " + path)
}

func hasCap(set uint64, c uint) bool {
	return set&(1<<c) != 0
}

// procHidesPIDs reports whether the proc mount at mountPoint, as listed in a
// /proc/<pid>/mountinfo file, hides the processes the reader may not access
// (hidepid=2/invisible or hidepid=4/ptraceable). The last mount listed at a
// mount point is the one on top.
func procHidesPIDs(mountinfo, mountPoint string) bool {
	f, err := os.Open(mountinfo)
	if err != nil {
		return false
	}
	defer f.Close()
	mountPoint = filepath.Clean(mountPoint)
	hides := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if mp, fsType, superOpts, ok := parseMountinfoLine(sc.Text()); ok && fsType == "proc" && mp == mountPoint {
			hides = hidesPIDs(superOpts)
		}
	}
	return hides
}

// parseMountinfoLine returns the mount point, the file system type and the
// super options of one mountinfo line:
//
//	25 70 0:24 / /proc rw,nosuid shared:13 - proc proc rw,hidepid=invisible
func parseMountinfoLine(line string) (string, string, string, bool) {
	pre, post, ok := strings.Cut(line, " - ")
	if !ok {
		return "", "", "", false
	}
	preFields := strings.Fields(pre)
	postFields := strings.Fields(post)
	if len(preFields) < 5 || len(postFields) < 3 {
		return "", "", "", false
	}
	return unescapeMountinfo(preFields[4]), postFields[0], postFields[2], true
}

// unescapeMountinfo decodes the octal escapes (\040 for a space) that mountinfo
// uses in paths.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hidesPIDs(superOpts string) bool {
	for _, opt := range strings.Split(superOpts, ",") {
		if v, ok := strings.CutPrefix(opt, "hidepid="); ok {
			switch v {
			case "2", "invisible", "4", "ptraceable":
				return true
			}
		}
	}
	return false
}

// procAccess is what limited mode concluded about one process's /proc entry.
type procAccess int

const (
	// procReadable: the entry belongs to the agent's uid and gid and the
	// process is dumpable, so its /proc candidates are worth trying.
	procReadable procAccess = iota
	// procDenied: the kernel would refuse the agent, or hides the process.
	procDenied
	// procGone: the process has no /proc entry, most likely because it exited.
	procGone
)

// statProc is unix.Stat. It is a variable only so that a test can present a
// /proc entry of another owner; production code never assigns it.
var statProc = unix.Stat

// checkProcAccess decides, without touching anything the ptrace check guards,
// whether the agent can read /proc/<pid> in limited mode. It stats
// /proc/<pid>/maps: for a dumpable process the kernel shows the process's
// effective uid and gid as its owner, and for a non-dumpable one (a setuid
// program, or one that cleared PR_SET_DUMPABLE) it shows root. So an owner
// equal to the agent's ids means the read check passes, unless the process's
// real or saved ids differ, which the open then reports as permission_denied.
func checkProcAccess(procDir string, priv privileges) procAccess {
	var st unix.Stat_t
	if err := statProc(procDir+"/maps", &st); err != nil {
		switch {
		case errors.Is(err, fs.ErrPermission):
			return procDenied
		case errors.Is(err, fs.ErrNotExist) && priv.hidePID:
			return procDenied
		default:
			return procGone
		}
	}
	if st.Uid != priv.uid || st.Gid != priv.gid {
		return procDenied
	}
	return procReadable
}

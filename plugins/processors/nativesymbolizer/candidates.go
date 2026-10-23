// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

// Finding a mapping's file: which paths are tried, in which order, and how each
// one is opened. See resolveMapping for how a candidate is then accepted.

package nativesymbolizer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pprofile"
	"golang.org/x/sys/unix"
)

// procContext is what the processor knows about the process a resource profile
// came from. The candidate paths for a mapping are derived from it.
type procContext struct {
	// procDir is <root_path_prefix>/proc/<pid>, or "" when the resource carries
	// no usable process.pid.
	procDir string
	// root is the directory that in-root candidates are resolved against:
	// procDir/root (the process's own view of the filesystem, which for a
	// container is the container image), or root_path_prefix when there is no
	// pid, or "".
	root string
	// exePath is process.executable.path without a " (deleted)" suffix.
	exePath string
	// denied is set when limited mode skipped this process's /proc entry
	// because the agent may not read it (see checkProcAccess).
	denied bool
}

// processContext builds the procContext of one resource.
//
// process.pid comes off the wire like every other value in the payload, so it
// is used only when it is a plain decimal number. Anything else ("../x", "-1")
// would turn the /proc paths below into arbitrary paths.
//
// In limited mode the /proc entry is used only when the agent may read it.
// Otherwise the process is treated like one with no pid: only the paths that
// the sender reported are tried, and a frame left unnamed is counted
// permission_denied rather than costing a refused open of each /proc path.
func (s *symbolizer) processContext(rp pprofile.ResourceProfiles) procContext {
	pid, exePath := processIdentity(rp)
	pc := procContext{exePath: trimDeleted(exePath)}
	if n, err := strconv.ParseUint(pid, 10, 32); err == nil && n > 0 {
		pc.procDir = filepath.Join(s.cfg.RootPathPrefix, "/proc", strconv.FormatUint(n, 10))
		pc.root = pc.procDir + "/root"
		if s.priv.mode == modeLimited {
			switch checkProcAccess(pc.procDir, s.priv) {
			case procDenied:
				pc.procDir, pc.root, pc.denied = "", "", true
			case procGone:
				pc.procDir, pc.root = "", ""
			}
		}
	}
	if pc.procDir == "" && s.cfg.RootPathPrefix != "" {
		pc.root = s.cfg.RootPathPrefix
	}
	return pc
}

// trimDeleted removes the " (deleted)" suffix that the kernel appends to the
// path of a file that was deleted or replaced while mapped. readlink of
// /proc/<pid>/exe and /proc/<pid>/maps both carry it (see path_with_deleted in
// linux/fs/d_path.c).
func trimDeleted(p string) string {
	return strings.TrimSuffix(p, " (deleted)")
}

// candidate is one place where a mapping's file may be found.
type candidate struct {
	// path is what diagnostics show. For an in-root candidate it is root + inner.
	path string
	// root, when not empty, makes open resolve inner inside root with
	// RESOLVE_IN_ROOT, so that no symlink or ".." can lead out of it.
	root  string
	inner string
}

// candidates lists where the file of one mapping may be, most exact first.
// Every candidate still has to prove the mapping's identity (see
// walkWithIdentity), so a wrong file at any of these paths gives no name, never
// a wrong one.
//
// The main executable (the mapping's basename is the basename of
// process.executable.path):
//
//  1. /proc/<pid>/exe. The kernel's link to the exact inode the process runs,
//     even when that file was deleted or replaced on disk since.
//  2. /proc/<pid>/root + process.executable.path, then the executable path as
//     it is.
//
// A shared object (any other mapping):
//
//  1. For each executable line of /proc/<pid>/maps whose file has the mapping's
//     basename and file offset: /proc/<pid>/map_files/<start>-<end>, the exact
//     inode that is mapped (only when the agent may follow those links, see
//     privileges.mapFiles), and then /proc/<pid>/root + the full path of that
//     line. A sender that reports only the basename of a file leaves this as
//     the only place the full path (/usr/lib64/libc.so.6) can come from. maps
//     is read only here, and at most once per process per pass. With
//     require_build_id_match on (the default), a resolved file is found by its
//     content before any walk, so maps is read only for a file that is not
//     resolved yet.
//
// Then, for both: /proc/<pid>/root + the mapping filename (or its basename,
// when it is not absolute), and the mapping filename as it is.
//
// Every candidate under a root is opened inside that root (see openInRoot).
func (s *symbolizer) candidates(p *passState, info mappingInfo, pc procContext) []candidate {
	var out []candidate
	seen := make(map[string]struct{}, 6)
	add := func(c candidate) {
		if _, dup := seen[c.path]; dup {
			return
		}
		seen[c.path] = struct{}{}
		out = append(out, c)
	}
	plain := func(path string) {
		add(candidate{path: path})
	}
	inRoot := func(inner string) {
		if pc.root != "" {
			add(candidate{path: filepath.Join(pc.root, inner), root: pc.root, inner: inner})
		}
	}

	base := filepath.Base(info.filename)
	if pc.exePath != "" && filepath.Base(pc.exePath) == base {
		if pc.procDir != "" {
			plain(pc.procDir + "/exe")
		}
		inRoot(pc.exePath)
		plain(pc.exePath)
	} else if pc.procDir != "" {
		for _, l := range s.execMaps(p, pc.procDir) {
			if filepath.Base(l.path) != base || l.offset != info.fileOffset {
				continue
			}
			if s.priv.mapFiles {
				plain(fmt.Sprintf("%s/map_files/%x-%x", pc.procDir, l.start, l.end))
			}
			inRoot(l.path)
		}
	}

	if filepath.IsAbs(info.filename) {
		inRoot(info.filename)
	} else {
		inRoot(base)
	}
	plain(info.filename)
	return out
}

// mapsLine is one executable, file-backed line of /proc/<pid>/maps.
type mapsLine struct {
	start, end uint64
	offset     uint64
	path       string
}

// execMaps returns the executable file mappings of the process at procDir. It
// reads /proc/<pid>/maps at most once per pass for each process. Reading maps
// takes the target's mmap lock, so with require_build_id_match on, the file is
// read only when a shared object of that process is not resolved yet.
func (s *symbolizer) execMaps(p *passState, procDir string) []mapsLine {
	if lines, ok := p.maps[procDir]; ok {
		return lines
	}
	s.procMapsReads.Add(1)
	lines, err := readExecMaps(procDir + "/maps")
	if err != nil {
		// The process may have exited, or the agent may not read its maps;
		// the other candidates still apply.
		lines = nil
		p.mapsErr[procDir] = err
	}
	p.maps[procDir] = lines
	return lines
}

// readExecMaps reads a /proc/<pid>/maps file and keeps its executable,
// file-backed lines.
func readExecMaps(path string) ([]mapsLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []mapsLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if l, ok := parseExecMapsLine(sc.Text()); ok {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// parseExecMapsLine parses one line of /proc/<pid>/maps,
//
//	7f3a1c000000-7f3a1c1b2000 r-xp 00000000 103:01 1234 /usr/lib64/libc-2.26.so
//
// and keeps it only when it is executable and backed by a file: the
// permissions have x, the inode is not 0, and the path is absolute. That leaves
// out anonymous memory, [vdso] and the other pseudo-files, which have no file to
// open. The path is the rest of the line, because a path can contain spaces.
func parseExecMapsLine(line string) (mapsLine, bool) {
	rest := line
	field := func() string {
		rest = strings.TrimLeft(rest, " ")
		f, r, _ := strings.Cut(rest, " ")
		rest = r
		return f
	}
	addrs, perms, offset, _, inode := field(), field(), field(), field(), field()
	path := trimDeleted(strings.TrimLeft(rest, " "))
	if len(perms) < 3 || perms[2] != 'x' || inode == "0" || inode == "" || !strings.HasPrefix(path, "/") {
		return mapsLine{}, false
	}
	startHex, endHex, ok := strings.Cut(addrs, "-")
	if !ok {
		return mapsLine{}, false
	}
	start, err1 := strconv.ParseUint(startHex, 16, 64)
	end, err2 := strconv.ParseUint(endHex, 16, 64)
	off, err3 := strconv.ParseUint(offset, 16, 64)
	if err1 != nil || err2 != nil || err3 != nil || end <= start {
		return mapsLine{}, false
	}
	return mapsLine{start: start, end: end, offset: off, path: path}, true
}

// open opens the candidate for reading and returns the fingerprint of the file
// it opened.
func (c candidate) open() (*os.File, fileFingerprint, error) {
	if c.root != "" {
		return openInRoot(c.root, c.inner)
	}
	return openPath(c.path)
}

// openInRoot opens inner inside root with openat2 and RESOLVE_IN_ROOT, so that
// an absolute symlink or a ".." inside a container root resolves inside that
// root and never reaches a host file, and RESOLVE_NO_MAGICLINKS, so that no
// /proc/self/... link inside the root is followed.
func openInRoot(root, inner string) (*os.File, fileFingerprint, error) {
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileFingerprint{}, &os.PathError{Op: "open", Path: root, Err: err}
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, inner, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fileFingerprint{}, &os.PathError{Op: "openat2", Path: filepath.Join(root, inner), Err: err}
	}
	return reopenRegular(fd, filepath.Join(root, inner))
}

// openPath opens a path that is not under a process root: /proc/<pid>/exe and
// /proc/<pid>/map_files/..., whose links the kernel resolves to the exact inode
// that the process uses, or a path in the agent's own mount namespace.
func openPath(path string) (*os.File, fileFingerprint, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileFingerprint{}, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return reopenRegular(fd, path)
}

// reopenRegular takes an O_PATH descriptor, checks that it names a non-empty
// regular file, and opens that same file for reading through /proc/self/fd. An
// O_PATH open never blocks, so a FIFO or a socket that has a library's name
// cannot hang the agent. It closes fd.
func reopenRegular(fd int, name string) (*os.File, fileFingerprint, error) {
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fileFingerprint{}, &os.PathError{Op: "fstat", Path: name, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fileFingerprint{}, fmt.Errorf("%s: not a regular file", name)
	}
	if st.Size == 0 {
		return nil, fileFingerprint{}, fmt.Errorf("%s: empty file", name)
	}
	f, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, fileFingerprint{}, fmt.Errorf("reopen %s: %w", name, err)
	}
	return f, fileFingerprint{
		dev:         uint64(st.Dev),
		ino:         st.Ino,
		modUnixNano: st.Mtim.Nano(),
		size:        st.Size,
		ok:          true,
	}, nil
}

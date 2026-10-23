// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"golang.org/x/sys/unix"
)

// --- ELF fixtures written in Go ---------------------------------------------

// elfFixture describes a synthetic ELF64 little-endian shared object.
//
// It is written in Go, not linked, so that its segment layout is the same on
// every build host. A linker cannot be trusted for this: an old binutils does
// not know -z separate-code and only warns, so a linked fixture would fall back
// to a text segment at offset 0 there, and a test of the other layouts would
// pass without testing anything.
type elfFixture struct {
	machine elf.Machine
	// The executable PT_LOAD: file offset, virtual address and size. textOff 0
	// is the classic layout: one R E segment that starts at the ELF header. Any
	// other textOff adds a read-only PT_LOAD for the headers in front, as
	// -z separate-code and lld's default layout do.
	textOff, textVaddr, textSize uint64
	buildID                      []byte // nil: no .note.gnu.build-id
	funcs                        []fixtureFunc
}

// fixtureFunc is one FUNC symbol, placed off bytes into the executable segment.
type fixtureFunc struct {
	name string
	off  uint64
	size uint64
}

// addr returns the ELF virtual address of the function named name, plus delta.
func (fx elfFixture) addr(t *testing.T, name string, delta uint64) uint64 {
	t.Helper()
	for _, f := range fx.funcs {
		if f.name == name {
			return fx.textVaddr + f.off + delta
		}
	}
	t.Fatalf("fixture has no function %q", name)
	return 0
}

func align(v, to uint64) uint64 { return (v + to - 1) &^ (to - 1) }

// writeELFFixture writes fx to path.
func writeELFFixture(t *testing.T, path string, fx elfFixture) {
	t.Helper()
	const (
		ehdrSize = 64
		phdrSize = 56
		shdrSize = 64
		symSize  = 24
		noteOff  = 0x100
		headPage = 0x1000
	)
	bo := binary.LittleEndian

	var note []byte
	if fx.buildID != nil {
		note = bo.AppendUint32(note, 4)                       // namesz, "GNU\0"
		note = bo.AppendUint32(note, uint32(len(fx.buildID))) //nolint:gosec // G115: a short test build ID
		note = bo.AppendUint32(note, 3)                       // NT_GNU_BUILD_ID
		note = append(note, 'G', 'N', 'U', 0)
		note = append(note, fx.buildID...)
		for len(note)%4 != 0 {
			note = append(note, 0)
		}
	}

	var progs []elf.Prog64
	if fx.textOff == 0 {
		require.GreaterOrEqual(t, fx.textSize, uint64(headPage), "a text segment at offset 0 holds the headers")
		progs = append(progs, elf.Prog64{
			Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X),
			Off: 0, Vaddr: fx.textVaddr, Paddr: fx.textVaddr,
			Filesz: fx.textSize, Memsz: fx.textSize, Align: 0x10000,
		})
	} else {
		head := min(fx.textOff, uint64(headPage))
		progs = append(progs,
			elf.Prog64{
				Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R),
				Off: 0, Vaddr: 0, Paddr: 0, Filesz: head, Memsz: head, Align: 0x10000,
			},
			elf.Prog64{
				Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X),
				Off: fx.textOff, Vaddr: fx.textVaddr, Paddr: fx.textVaddr,
				Filesz: fx.textSize, Memsz: fx.textSize, Align: 0x1000,
			})
	}
	if note != nil {
		progs = append(progs, elf.Prog64{
			Type: uint32(elf.PT_NOTE), Flags: uint32(elf.PF_R),
			Off: noteOff, Vaddr: noteOff, Paddr: noteOff,
			Filesz: uint64(len(note)), Memsz: uint64(len(note)), Align: 4,
		})
	}
	require.Less(t, uint64(ehdrSize+phdrSize*len(progs)), uint64(noteOff), "program headers overlap the note")

	// Symbols and strings, after the text.
	strtab := []byte{0}
	syms := []elf.Sym64{{}} // index 0 is the null symbol
	const textShndx = 1
	for _, f := range fx.funcs {
		syms = append(syms, elf.Sym64{
			Name:  uint32(len(strtab)), //nolint:gosec // G115: a small test string table
			Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC),
			Shndx: textShndx,
			Value: fx.textVaddr + f.off,
			Size:  f.size,
		})
		strtab = append(strtab, f.name...)
		strtab = append(strtab, 0)
	}
	shstrtab := []byte{0}
	name := func(s string) uint32 {
		off := u32(len(shstrtab))
		shstrtab = append(shstrtab, s...)
		shstrtab = append(shstrtab, 0)
		return off
	}

	end := max(fx.textOff+fx.textSize, uint64(headPage))
	symOff := align(end, 8)
	strOff := symOff + uint64(len(syms)*symSize)
	shstrOff := strOff + uint64(len(strtab))

	sections := []elf.Section64{{}}
	sections = append(sections, elf.Section64{
		Name: name(".text"), Type: uint32(elf.SHT_PROGBITS),
		Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR),
		Addr:  fx.textVaddr, Off: fx.textOff, Size: fx.textSize, Addralign: 16,
	})
	if note != nil {
		sections = append(sections, elf.Section64{
			Name: name(".note.gnu.build-id"), Type: uint32(elf.SHT_NOTE), Flags: uint64(elf.SHF_ALLOC),
			Addr: noteOff, Off: noteOff, Size: uint64(len(note)), Addralign: 4,
		})
	}
	symtabIdx := len(sections)
	sections = append(sections,
		elf.Section64{
			Name: name(".symtab"), Type: uint32(elf.SHT_SYMTAB),
			Off: symOff, Size: uint64(len(syms) * symSize),
			Link: u32(symtabIdx + 1), Info: 1, Addralign: 8, Entsize: symSize,
		},
		elf.Section64{
			Name: name(".strtab"), Type: uint32(elf.SHT_STRTAB),
			Off: strOff, Size: uint64(len(strtab)), Addralign: 1,
		})
	shstrIdx := len(sections)
	sections = append(sections, elf.Section64{
		Name: name(".shstrtab"), Type: uint32(elf.SHT_STRTAB), Addralign: 1,
	})
	sections[shstrIdx].Off = shstrOff
	sections[shstrIdx].Size = uint64(len(shstrtab))
	shOff := align(shstrOff+uint64(len(shstrtab)), 8)

	hdr := elf.Header64{
		Type: uint16(elf.ET_DYN), Machine: uint16(fx.machine), Version: uint32(elf.EV_CURRENT),
		Phoff: ehdrSize, Shoff: shOff, Ehsize: ehdrSize,
		Phentsize: phdrSize, Phnum: uint16(len(progs)), //nolint:gosec // G115: a few test headers
		Shentsize: shdrSize, Shnum: uint16(len(sections)), Shstrndx: uint16(shstrIdx), //nolint:gosec // G115: a few test sections
	}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})

	file := make([]byte, shOff+uint64(len(sections)*shdrSize))
	put := func(off uint64, v any) {
		var b bytes.Buffer
		require.NoError(t, binary.Write(&b, bo, v))
		copy(file[off:], b.Bytes())
	}
	put(0, hdr)
	put(ehdrSize, progs)
	copy(file[noteOff:], note)
	put(symOff, syms)
	copy(file[strOff:], strtab)
	copy(file[shstrOff:], shstrtab)
	put(shOff, sections)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, file, 0o600))
}

// classicLayout is the classic layout: the executable segment starts at file
// offset 0 and virtual address 0.
func classicLayout(buildID []byte) elfFixture {
	return elfFixture{
		machine: elf.EM_AARCH64, textOff: 0, textVaddr: 0, textSize: 0x3000, buildID: buildID,
		funcs: []fixtureFunc{
			{name: "hot_leaf", off: 0x1000, size: 0x40},
			{name: "second_fn", off: 0x1800, size: 0x80},
		},
	}
}

// newSymbolTable parses the ELF file at path, as the processor parses a
// candidate it has opened.
func newSymbolTable(path string) (*symbolTable, error) {
	f, err := os.Open(path) //nolint:gosec // G703: test-controlled temp file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readSymbolTable(f)
}

// --- C fixtures --------------------------------------------------------------

// cCompiler returns the C compiler that the fixtures are built with, and skips
// the test where there is none.
func cCompiler(t *testing.T) string {
	t.Helper()
	for _, cc := range []string{"cc", "gcc"} {
		if _, err := exec.LookPath(cc); err == nil {
			return cc
		}
	}
	t.Skip("no C compiler (cc or gcc) to build the test binaries")
	return ""
}

// buildNoBuildIDBinary compiles the same tiny C program as buildTestBinaryWith,
// non-PIE, but linked with -Wl,--build-id=none: a real linker output with a
// full .symtab and no GNU build ID. It returns the path and an address a few
// bytes into hot_leaf.
func buildNoBuildIDBinary(t *testing.T) (string, uint64) {
	t.Helper()
	return buildNoBuildIDBinaryWith(t, "")
}

// buildNoBuildIDBinaryWith adds extra C code to the program. Two builds of the
// same source can have the same htlhash, because the htlhash does not read the
// middle of the file, where the debug info that differs between them is.
// Extra code changes the sizes of sections, which the section header table at
// the end of the file holds, and so the htlhash.
func buildNoBuildIDBinaryWith(t *testing.T, extra string) (string, uint64) {
	t.Helper()
	cc := cCompiler(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "prog.c")
	bin := filepath.Join(dir, "prog-no-build-id")
	require.NoError(t, os.WriteFile(src, []byte(`
#include <stdio.h>
__attribute__((noinline)) long hot_leaf(long n){ long a=0; for(long i=0;i<n;i++) a+=i; return a; }
int main(void){ printf("%ld\n", hot_leaf(1000)); return 0; }
`+extra), 0o600))
	out, err := exec.Command(cc, "-O0", "-fno-inline", "-g", "-no-pie", "-Wl,--build-id=none", "-o", bin, src).CombinedOutput()
	require.NoError(t, err, "compile failed: %s", out)

	st, err := newSymbolTable(bin)
	require.NoError(t, err)
	require.Empty(t, st.buildID, "the fixture must have no GNU build ID")
	for _, r := range st.ranges {
		if r.name == "hot_leaf" {
			return bin, r.start + 4
		}
	}
	t.Fatalf("hot_leaf not found in symbol table of %s", bin)
	return "", 0
}

// htlhashOf returns the htlhash of a file as the semantic conventions define
// process.executable.build_id.htlhash, computed here independently of the
// processor's streaming implementation: the whole file is read, and the head,
// the tail and the length are hashed.
func htlhashOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	n := min(len(data), 4096)
	h := sha256.New()
	h.Write(data[:n])
	h.Write(data[len(data)-n:])
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(data))))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// --- a sender's view of a mapping --------------------------------------------

// senderMapping returns the mapping that a sender reporting addresses in the
// file's ELF virtual-address space sends for the executable segment of the file
// at path, which the kernel maps from file offset mapsOffset for length bytes:
// memory_start is the virtual address at which file offset mapsOffset is
// loaded, read here from the file's program headers. It carries both
// identities, the GNU build ID (when the file has one) and the htlhash.
func senderMapping(t *testing.T, path string, mapsOffset, length uint64) fxMapping {
	t.Helper()
	ef, err := elf.Open(path)
	require.NoError(t, err)
	defer ef.Close()
	ps := uint64(os.Getpagesize()) //nolint:gosec // G115: the page size is positive
	var start uint64
	found := false
	for _, p := range ef.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		if mapsOffset >= p.Off&^(ps-1) && mapsOffset < p.Off+p.Filesz {
			start, found = p.Vaddr-(p.Off-mapsOffset), true
			break
		}
	}
	require.True(t, found, "no executable segment holds offset %#x", mapsOffset)
	return fxMapping{
		filename: filepath.Base(path),
		gnu:      readBuildID(ef),
		htlhash:  htlhashOf(t, path),
		start:    start,
		limit:    start + length,
		offset:   mapsOffset,
	}
}

// runtimeView returns the same mapping as a sender reporting runtime addresses
// sends it, for a process that loaded the mapping at base: memory_start and
// memory_limit move to base, and so does every frame address (see runtimeAddr).
func runtimeView(m fxMapping, base uint64) fxMapping {
	m.limit = base + (m.limit - m.start)
	m.start = base
	return m
}

// runtimeAddr returns the runtime address of the ELF virtual address va in the
// mapping elfView, loaded at base.
func runtimeAddr(elfView fxMapping, base, va uint64) uint64 {
	return base + (va - elfView.start)
}

// kernelMapping returns the file offset and the length with which the kernel
// maps the executable segment of fx: from the page that holds its first byte to
// the end of the page that holds its last byte.
func kernelMapping(fx elfFixture) (uint64, uint64) {
	ps := uint64(os.Getpagesize()) //nolint:gosec // G115: the page size is positive
	mapsOffset := fx.textOff &^ (ps - 1)
	return mapsOffset, align(fx.textOff+fx.textSize, ps) - mapsOffset
}

// --- payloads ----------------------------------------------------------------

// fxMapping is one mapping of a test payload.
type fxMapping struct {
	filename     string
	gnu, htlhash string
	start, limit uint64
	offset       uint64
}

// fxLocation is one native location with no lines, in mapping `mapping` (an
// index into the mappings of buildPayload).
type fxLocation struct {
	mapping int
	addr    uint64
}

// fxResource is one process: its process.pid (0: none), its
// process.executable.path ("": none), and the locations it sampled, one sample
// each.
type fxResource struct {
	pid  int64
	exe  string
	locs []int
}

// buildPayload builds a Profiles payload: a shared dictionary whose index 0
// entries are empty, the semantic-convention attribute keys, native frame
// types, and one ResourceProfiles per process. Location i of locs is
// dictionary location i+1.
func buildPayload(mappings []fxMapping, locs []fxLocation, resources []fxResource) pprofile.Profiles {
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

	mapTab := dict.MappingTable()
	mapTab.AppendEmpty()
	for _, m := range mappings {
		pm := mapTab.AppendEmpty()
		pm.SetFilenameStrindex(str(m.filename))
		pm.SetMemoryStart(m.start)
		pm.SetMemoryLimit(m.limit)
		pm.SetFileOffset(m.offset)
		if m.gnu != "" {
			pm.AttributeIndices().Append(attr(string(semconv.ProcessExecutableBuildIDGNUKey), m.gnu))
		}
		if m.htlhash != "" {
			pm.AttributeIndices().Append(attr(string(semconv.ProcessExecutableBuildIDHtlhashKey), m.htlhash))
		}
	}

	native := attr(string(semconv.ProfileFrameTypeKey), "native")
	locTab := dict.LocationTable()
	locTab.AppendEmpty()
	stackTab := dict.StackTable()
	stackTab.AppendEmpty()
	for _, l := range locs {
		loc := locTab.AppendEmpty()
		loc.SetMappingIndex(int32(l.mapping + 1)) //nolint:gosec // G115: a few test mappings
		loc.SetAddress(l.addr)
		loc.AttributeIndices().Append(native)
		stackTab.AppendEmpty().LocationIndices().Append(i32(locTab.Len() - 1))
	}

	for _, r := range resources {
		rp := pd.ResourceProfiles().AppendEmpty()
		if r.pid != 0 {
			rp.Resource().Attributes().PutInt(string(semconv.ProcessPIDKey), r.pid)
		}
		if r.exe != "" {
			rp.Resource().Attributes().PutStr(string(semconv.ProcessExecutablePathKey), r.exe)
		}
		prof := rp.ScopeProfiles().AppendEmpty().Profiles().AppendEmpty()
		for _, li := range r.locs {
			prof.Samples().AppendEmpty().SetStackIndex(i32(li + 1))
		}
	}
	return pd
}

// locationName returns the name written on location i of buildPayload's locs,
// or "" when it has none.
func locationName(pd pprofile.Profiles, i int) string {
	dict := pd.Dictionary()
	loc := dict.LocationTable().At(i + 1)
	if loc.Lines().Len() == 0 {
		return ""
	}
	fn := dict.FunctionTable().At(int(loc.Lines().At(0).FunctionIndex()))
	return dict.StringTable().At(int(fn.NameStrindex()))
}

// addNamedFrame adds to a buildPayload payload one frame that the sender
// already named: a Function with a name and, when file is not "", a source
// file, and a Location of frameType with one Line. A new stack holds it above
// location nativeLoc of locs, and resource ri samples that stack once. It
// returns the index of the Function.
func addNamedFrame(pd pprofile.Profiles, ri, nativeLoc int, name, file, frameType string) int32 {
	dict := pd.Dictionary()
	strTab := dict.StringTable()
	str := func(s string) int32 {
		strTab.Append(s)
		return i32(strTab.Len() - 1)
	}
	funcTab := dict.FunctionTable()
	if funcTab.Len() == 0 {
		funcTab.AppendEmpty() // index 0 is the empty Function
	}
	fn := funcTab.AppendEmpty()
	fn.SetNameStrindex(str(name))
	if file != "" {
		fn.SetFilenameStrindex(str(file))
	}
	fi := i32(funcTab.Len() - 1)

	kv := dict.AttributeTable().AppendEmpty()
	kv.SetKeyStrindex(str(string(semconv.ProfileFrameTypeKey)))
	kv.Value().SetStr(frameType)
	loc := dict.LocationTable().AppendEmpty()
	loc.Lines().AppendEmpty().SetFunctionIndex(fi)
	loc.AttributeIndices().Append(i32(dict.AttributeTable().Len() - 1))

	stk := dict.StackTable().AppendEmpty()
	stk.LocationIndices().Append(i32(nativeLoc+1), i32(dict.LocationTable().Len()-1))
	prof := pd.ResourceProfiles().At(ri).ScopeProfiles().At(0).Profiles().At(0)
	prof.Samples().AppendEmpty().SetStackIndex(i32(dict.StackTable().Len() - 1))
	return fi
}

// locationFunction returns the Function index, the name and the source file
// that location i of buildPayload's locs points at.
func locationFunction(t *testing.T, pd pprofile.Profiles, i int) (int32, string, string) {
	t.Helper()
	dict := pd.Dictionary()
	loc := dict.LocationTable().At(i + 1)
	require.Equal(t, 1, loc.Lines().Len(), "location %d must be named", i)
	fi := loc.Lines().At(0).FunctionIndex()
	fn := dict.FunctionTable().At(int(fi))
	return fi, dict.StringTable().At(int(fn.NameStrindex())), dict.StringTable().At(int(fn.FilenameStrindex()))
}

// --- a fake /proc ------------------------------------------------------------

// fakeProc is /proc/<pid> of one process under a root_path_prefix: a root
// directory, a maps file, map_files links and an exe link.
type fakeProc struct {
	t      *testing.T
	prefix string
	pid    int64
	dir    string
	root   string
	maps   bytes.Buffer
}

func newFakeProc(t *testing.T, prefix string, pid int64) *fakeProc {
	t.Helper()
	dir := filepath.Join(prefix, "proc", fmt.Sprint(pid))
	p := &fakeProc{t: t, prefix: prefix, pid: pid, dir: dir, root: filepath.Join(dir, "root")}
	require.NoError(t, os.MkdirAll(p.root, 0o755))
	return p
}

// inRoot returns the host path of a path inside the process's root.
func (p *fakeProc) inRoot(path string) string { return filepath.Join(p.root, path) }

// mapExec adds an executable maps line for path (a path inside the root) at
// runtime address start, and returns the line's end address.
func (p *fakeProc) mapExec(start, offset, length uint64, path string) uint64 {
	end := start + length
	fmt.Fprintf(&p.maps, "%x-%x r-xp %08x 103:01 4711 %s\n", start, end, offset, path)
	return end
}

// mapLine adds a raw maps line.
func (p *fakeProc) mapLine(line string) { p.maps.WriteString(line + "\n") }

// linkMapFile adds /proc/<pid>/map_files/<start>-<end>, pointing at target.
func (p *fakeProc) linkMapFile(start, end uint64, target string) {
	dir := filepath.Join(p.dir, "map_files")
	require.NoError(p.t, os.MkdirAll(dir, 0o755))
	require.NoError(p.t, os.Symlink(target, filepath.Join(dir, fmt.Sprintf("%x-%x", start, end))))
}

// linkExe adds /proc/<pid>/exe, pointing at target.
func (p *fakeProc) linkExe(target string) {
	require.NoError(p.t, os.Symlink(target, filepath.Join(p.dir, "exe")))
}

// writeMaps writes the maps lines added so far.
func (p *fakeProc) writeMaps() {
	require.NoError(p.t, os.WriteFile(filepath.Join(p.dir, "maps"), p.maps.Bytes(), 0o400))
}

// requireOpenat2 skips a test that needs openat2(2) where it cannot run: on a
// kernel without it (before Linux 5.6, ENOSYS), or in a sandbox whose seccomp
// filter refuses it (EPERM). There, every in-root candidate fails closed.
func requireOpenat2(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	fd2, err := unix.Openat2(fd, ".", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		t.Skipf("openat2 cannot run here: %v", err)
	}
	require.NoError(t, err)
	unix.Close(fd2)
}

// --- conversions ------------------------------------------------------------

// i32 converts a test index. Test tables hold a few entries, far below the
// int32 bound of OTLP dictionary indices.
func i32(n int) int32 { return int32(n) } //nolint:gosec // G115: small test indices

// u32 converts a small test value.
func u32(n int) uint32 { return uint32(n) } //nolint:gosec // G115: small test values

// euid and egid are the test process's effective ids, as the probe reads them.
func euid() uint32 { return uint32(os.Geteuid()) } //nolint:gosec // G115: Linux ids are 32-bit

func egid() uint32 { return uint32(os.Getegid()) } //nolint:gosec // G115: Linux ids are 32-bit

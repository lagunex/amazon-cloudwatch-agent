// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

// ELF parsing and address-to-name lookup: this file turns a raw code address
// like 0x8bbc into a name like "sum_loop::hot_leaf".
//
// See doc.go for why the file's identity is checked before any address is
// trusted.

package nativesymbolizer

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
)

// errNoSymtab is returned for a binary that carries no usable text symbols
// (fully stripped). It is a DEFINITIVE answer about that FILE VERSION -- re-reading
// the same bytes will not help -- so it is negative-cached: against the file's
// fingerprint for a path key, or against the sampled content for a content key
// (see resolverCache). Contrast a failure to open the file, which is transient
// and is not cached at all.
var errNoSymtab = errors.New("no text symbols in .symtab or .dynsym")

// errSymbolTablePanic is returned when reading a file's symbol table panicked.
// debug/elf parses bytes this processor does not control, and this runs on the
// agent's profile goroutine, where an escaped panic would stop the agent on
// every pass. Like errNoSymtab it is definitive for the file
// version that caused it, so that version is cached as failed and not read again.
var errSymbolTablePanic = errors.New("reading the ELF symbol table panicked")

// funcRange is one text-symbol extent: [start, start+size).
type funcRange struct {
	start uint64
	size  uint64
	name  string
}

// loadSegment is one executable PT_LOAD program header: where a run of the file
// is loaded in the ELF virtual-address space.
type loadSegment struct {
	off    uint64
	vaddr  uint64
	filesz uint64
}

// symbolTable holds the sorted text-symbol ranges for one on-disk binary plus
// the GNU build ID read from its ELF note. It answers address -> "name+0xNN".
//
// `starts` duplicates the start address of every range into its own slice. That
// is deliberate: sort.Search needs a slice it can index cheaply, and keeping the
// keys separate from the records keeps the binary search tight.
type symbolTable struct {
	buildID string
	ranges  []funcRange // sorted ascending by start
	starts  []uint64    // parallel slice of starts for binary search
	maxSize uint64      // largest extent in ranges; bounds resolve's back-scan
	// loads are the executable PT_LOAD headers. fileOffsetToVA uses them to place
	// a mapping's file offset in the ELF virtual-address space.
	loads []loadSegment
	// size estimates the heap this table holds. max_cached_bytes is charged with it.
	size int64
}

// Heap-size estimate for a symbolTable, used by the cache's byte bound. A range
// costs its funcRange record (32 bytes), its entry in starts (8 bytes), and the
// allocation slack of the name string and of the slices that append grew. 64
// bytes per range plus the name bytes is a little above what was measured: a
// Rust binary with 60,420 text symbols and 13.7 MB of names retains 16.2 MiB,
// which is 53 bytes per range plus the names.
const (
	bytesPerRange       = 64
	bytesPerLoadSegment = 24
	symbolTableOverhead = 128
)

// buildSymbolTable is the parser behind every symbol-table read. It is a
// variable only so that a test can make it panic; production code never assigns
// it.
var buildSymbolTable = parseSymbolTable

// readSymbolTable reads the symbol table of an ELF file that is already open. A
// panic anywhere in the read is recovered and returned as errSymbolTablePanic.
func readSymbolTable(r io.ReaderAt) (*symbolTable, error) {
	var (
		st  *symbolTable
		err error
	)
	if p := recoverPanic(func() {
		var ef *elf.File
		if ef, err = elf.NewFile(r); err == nil {
			st, err = buildSymbolTable(ef)
		}
	}); p != nil {
		return nil, fmt.Errorf("%w: %v", errSymbolTablePanic, p)
	}
	return st, err
}

// recoverPanic runs fn and returns the value of a panic in fn, or nil. Every
// read of an ELF file runs under it: debug/elf parses bytes this processor does
// not control, and an escaped panic would stop the agent.
func recoverPanic(fn func()) any {
	var p any
	func() {
		defer func() { p = recover() }()
		fn()
	}()
	return p
}

// parseSymbolTable collects the text symbols, the GNU build ID and the
// executable PT_LOAD headers of a parsed ELF file. It reads .symtab first
// (richer; present on unstripped binaries), then falls back to .dynsym
// (exported symbols; the best available on a stripped binary).
func parseSymbolTable(f *elf.File) (*symbolTable, error) {
	st := &symbolTable{buildID: readBuildID(f), loads: execLoadSegments(f)}

	// An ELF symbol table holds far more than functions (variables, sections,
	// files, ...). ST_TYPE extracts the kind from the packed Info byte; only
	// STT_FUNC (an ordinary function) and STT_GNU_IFUNC (a function resolved at
	// load time, used by glibc for CPU-specific variants) are code we can name.
	//
	// Size-bearing entries only: a zero-size symbol gives no honest extent, and
	// guessing its end from the next symbol's start would silently attribute
	// inter-function padding to the preceding function.
	collect := func(syms []elf.Symbol) {
		for i := range syms {
			s := &syms[i]
			typ := elf.ST_TYPE(s.Info)
			if typ != elf.STT_FUNC && typ != elf.STT_GNU_IFUNC {
				continue
			}
			if s.Size == 0 || s.Value == 0 || s.Name == "" {
				continue
			}
			st.ranges = append(st.ranges, funcRange{s.Value, s.Size, s.Name})
		}
	}

	// Symbols() reads .symtab, DynamicSymbols() reads .dynsym. Both return an
	// error when the section is absent, which is not fatal here -- it just means
	// try the other one.
	if syms, err := f.Symbols(); err == nil {
		collect(syms)
	}
	if len(st.ranges) == 0 {
		if dyn, err := f.DynamicSymbols(); err == nil {
			collect(dyn)
		}
	}
	if len(st.ranges) == 0 {
		return nil, errNoSymtab
	}

	// Sort and derive the search structures. finalize() is the single place
	// that establishes resolve()'s invariants (deterministic order, parallel
	// starts slice, maxSize bound), so tests can build a symbolTable from
	// synthetic ranges through the same path rather than duplicating it.
	st.finalize()
	return st, nil
}

// execLoadSegments returns the executable PT_LOAD headers of f. A frame's
// mapping is executable, so these are the only segments its file offset can
// fall in.
func execLoadSegments(f *elf.File) []loadSegment {
	var out []loadSegment
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
			out = append(out, loadSegment{off: p.Off, vaddr: p.Vaddr, filesz: p.Filesz})
		}
	}
	return out
}

// finalize sorts st.ranges and builds the derived search structures that
// resolve() depends on. It is idempotent and safe to call once after ranges are
// collected.
//
// The sort is ascending by start, DETERMINISTIC among ranges that share a
// start: larger extent first, then by name. ELF symbol tables routinely contain
// overlapping or aliased function symbols -- glibc `__libc_start_main` aliases,
// ifunc pairs, or two `.symtab` entries sharing a start with different sizes.
// sort.Slice is not stable, so without an explicit tie-break the survivor among
// equal-start ranges would be arbitrary from run to run.
func (st *symbolTable) finalize() {
	sort.Slice(st.ranges, func(i, j int) bool {
		a, b := st.ranges[i], st.ranges[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.size != b.size {
			return a.size > b.size // larger extent first
		}
		return a.name < b.name
	})
	st.starts = make([]uint64, len(st.ranges))
	st.maxSize = 0
	st.size = symbolTableOverhead + int64(len(st.buildID)) +
		int64(len(st.ranges))*bytesPerRange + int64(len(st.loads))*bytesPerLoadSegment
	for i := range st.ranges {
		st.starts[i] = st.ranges[i].start
		if st.ranges[i].size > st.maxSize {
			st.maxSize = st.ranges[i].size
		}
		st.size += int64(len(st.ranges[i].name))
	}
}

// pageMask is the host page size minus one. The kernel maps a segment from the
// page that holds its first byte, so a mapping's file offset can lie up to one
// page below the segment's p_offset.
var pageMask = uint64(os.Getpagesize()) - 1

// fileOffsetToVA returns the ELF virtual address at which file offset off is
// loaded: the vaddr of the executable PT_LOAD that holds off, moved by how far
// off is from that segment's p_offset. It answers false when off is in no
// executable segment.
//
// For a sender that reports addresses in the file's ELF virtual-address space,
// the result equals the mapping's memory_start.
func (st *symbolTable) fileOffsetToVA(off uint64) (uint64, bool) {
	for _, p := range st.loads {
		aligned := p.off &^ pageMask
		if off >= aligned && off < p.off+p.filesz {
			return p.vaddr - (p.off - off), true
		}
	}
	return 0, false
}

// resolve returns the function name and byte offset for an ELF virtual address,
// or ("", 0, false) if the address is in no known function (e.g. a padding gap).
//
// ADDRESS CONVENTION. addr is compared directly against the ELF symbol's
// link-time value (st_value): it must ALREADY be an ELF virtual address. The
// caller (symbolizeLocation) produces one from the frame address and the
// mapping: addr - memory_start + the virtual address of the mapping's file
// offset. So no load-bias subtraction belongs here, and
// TestAddressConventionIsFileRelative pins that a load-biased address does not
// resolve on its own.
func (st *symbolTable) resolve(addr uint64) (string, uint64, bool) {
	// Find the last symbol whose start is <= addr.
	//
	// sort.Search returns the FIRST index where the predicate is true, i.e. the
	// first symbol starting strictly after addr. Subtracting 1 steps back to the
	// last one starting at or before it. -1 means addr precedes every symbol.
	i := sort.Search(len(st.starts), func(k int) bool { return st.starts[k] > addr }) - 1
	if i < 0 {
		return "", 0, false
	}
	// A single binary-search hit is NOT enough when symbols overlap. ELF symbol
	// tables routinely contain overlapping/aliased functions: a smaller alias
	// (an ifunc entry, a `__libc_start_main` alias, a zero-region label with a
	// small size) can start at or after a larger enclosing function's start but
	// end before addr. Index i is merely the last range whose start <= addr; if
	// that range is a short alias, addr falls in its gap and a naive check would
	// report "no symbol" even though a covering enclosing function exists a few
	// entries back.
	//
	// So scan backward from i over ranges whose start <= addr and keep the one
	// that (a) actually covers addr and (b) has the SMALLEST extent among the
	// covering ranges -- the tightest enclosing symbol is the most specific name
	// for the address, and any cover at all avoids the false "no symbol" miss.
	//
	// The scan is bounded by maxSize (the largest extent in the table): once a
	// range starts more than maxSize below addr, no earlier range can possibly
	// reach addr, so iteration stops. In the common non-overlapping case the
	// k == i entry either covers addr (done immediately) or the next few do not,
	// and the maxSize bound halts the scan quickly -- so a padding-gap miss stays
	// close to O(1) rather than walking the whole table.
	var (
		best     funcRange
		haveBest bool
	)
	for k := i; k >= 0; k-- {
		r := st.ranges[k]
		// Stop once even the widest symbol starting here could not reach addr.
		// r.start <= addr for all k <= i, so addr-r.start is non-negative.
		if addr-r.start >= st.maxSize {
			break
		}
		if addr < r.start+r.size { // r covers addr
			if !haveBest || r.size < best.size {
				best = r
				haveBest = true
			}
		}
	}
	if !haveBest {
		return "", 0, false
	}
	// The offset is returned so a caller can render "name+0x2c" and tell two
	// samples inside the same function apart.
	return best.name, addr - best.start, true
}

// readBuildID extracts the GNU build ID (hex) from .note.gnu.build-id, or ""
// if absent. debug/elf exposes sections but does not decode notes, so the
// section is parsed by hand.
//
// An ELF note is a small tagged record with this layout:
//
//	namesz  uint32   length of name, including its NUL
//	descsz  uint32   length of the payload ("descriptor")
//	type    uint32   what kind of note this is
//	name    [namesz] e.g. "GNU\0", padded up to a 4-byte boundary
//	desc    [descsz] the payload -- here, the build-ID bytes
//
// The build ID is those raw desc bytes; it is conventionally shown as hex, which
// is what `readelf -n` and `file` print, so hex is what we compare.
func readBuildID(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil || len(data) < 16 {
		return ""
	}
	// Note layout: namesz(4) descsz(4) type(4) name(namesz, padded to 4) desc.
	bo := f.ByteOrder
	namesz := bo.Uint32(data[0:4])
	descsz := bo.Uint32(data[4:8])
	// (namesz+3) &^ 3 rounds up to the next multiple of 4. &^ is Go's AND-NOT
	// operator, so this clears the low two bits. 12 is the three header words.
	nameEnd := 12 + int((namesz+3)&^3)
	if nameEnd+int(descsz) > len(data) {
		return ""
	}
	desc := data[nameEnd : nameEnd+int(descsz)]
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(desc)*2)
	for _, b := range desc {
		out = append(out, hexdigits[b>>4], hexdigits[b&0xf])
	}
	return string(out)
}

// resolverCache is a bounded, concurrency-safe cache of parsed symbol tables.
// It bounds host memory: a host runs many distinct binaries and a symbol table
// can be tens of megabytes, so max_cached_binaries and max_cached_bytes are the
// knobs that keep this affordable next to the workloads it profiles.
//
// TWO KINDS OF KEY share one LRU:
//
//   - A CONTENT key names the file the sender sampled by its content: the
//     mapping's htlhash (with its GNU build ID, when it has one), or its GNU build
//     ID alone. A table is stored under a content key only after a candidate file
//     proved that identity, so the entry describes those exact bytes and can
//     never go stale -- a hit needs no stat. Every process that maps the same
//     library, and the processor instance of each pipeline, share the one entry.
//   - A PATH key names one file on disk and carries the file's fingerprint
//     (device, inode, mtime, size). get(path) and require_build_id_match: false
//     use it, and so does the record of a file version whose read panicked.
//
// Content keys start with a NUL byte, which no path can contain, so the two
// kinds never collide.
//
// NEGATIVE CACHING IS SELECTIVE. Only a DEFINITIVE failure is latched: errNoSymtab
// (the file was read fine and genuinely carries no text symbols) and
// errSymbolTablePanic. Re-reading such a file cannot change the answer, so a nil
// entry avoids re-parsing a hot stripped mapping on every report.
//
// A transient failure is NOT cached: opening can fail because the target
// process (and therefore /proc/<pid>/...) has just exited, or because the file
// was mid-write when first read. Latching those would permanently blind the
// processor to a path that becomes readable a second later.
//
// STALENESS of a path key. The agent is long-lived and a path can be
// redeployed under it (an unstripped binary replacing a stripped one, or a new
// build replacing an old). A path entry is only honored while the opened file's
// fingerprint still matches the one recorded at parse time, so neither a stale
// "stripped" verdict nor a stale table can outlive the file it describes.
type cacheEntry struct {
	table *symbolTable    // nil means definitively unusable (stripped, or its read panicked)
	fp    fileFingerprint // path keys only: the file version the entry describes
	size  int64           // bytes charged to max_cached_bytes; computed by insert when 0
}

// fileFingerprint identifies a file version cheaply. A redeploy always rewrites
// the file, which changes its mtime and size (or, for a rename into place, its
// inode).
type fileFingerprint struct {
	dev, ino    uint64
	modUnixNano int64
	size        int64
	ok          bool // false when the file could not be stat'd
}

// cacheEntryOverhead is the per-entry cost of the map slot, the LRU slot and the
// key, charged on top of the table.
const cacheEntryOverhead = 96

type resolverCache struct {
	mu       sync.Mutex
	entries  map[string]cacheEntry
	order    []string // simple LRU: most-recently-used appended at the end
	capacity int
	maxBytes int64 // 0 means no byte bound
	bytes    int64 // sum of the size of every entry
}

// newResolverCache returns a cache bounded by entry count only.
func newResolverCache(capacity int) *resolverCache {
	return newResolverCacheBytes(capacity, 0)
}

// newResolverCacheBytes returns a cache bounded by entry count and, when
// maxBytes > 0, by the estimated bytes of its entries. maxBytes 0 is
// max_cached_bytes: 0, which turns the byte bound off.
func newResolverCacheBytes(capacity int, maxBytes int64) *resolverCache {
	if capacity < 1 {
		capacity = 1
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	return &resolverCache{
		entries:  make(map[string]cacheEntry, capacity),
		capacity: capacity,
		maxBytes: maxBytes,
	}
}

// get returns the cached table for path, parsing and inserting it on a miss.
// A nil table means "no symbols available for this path right now". Only a
// definitive result (errNoSymtab, errSymbolTablePanic) is remembered; a
// transient open/IO failure is returned without being cached so the next report
// retries it. A cached entry whose on-disk fingerprint has changed (redeploy) is
// discarded and re-parsed.
func (c *resolverCache) get(path string) (*symbolTable, bool) {
	st, cached, _ := c.getFile(candidate{path: path}, nil)
	return st, cached
}

// getFile is get for any candidate: an in-root candidate is opened without
// leaving its root. onParse, when not nil, is called after each parse with the
// parse error (nil on success), so that the caller can count parses and panics.
func (c *resolverCache) getFile(cand candidate, onParse func(error)) (*symbolTable, bool, error) {
	f, fp, err := cand.open()
	if err != nil {
		return nil, false, err // transient: not cached, retried next time
	}
	defer f.Close()
	if e, ok := c.lookupFile(cand.path, fp); ok {
		return e.table, true, nil
	}
	st, err := readSymbolTable(f)
	if onParse != nil {
		onParse(err)
	}
	if err != nil {
		if errors.Is(err, errNoSymtab) || errors.Is(err, errSymbolTablePanic) {
			// Definitive for THIS file version: latch it against the fingerprint
			// so that a later redeploy re-parses.
			c.store(cand.path, cacheEntry{fp: fp})
		}
		return nil, false, err
	}
	c.store(cand.path, cacheEntry{table: st, fp: fp})
	return st, false, nil
}

// lookupContent returns the entry under a content key. A content entry never
// goes stale, so there is nothing to check.
func (c *resolverCache) lookupContent(key string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if ok {
		c.touch(key)
	}
	return e, ok
}

// lookupFile returns the entry under a path key while fp still matches the file
// version it was recorded for. A stale entry is dropped.
func (c *resolverCache) lookupFile(key string, fp fileFingerprint) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return cacheEntry{}, false
	}
	if fp.ok && e.fp.ok && fp == e.fp {
		c.touch(key)
		return e, true
	}
	c.remove(key)
	return cacheEntry{}, false
}

// store inserts or replaces an entry and then enforces both bounds.
func (c *resolverCache) store(key string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.insert(key, e)
}

func (c *resolverCache) remove(key string) {
	if e, ok := c.entries[key]; ok {
		c.bytes -= e.size
		delete(c.entries, key)
	}
	for i, p := range c.order {
		if p == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

func (c *resolverCache) touch(key string) {
	for i, p := range c.order {
		if p == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, key)
}

// insert adds an entry and evicts least-recently-used entries until both bounds
// hold. The caller holds c.mu (or owns c alone, as a test does).
//
// The entry just inserted is never evicted, even when it alone is larger than
// max_cached_bytes. Such an oversized entry evicts every other entry when it is
// stored, and it is the oldest entry when the next one is stored, so that store
// evicts it. So a byte bound below one table, or below the tables that one
// report needs, makes those tables evict each other, and every pass parses them
// again. symbol_tables_parsed shows it.
func (c *resolverCache) insert(key string, e cacheEntry) {
	if e.size == 0 {
		e.size = cacheEntryOverhead + int64(len(key))
		if e.table != nil {
			e.size += e.table.size
		}
	}
	if old, present := c.entries[key]; present {
		c.bytes -= old.size
	}
	c.entries[key] = e
	c.bytes += e.size
	c.touch(key)
	for len(c.order) > 1 && (len(c.entries) > c.capacity || (c.maxBytes > 0 && c.bytes > c.maxBytes)) {
		oldest := c.order[0]
		c.order = c.order[1:]
		c.bytes -= c.entries[oldest].size
		delete(c.entries, oldest)
	}
}

// len reports the current number of cached entries (for tests/metrics).
func (c *resolverCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// stats reports the number of entries and the bytes charged to the byte bound.
func (c *resolverCache) stats() (int, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.bytes
}

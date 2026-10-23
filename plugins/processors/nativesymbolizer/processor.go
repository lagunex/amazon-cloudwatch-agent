// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package nativesymbolizer

import (
	"context"
	"debug/elf"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.uber.org/zap"
)

// The OTel semantic-convention attributes that the processor reads from
// resources, mappings and locations. They are its whole contract with the
// sender.
const (
	attrExecutablePath    = string(semconv.ProcessExecutablePathKey)
	attrExecutableName    = string(semconv.ProcessExecutableNameKey)
	attrPID               = string(semconv.ProcessPIDKey)
	attrMappingBuildIDGnu = string(semconv.ProcessExecutableBuildIDGNUKey)
	attrMappingHtlhash    = string(semconv.ProcessExecutableBuildIDHtlhashKey)
	attrFrameType         = string(semconv.ProfileFrameTypeKey)
	frameTypeNative       = "native"
)

// symbolizer holds the per-instance state: config, the symbol-table cache and
// privileges it shares with the instances of the other pipelines, logger, and
// counters exposed for self-telemetry.
//
// The frame counters are designed to ACCOUNT FOR EVERY SEEN FRAME, so an
// operator can subtract and get zero:
//
//	framesSeen = framesResolved + framesNoCandidate + framesNoBuildID
//	           + buildIDMismatch + htlhashMismatch + mappingBiasUnexpected
//	           + framesNoSymbol + permissionDenied
//
// An unexplained residual would mean a miss path exists with no counter, which
// is exactly the kind of blind spot that makes "profiles look fine but frames
// are missing" hard to diagnose. framesResolvedByHtlhash is not a bucket of its
// own: it is the part of framesResolved whose file has no GNU build ID and was
// matched by its htlhash instead. symbolTablesParsed, symbolTablePanics and
// procMapsReads count work on files, not frames.
type symbolizer struct {
	cfg    *Config
	cache  *resolverCache
	shared *sharedState
	priv   privileges
	log    *zap.Logger

	framesSeen     atomic.Uint64
	framesResolved atomic.Uint64
	// framesResolvedByHtlhash counts resolved frames whose identity was proven by
	// the htlhash, because the file has no GNU build ID.
	framesResolvedByHtlhash atomic.Uint64
	framesNoBuildID         atomic.Uint64
	buildIDMismatch         atomic.Uint64
	// htlhashMismatch counts frames of a file with no GNU build ID where every
	// file found had a different htlhash: the file on disk is not the one the
	// sender sampled.
	htlhashMismatch atomic.Uint64
	// framesNoCandidate counts frames whose binary was not found or not
	// parseable at ANY candidate path. Expected to be the most common miss in
	// practice: the sampled process may have exited before the report, or it
	// runs on another host or in a pid namespace the agent cannot see.
	framesNoCandidate atomic.Uint64
	// permissionDenied counts frames left unnamed because the agent may not
	// read what would name them: a candidate failed with EACCES or EPERM, or
	// limited mode skipped the /proc entry of a process of another user (see
	// privilege.go).
	permissionDenied atomic.Uint64
	// framesNoSymbol counts frames whose binary WAS found and matched, but whose
	// address fell in no function extent (e.g. alignment padding, or a region
	// with no symbol such as a PLT stub).
	framesNoSymbol atomic.Uint64
	// mappingBiasUnexpected counts frames refused by the address guard: the frame
	// address is outside its mapping, or the mapping's file offset is in no
	// executable segment of the file. Either means the address cannot be placed
	// in the file with confidence, and a guess would be a wrong name.
	mappingBiasUnexpected atomic.Uint64

	symbolTablesParsed atomic.Uint64
	symbolTablePanics  atomic.Uint64
	procMapsReads      atomic.Uint64

	// candidateWalks counts how often a mapping's candidate files were walked.
	// Not exported; tests use it to prove that one mapping is resolved at most
	// once per pass.
	candidateWalks atomic.Uint64

	passes       atomic.Uint64
	summaryEvery uint64
	metrics      *selfMetrics

	// diagnosed bounds the miss diagnostic log (see diagnoseMiss).
	//
	// It is keyed by the mapping filename plus the root and executable path the
	// candidates were derived from, because the candidate paths the diagnostic
	// reports depend on all three. Keying on the filename alone would mean that
	// two containerized processes sharing a basename diagnose whichever context
	// failed first and permanently suppress the other, which is the multi-root
	// case the diagnostic exists to explain.
	//
	// diagnosedPerFile then bounds how many contexts ONE filename may report,
	// because no_candidate is the correct and permanent outcome for a mapping
	// with no file on disk: `linux-vdso.1.so` is mapped into every process, so
	// on the composite key alone it would produce an entry per process and
	// exhaust the budget before a real miss ever reached the log.
	diagnosedMu      sync.Mutex
	diagnosed        map[diagKey]struct{}
	diagnosedPerFile map[string]int
}

// diagKey identifies one resolution context for the no_candidate diagnostic.
type diagKey struct {
	filename string
	root     string
	exePath  string
}

// newSymbolizer builds a symbolizer with a cache of its own and no metrics. The
// factory uses newSymbolizerShared instead, so that the instances of all
// pipelines share one cache and export their counters.
func newSymbolizer(cfg *Config, log *zap.Logger) *symbolizer {
	// No fallback for a zero/negative bound here: Config.Validate rejects
	// max_cached_binaries <= 0 before the collector ever builds the processor,
	// so cfg.MaxCachedBinaries is guaranteed positive on this path. Keeping a
	// silent 0 -> 256 substitution would be a second, conflicting source of
	// truth for the floor (newResolverCache clamps < 1 to 1), which is exactly
	// the ambiguity we want to avoid.
	return newSymbolizerShared(cfg, log, newSharedState(cfg))
}

func newSymbolizerShared(cfg *Config, log *zap.Logger, shared *sharedState) *symbolizer {
	return &symbolizer{
		cfg:          cfg,
		cache:        shared.cache,
		shared:       shared,
		priv:         shared.priv,
		log:          log,
		summaryEvery: summaryEveryPasses,
	}
}

// mappingInfo is what one mapping of the shared dictionary says about its file.
type mappingInfo struct {
	filename string // as reported by the sender: a basename or an absolute path
	buildID  string // GNU build ID, "" when the file has none
	htlhash  string // the sender's htlhash of the file, "" when absent
	native   bool
	// memoryStart, memoryLimit and fileOffset place the mapping: the addresses
	// of [memory_start, memory_limit) are loaded from file_offset. A sender may
	// report them as runtime addresses or in the file's ELF virtual-address
	// space; symbolizeLocation handles both.
	memoryStart uint64
	memoryLimit uint64
	fileOffset  uint64
}

// noRange reports whether the mapping carries no address range at all:
// memory_start, memory_limit and file_offset are all 0. Such a mapping says
// nothing about where it was loaded, so its frame addresses are taken to be
// ELF virtual addresses already. A mapping with only some of the three fields
// set is not this shape, and it gets the range check like any other.
func (m mappingInfo) noRange() bool {
	return m.memoryStart == 0 && m.memoryLimit == 0 && m.fileOffset == 0
}

// contains reports whether addr is inside [memory_start, memory_limit).
func (m mappingInfo) contains(addr uint64) bool {
	return addr >= m.memoryStart && addr < m.memoryLimit
}

// contentKey names the sampled file by its content, for the cache. It is ""
// when the mapping carries no identity at all.
func (m mappingInfo) contentKey() string {
	switch {
	case m.htlhash != "":
		return "\x00htlhash:" + strings.ToLower(m.htlhash) + "\x00gnu:" + strings.ToLower(m.buildID)
	case m.buildID != "":
		return "\x00gnu:" + strings.ToLower(m.buildID)
	}
	return ""
}

// missIdentity names the mapping for the miss memo: its content key, or its
// filename when it has no identity.
func (m mappingInfo) missIdentity() string {
	if k := m.contentKey(); k != "" {
		return k
	}
	return "\x00file:" + m.filename
}

// passState is the state of one processProfiles call.
type passState struct {
	// resolved holds the table of every mapping resolved in this pass, by mapping
	// index. A mapping carries the identity of its file, and a table is only
	// stored for a file that proved it, so after one success every later
	// location of that mapping reuses the table, in whatever process.
	resolved map[int]*symbolTable
	// maps holds the parsed /proc/<pid>/maps of each process read in this pass,
	// and mapsErr the error of each read that failed.
	maps    map[string][]mapsLine
	mapsErr map[string]error
}

// resolution is the outcome of resolving one mapping in one process context.
type resolution struct {
	table   *symbolTable
	outcome resolveOutcome
}

// processProfiles is the ProcessProfilesFunc. It walks every profile, finds
// native locations with no `lines`, resolves them against the on-disk binary,
// and writes the resulting function name back into the shared dictionary so a
// downstream backend renders it. Frames it cannot name are left as they
// arrived, and it never drops data or returns an error.
//
// PID-NAMESPACE ANCHORING. A mapping's filename is often only a BASENAME (e.g.
// "libc.so.6"), and the profiled process frequently lives in a container whose
// root differs from the agent's. The file is therefore found from the process
// that a resource profile describes, through its process.pid and
// process.executable.path: see candidates for the paths, in order. The pid is
// read in the agent's pid namespace, so the sender must profile processes that
// the agent can see.
func (s *symbolizer) processProfiles(ctx context.Context, pd pprofile.Profiles) (pprofile.Profiles, error) {
	if s.priv.mode == modeInactive {
		return pd, nil
	}
	dict := pd.Dictionary()
	strTab := dict.StringTable()
	funcTab := dict.FunctionTable()
	locTab := dict.LocationTable()
	mapTab := dict.MappingTable()
	attrTab := dict.AttributeTable()
	stackTab := dict.StackTable()

	// internString returns the index of v in the string table, appending it if
	// absent. The map avoids an O(n) scan of a table that can hold thousands of
	// entries, once per frame.
	strIndex := buildStringIndex(strTab)
	internString := func(v string) int32 {
		if idx, ok := strIndex[v]; ok {
			return idx
		}
		strTab.Append(v)
		idx := int32(strTab.Len() - 1) //nolint:gosec // G115: OTLP dictionary indices are int32, so the table is never longer
		strIndex[v] = idx
		return idx
	}

	// internFunction is the same idea one level up, keyed by the function's
	// name-string index. Without it, a symbol appearing in a hundred stacks
	// would add a hundred identical Function rows.
	//
	// Only a Function that holds a name and nothing else is reused. A sender
	// may write a Function with a source file for an interpreted frame, and a
	// Python function can have the name of a C function (read, write, poll,
	// main). A native frame that points at that Function would show the Python
	// file as its own source file.
	funcByName := make(map[int32]int32, funcTab.Len())
	for i := 0; i < funcTab.Len(); i++ {
		f := funcTab.At(i)
		if f.FilenameStrindex() != 0 || f.SystemNameStrindex() != 0 || f.StartLine() != 0 {
			continue
		}
		funcByName[f.NameStrindex()] = int32(i)
	}
	internFunction := func(nameIdx int32) int32 {
		if fi, ok := funcByName[nameIdx]; ok {
			return fi
		}
		fn := funcTab.AppendEmpty()
		fn.SetNameStrindex(nameIdx)
		fi := int32(funcTab.Len() - 1) //nolint:gosec // G115: OTLP dictionary indices are int32, so the table is never longer
		funcByName[nameIdx] = fi
		return fi
	}

	// Read each mapping's identity and range once (shared across resources).
	mapInfos := make([]mappingInfo, mapTab.Len())
	for i := 0; i < mapTab.Len(); i++ {
		m := mapTab.At(i)
		fn := stringAt(strTab, m.FilenameStrindex())
		mapInfos[i] = mappingInfo{
			filename:    fn,
			buildID:     attrValue(attrTab, strTab, m.AttributeIndices(), attrMappingBuildIDGnu),
			htlhash:     attrValue(attrTab, strTab, m.AttributeIndices(), attrMappingHtlhash),
			native:      fn != "",
			memoryStart: m.MemoryStart(),
			memoryLimit: m.MemoryLimit(),
			fileOffset:  m.FileOffset(),
		}
	}

	pass := &passState{
		resolved: make(map[int]*symbolTable),
		maps:     make(map[string][]mapsLine),
		mapsErr:  make(map[string]error),
	}

	// symbolizeLocation resolves one location for a given process context and
	// writes a Line back on success.
	symbolizeLocation := func(loc pprofile.Location, pc procContext) {
		// A non-empty Lines means this frame ALREADY has a name: the sender named
		// it (kernel frames, Go frames, interpreted frames). Never overwrite
		// that -- the sender's data is richer than a symbol-table lookup.
		if loc.Lines().Len() > 0 {
			return
		}
		// Only touch frames that are native, or that carry no frame type at
		// all. An interpreted or JIT frame that happens to be unnamed is not
		// ours to resolve.
		ft := attrValue(attrTab, strTab, loc.AttributeIndices(), attrFrameType)
		if ft != "" && ft != frameTypeNative {
			return
		}
		mi := int(loc.MappingIndex())
		// Defensive bounds check: every index in this payload comes off the wire,
		// so it is treated as untrusted rather than assumed in range.
		if mi < 0 || mi >= len(mapInfos) {
			return
		}
		info := mapInfos[mi]
		if !info.native {
			return
		}
		s.framesSeen.Add(1)

		// ADDRESS GUARD, part one: an address outside its own mapping cannot be
		// placed in the mapping's file. Refuse rather than mis-resolve. This
		// also refuses a mapping whose range and frame addresses follow two
		// different conventions (a runtime memory_start with ELF-space frame
		// addresses, say), because those addresses fall outside the range.
		addr := loc.Address()
		if !info.noRange() && !info.contains(addr) {
			s.mappingBiasUnexpected.Add(1)
			return
		}

		res := s.resolveOnce(pass, mi, info, pc)
		// Every non-OK outcome gets its own counter so a miss is attributable:
		// "build ID mismatched" or "htlhash mismatched" points at a stale
		// artifact, "no candidate" at a path or process-lifetime problem, "no
		// build ID" at a binary with no identity at all, and "permission
		// denied" at the agent's privileges.
		switch res.outcome {
		case resolveNoCandidate:
			s.framesNoCandidate.Add(1)
			return
		case resolvePermissionDenied:
			s.permissionDenied.Add(1)
			return
		case resolveNoBuildID:
			s.framesNoBuildID.Add(1)
			return
		case resolveBuildIDMismatch:
			s.buildIDMismatch.Add(1)
			return
		case resolveHtlhashMismatch:
			s.htlhashMismatch.Add(1)
			return
		}
		// Only resolveOK reaches here, which guarantees a non-nil table. The
		// check is kept as a cheap invariant guard rather than a live branch.
		st := res.table
		if st == nil {
			s.framesNoCandidate.Add(1)
			return
		}

		// ADDRESS GUARD, part two: turn the frame address into an ELF virtual
		// address of the file that proved its identity:
		//
		//	elfVA = address - memory_start + vaddr(file_offset)
		//
		// vaddr(file_offset) comes from the file's own PT_LOAD header that holds
		// file_offset, so this holds for any segment layout: an R E segment at
		// offset 0, one behind a read-only segment (-z separate-code), or one
		// whose vaddr differs from its offset (lld's default layout). A sender
		// that reports runtime addresses has memory_start at the load address;
		// one that reports ELF virtual addresses has memory_start =
		// vaddr(file_offset), and elfVA is then the frame address itself.
		elfVA := addr
		if !info.noRange() {
			va, ok := st.fileOffsetToVA(info.fileOffset)
			if !ok {
				s.mappingBiasUnexpected.Add(1)
				return
			}
			elfVA = addr - info.memoryStart + va
		}
		name, _, ok := st.resolve(elfVA)
		if !ok {
			// Found and identity-matched, but the address is in no function
			// extent. Counted separately so it is not confused with a missing
			// binary.
			s.framesNoSymbol.Add(1)
			return
		}
		if s.cfg.Demangle {
			name = demangle(name)
		}
		// Intern the string, intern a Function referencing it, and hang a Line
		// off the Location referencing that Function.
		nameIdx := internString(name)
		funcIdx := internFunction(nameIdx)
		loc.Lines().AppendEmpty().SetFunctionIndex(funcIdx)
		s.framesResolved.Add(1)
		if s.cfg.RequireBuildIDMatch && info.buildID == "" && info.htlhash != "" {
			s.framesResolvedByHtlhash.Add(1)
		}
	}

	// Resource-scoped walk. Locations live in ONE shared table, but finding the
	// file of an address requires knowing which PROCESS it came from -- that is
	// what gives us the pid and executable path needed to find the file on disk.
	// The walk therefore descends
	// resource -> scope -> profile -> sample -> stack -> locations
	// rather than looping over the location table directly. A sender may
	// deduplicate mappings and locations across the processes of a report, so
	// one location can be reached from several resources.
	//
	// A location index is visited once per SAMPLE that references it, and a hot
	// stack repeats the same locations across thousands of samples. Each
	// location's symbolization is identical every time (the on-disk binary does
	// not change mid-pass), so `processedLocs` ensures each is symbolized and
	// counted AT MOST ONCE per pass. Without it, an unresolved native frame --
	// which never mutates its location, so the `Lines().Len() > 0` short-circuit
	// never fires -- would re-run resolution and re-increment a miss counter on
	// every sample, both wasting work and inflating the miss counts relative to
	// the per-location framesResolved.
	//
	// The dedup key is (process context, locIdx), NOT locIdx alone. Finding the
	// file depends on the owning process's context. Keying by locIdx alone would
	// let a location first reached under a WEAKER context (e.g. a resource with
	// no process.pid) be marked done and counted a miss, so a later resource
	// that DOES carry a valid /proc/<pid> context could never resolve it.
	// Keying by context as well means the identical (context, loc) pair is
	// still deduped, but the same location under a different process context
	// gets its own resolution attempt.
	type locKey struct {
		procDir, root, exePath string
		locIdx                 int
	}
	processedLocs := make(map[locKey]struct{})
	rps := pd.ResourceProfiles()
	for ri := 0; ri < rps.Len(); ri++ {
		rp := rps.At(ri)
		pc := s.processContext(rp)
		sps := rp.ScopeProfiles()
		for si := 0; si < sps.Len(); si++ {
			profs := sps.At(si).Profiles()
			for pi := 0; pi < profs.Len(); pi++ {
				samples := profs.At(pi).Samples()
				for smi := 0; smi < samples.Len(); smi++ {
					stkIdx := int(samples.At(smi).StackIndex())
					if stkIdx < 0 || stkIdx >= stackTab.Len() {
						continue
					}
					locIdxs := stackTab.At(stkIdx).LocationIndices()
					for li := 0; li < locIdxs.Len(); li++ {
						locIdx := int(locIdxs.At(li))
						if locIdx < 0 || locIdx >= locTab.Len() {
							continue
						}
						key := locKey{pc.procDir, pc.root, pc.exePath, locIdx}
						if _, done := processedLocs[key]; done {
							continue // already symbolized/counted this pass under this context
						}
						processedLocs[key] = struct{}{}
						symbolizeLocation(locTab.At(locIdx), pc)
					}
				}
			}
		}
	}

	s.endPass(ctx)
	return pd, nil
}

// resolveOnce resolves a mapping at most once per pass after it succeeds.
func (s *symbolizer) resolveOnce(p *passState, mi int, info mappingInfo, pc procContext) resolution {
	if st, ok := p.resolved[mi]; ok {
		return resolution{table: st, outcome: resolveOK}
	}
	res := s.resolveMapping(p, info, pc)
	if res.outcome == resolveOK {
		p.resolved[mi] = res.table
	}
	return res
}

// resolveOutcome explains why resolveMapping did or did not yield a table, so
// the caller can attribute a miss to the right self-telemetry counter.
type resolveOutcome int

const (
	resolveOK               resolveOutcome = iota
	resolveNoCandidate                     // no candidate path parsed at all
	resolveNoBuildID                       // parsed, but no identity to compare on one side
	resolveBuildIDMismatch                 // parsed, but no candidate's GNU build ID matched
	resolveHtlhashMismatch                 // no GNU build ID, and no candidate's htlhash matched
	resolvePermissionDenied                // nothing parsed, and the agent was refused or skipped a process
)

// resolveMapping maps a sender-reported mapping to its file and returns the
// parsed symbol table.
//
// IDENTITY. A file is accepted only when it proves that it is the file the
// sender sampled (require_build_id_match, default on):
//
//   - When the mapping has a GNU build ID, the file must carry the same GNU
//     build ID.
//   - When the mapping has no GNU build ID (a binary linked without
//     --build-id), the file's htlhash must equal the mapping's
//     process.executable.build_id.htlhash, which the semantic conventions
//     define as SHA-256 over the first 4 KiB, the last 4 KiB and the length of
//     the file (see identity.go). The first 4 KiB hold the ELF header and the
//     program headers, with the offset and size of every segment. In a file
//     whose section headers come last, the last 4 KiB hold the section header
//     table (or its end). So a rebuild changes the htlhash when it changes the
//     start or the end of the file, its length, or the size of a segment or a
//     section. Two builds that differ only in the middle, with every size the
//     same, get the same htlhash.
//   - When the mapping has neither, nothing can prove the file, and the frame
//     is counted no_build_id.
//
// The identity check is part of CANDIDATE SELECTION, not a post-check. Several
// candidate paths can each hold a parseable ELF of the same basename -- e.g. a
// host-root `libfoo.so` and the container's own `libfoo.so` -- and only one is
// the binary that was actually sampled. So iteration continues until a
// candidate both parses AND matches, and the outcome reported is the best one
// observed across all candidates.
//
// A table that a file proved is cached under the mapping's content key, so the
// next lookup of the same content, from any process, any pass or another
// pipeline, touches no file at all. A walk that found nothing is remembered for
// missRetryAfter in the shared miss memo, so that a file that is gone for good
// (the vDSO, a deleted file of an exited process) does not cost a walk and a
// /proc/<pid>/maps read on every pass.
func (s *symbolizer) resolveMapping(p *passState, info mappingInfo, pc procContext) resolution {
	key := info.contentKey()
	if s.cfg.RequireBuildIDMatch && key != "" {
		if e, ok := s.cache.lookupContent(key); ok {
			if e.table == nil {
				// This content is known to have no usable symbols, or reading it
				// panicked: definitive for these bytes.
				return resolution{outcome: resolveNoCandidate}
			}
			return resolution{table: e.table, outcome: resolveOK}
		}
	}
	mk := missKey{identity: info.missIdentity(), procDir: pc.procDir, root: pc.root, exePath: pc.exePath}
	if outcome, ok := s.shared.misses.get(mk); ok {
		return resolution{outcome: outcome}
	}

	s.candidateWalks.Add(1)
	var (
		res     resolution
		reasons []string
	)
	if s.cfg.RequireBuildIDMatch {
		res, reasons = s.walkWithIdentity(p, info, pc, key)
	} else {
		res, reasons = s.walkFirstParseable(p, info, pc)
	}
	if res.outcome != resolveOK {
		s.shared.misses.put(mk, res.outcome)
		if res.outcome == resolveNoCandidate || res.outcome == resolvePermissionDenied {
			s.diagnoseMiss(res.outcome, info, pc, reasons)
		}
	}
	return res
}

// walkWithIdentity tries the candidates of a mapping in order and returns the
// table of the first one that proves the mapping's identity and has symbols.
// reasons explains each candidate that was not used, for the diagnostic log.
func (s *symbolizer) walkWithIdentity(p *passState, info mappingInfo, pc procContext, key string) (resolution, []string) {
	var (
		sawMismatch    bool
		sawHtlMismatch bool
		sawMissingID   bool
		sawUnusable    bool
		sawDenied      = pc.denied
		reasons        []string
	)
	for _, c := range s.candidates(p, info, pc) {
		f, fp, err := c.open()
		if err != nil {
			sawDenied = sawDenied || errors.Is(err, fs.ErrPermission)
			reasons = append(reasons, c.path+" ["+err.Error()+"]")
			continue
		}
		if e, ok := s.cache.lookupFile(c.path, fp); ok && e.table == nil {
			// This exact file version panicked before: do not read it again.
			f.Close()
			reasons = append(reasons, c.path+" [present, its read panicked before]")
			continue
		}
		v := s.examine(f, c.path, info)
		f.Close()
		switch v.kind {
		case verdictOK:
			if key != "" {
				s.cache.store(key, cacheEntry{table: v.table})
			}
			return resolution{table: v.table, outcome: resolveOK}, nil
		case verdictNotELF:
			reasons = append(reasons, c.path+" [present, not parseable]")
		case verdictPanicked:
			// Cache that file version as failed, so that it is not read again.
			s.cache.store(c.path, cacheEntry{fp: fp})
			if v.proven {
				// The file had already proved the mapping's identity, so the
				// failure belongs to the sampled content itself.
				sawUnusable = true
			}
			reasons = append(reasons, c.path+" [present, reading it panicked]")
		case verdictNoIdentity:
			sawMissingID = true
			reasons = append(reasons, c.path+" [present, no build ID to compare]")
		case verdictBuildIDMismatch:
			sawMismatch = true
			reasons = append(reasons, c.path+" [present, GNU build ID differs]")
		case verdictHtlhashMismatch:
			sawHtlMismatch = true
			reasons = append(reasons, c.path+" [present, htlhash differs]")
		case verdictNoSymbols:
			sawUnusable = true
			reasons = append(reasons, c.path+" [identity matched, no text symbols]")
		}
	}
	if sawUnusable && key != "" {
		// Definitive for the sampled content: every file that proved it is
		// unusable, and the same bytes will not read differently next time.
		s.cache.store(key, cacheEntry{})
	}
	sawDenied = sawDenied || errors.Is(p.mapsErr[pc.procDir], fs.ErrPermission)
	switch {
	case sawMismatch:
		// A concrete wrong-binary signal outranks a missing-ID one: it is the
		// finding an operator needs to see (stale deploy / rebuilt artifact).
		return resolution{outcome: resolveBuildIDMismatch}, reasons
	case sawHtlMismatch:
		return resolution{outcome: resolveHtlhashMismatch}, reasons
	case sawMissingID:
		return resolution{outcome: resolveNoBuildID}, reasons
	case sawDenied && !sawUnusable:
		// Nothing that was read could prove the mapping, and something was not
		// read because the agent may not: a privilege problem, not a missing
		// file.
		return resolution{outcome: resolvePermissionDenied}, reasons
	default:
		// Nothing parsed, or what proved the identity had no usable symbols.
		return resolution{outcome: resolveNoCandidate}, reasons
	}
}

// walkFirstParseable is the walk for require_build_id_match: false, a
// diagnostics-only mode: the first candidate that parses and has symbols is
// used, whatever its identity.
func (s *symbolizer) walkFirstParseable(p *passState, info mappingInfo, pc procContext) (resolution, []string) {
	var reasons []string
	sawDenied := pc.denied
	onParse := func(err error) {
		s.symbolTablesParsed.Add(1)
		if errors.Is(err, errSymbolTablePanic) {
			s.symbolTablePanics.Add(1)
		}
	}
	for _, c := range s.candidates(p, info, pc) {
		st, _, err := s.cache.getFile(c, onParse)
		if err != nil {
			sawDenied = sawDenied || errors.Is(err, fs.ErrPermission)
			reasons = append(reasons, c.path+" ["+err.Error()+"]")
			continue
		}
		if st == nil {
			reasons = append(reasons, c.path+" [present, no usable symbols]")
			continue
		}
		return resolution{table: st, outcome: resolveOK}, nil
	}
	if sawDenied || errors.Is(p.mapsErr[pc.procDir], fs.ErrPermission) {
		return resolution{outcome: resolvePermissionDenied}, reasons
	}
	return resolution{outcome: resolveNoCandidate}, reasons
}

// verdictKind is what examine concluded about one candidate file.
type verdictKind int

const (
	verdictNotELF verdictKind = iota
	verdictPanicked
	verdictNoIdentity
	verdictBuildIDMismatch
	verdictHtlhashMismatch
	verdictNoSymbols
	verdictOK
)

type verdict struct {
	kind  verdictKind
	table *symbolTable
	// proven is true once the file has proved the mapping's identity.
	proven bool
}

// newELFFile reads the ELF headers of an open candidate. It is a variable only
// so that a test can make it panic before the file has proved its identity;
// production code never assigns it.
var newELFFile = elf.NewFile

// examine checks that an open candidate file is the file the mapping describes,
// and only then reads its symbol table. Nothing is parsed beyond the ELF and
// section headers for a file that does not prove the identity.
//
// A panic anywhere in here -- debug/elf parsing headers or symbols this process
// does not control -- is recovered, logged and counted. It must not escape: the
// agent would crash and restart on the same file every pass.
func (s *symbolizer) examine(f *os.File, path string, info mappingInfo) verdict {
	var (
		v      verdict
		proven bool
	)
	if p := recoverPanic(func() { v = s.examineUnsafe(f, info, &proven) }); p != nil {
		s.symbolTablePanics.Add(1)
		s.log.Warn("nativesymbolizer recovered a panic while reading an ELF file",
			zap.String("file", path),
			zap.String("mapping_filename", info.filename),
			zap.Any("panic", p),
		)
		return verdict{kind: verdictPanicked, proven: proven}
	}
	return v
}

// examineUnsafe is examine without the panic recovery. It sets *proven once the
// file has proved the mapping's identity, so that examine still knows it when
// the symbol-table read panics.
func (s *symbolizer) examineUnsafe(f *os.File, info mappingInfo, proven *bool) verdict {
	ef, err := newELFFile(f)
	if err != nil {
		return verdict{kind: verdictNotELF}
	}
	switch {
	case info.buildID != "":
		got := readBuildID(ef)
		if got == "" {
			return verdict{kind: verdictNoIdentity}
		}
		if !strings.EqualFold(got, info.buildID) {
			return verdict{kind: verdictBuildIDMismatch}
		}
	case info.htlhash != "":
		// The hash over the same open file that is parsed below, so the file
		// cannot change between the check and the read.
		id, err := htlhash(f)
		if err != nil {
			return verdict{kind: verdictNotELF}
		}
		if !strings.EqualFold(id, info.htlhash) {
			return verdict{kind: verdictHtlhashMismatch}
		}
	default:
		return verdict{kind: verdictNoIdentity}
	}
	*proven = true
	s.symbolTablesParsed.Add(1)
	st, err := buildSymbolTable(ef)
	if err != nil {
		return verdict{kind: verdictNoSymbols, proven: true}
	}
	return verdict{kind: verdictOK, table: st, proven: true}
}

// diagnoseMiss logs, once per resolution context, what path resolution
// actually saw for a mapping it found no file for (no_candidate or
// permission_denied).
//
// The accounting counters say HOW MANY frames missed and in which class; this
// says WHY a particular binary missed, which is the part an operator cannot
// reconstruct afterwards: the filename the sender reported, the root and
// executable path it was joined against, and each candidate path with the
// reason it could not be used.
//
// It is deliberately Debug and deliberately deduplicated. A repeat of a known
// miss carries no new information, so the interesting event is the FIRST time a
// given binary fails under a given process root.
func (s *symbolizer) diagnoseMiss(outcome resolveOutcome, info mappingInfo, pc procContext, reasons []string) {
	const (
		// diagMaxContexts caps the whole set so a host with an unbounded churn
		// of short-lived, differently-named binaries cannot grow it without
		// limit. Past the cap the log goes quiet rather than evicting: the
		// frames still show up in the no_candidate counter, and a cap this far
		// above the number of distinct binaries on a service host means
		// reaching it is itself a signal.
		diagMaxContexts = 512
		// diagMaxContextsPerFile caps how many resolution contexts a single
		// filename may report. A handful is enough to show that a binary fails
		// under more than one process root, which is the interesting part,
		// while keeping a mapping present in every process on the host from
		// consuming the whole budget.
		diagMaxContextsPerFile = 4
	)

	key := diagKey{filename: info.filename, root: pc.root, exePath: pc.exePath}

	s.diagnosedMu.Lock()
	if s.diagnosed == nil {
		s.diagnosed = make(map[diagKey]struct{})
		s.diagnosedPerFile = make(map[string]int)
	}
	_, seen := s.diagnosed[key]
	if seen || len(s.diagnosed) >= diagMaxContexts || s.diagnosedPerFile[info.filename] >= diagMaxContextsPerFile {
		s.diagnosedMu.Unlock()
		return
	}
	s.diagnosed[key] = struct{}{}
	s.diagnosedPerFile[info.filename]++
	s.diagnosedMu.Unlock()

	reason := "no_candidate"
	if outcome == resolvePermissionDenied {
		reason = "permission_denied"
	}
	s.log.Debug("nativesymbolizer miss diagnostic",
		zap.String("reason", reason),
		zap.String("mapping_filename", info.filename),
		zap.String("proc_root", pc.root),
		zap.String("exe_path", pc.exePath),
		zap.String("build_id", info.buildID),
		zap.String("htlhash", info.htlhash),
		zap.Strings("candidates", reasons),
	)
}

// processIdentity reads process.pid and process.executable.path from a
// resource's attributes. The pid is returned as a decimal string ("" if
// absent).
func processIdentity(rp pprofile.ResourceProfiles) (string, string) {
	var pid, exePath string
	attrs := rp.Resource().Attributes()
	if v, ok := attrs.Get(attrPID); ok {
		pid = v.AsString()
	}
	if v, ok := attrs.Get(attrExecutablePath); ok {
		exePath = v.Str()
	}
	return pid, exePath
}

// --- dictionary helpers -----------------------------------------------------

func buildStringIndex(strTab pcommon.StringSlice) map[string]int32 {
	m := make(map[string]int32, strTab.Len())
	for i := 0; i < strTab.Len(); i++ {
		// First occurrence wins -- interning must return the canonical index.
		if _, ok := m[strTab.At(i)]; !ok {
			m[strTab.At(i)] = int32(i)
		}
	}
	return m
}

func stringAt(strTab pcommon.StringSlice, idx int32) string {
	if idx < 0 || int(idx) >= strTab.Len() {
		return ""
	}
	return strTab.At(int(idx))
}

// attrValue looks up a string-valued attribute by key among the given attribute
// indices into the shared attribute table. Returns "" if absent.
func attrValue(attrTab pprofile.KeyValueAndUnitSlice, strTab pcommon.StringSlice, indices pcommon.Int32Slice, key string) string {
	for i := 0; i < indices.Len(); i++ {
		ai := int(indices.At(i))
		if ai < 0 || ai >= attrTab.Len() {
			continue
		}
		kv := attrTab.At(ai)
		if stringAt(strTab, kv.KeyStrindex()) == key {
			return kv.Value().AsString()
		}
	}
	return ""
}

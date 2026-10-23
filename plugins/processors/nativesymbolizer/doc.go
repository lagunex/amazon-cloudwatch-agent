// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//go:build linux

// Package nativesymbolizer names the native (C, C++, Rust, ...) frames of OTLP
// profiles that arrive with no function name.
//
// A sampling profiler records each frame as an address in a mapped file. Many
// profilers name only the frames they can name cheaply where they sample (kernel
// frames, Go frames, interpreted frames) and send native frames as
// {mapping, address} with an empty `lines` list, leaving symbolization to the
// backend. A backend that renders frames by name shows nothing for those
// frames, so a flame graph of a native service loses its own code.
//
// This processor does that symbolization in the agent, for any sender: it reads
// the ELF symbol table (.symtab, falling back to .dynsym) of the binary that
// the agent's host holds for each mapping, and writes the function name back
// into the profiles dictionary. It depends only on OTLP profiles and the OTel
// semantic conventions:
//
//   - resource: process.pid (to find the process's files through /proc) and,
//     optionally, process.executable.path;
//   - mapping: its filename (a basename or an absolute path), and its identity,
//     process.executable.build_id.gnu and/or process.executable.build_id.htlhash;
//   - location: profile.frame.type, when present, must be "native".
//
// # Identity
//
// A frame is named only from a file that proves it is the file the sender
// sampled: its GNU build ID must equal the mapping's, or, for a file with no GNU
// build ID, its htlhash must (see identity.go). A rebuilt binary would otherwise
// resolve every address to a plausible but wrong name, which is worse than no
// name. A frame that cannot be proved is left as it arrived.
//
// # Addresses
//
// An address is placed in the file's ELF virtual-address space as
//
//	address - memory_start + vaddr(file_offset)
//
// where vaddr(file_offset) comes from the file's own executable PT_LOAD. This
// holds whether the sender reports runtime addresses (memory_start is where the
// mapping was loaded) or addresses already in the file's address space
// (memory_start is vaddr(file_offset)). An address outside
// [memory_start, memory_limit) is refused.
//
// # Data model
//
// OTLP profiles intern everything in one dictionary shared by the payload:
//
//	Sample.StackIndex -> Stack.LocationIndices[i] -> Location
//	  -> Location.Lines[0].FunctionIndex -> Function.NameStrindex -> string
//
// An empty Location.Lines is what "this frame has no name" means. Naming it is
// interning the string, interning a Function that points at it, and appending a
// Line to the Location. The walk is resource-scoped, because finding a file
// needs the process that mapped it.
//
// # Privileges
//
// Finding the file of a process means reading /proc/<pid>/{exe,maps,root}. The
// kernel allows that for a dumpable process with the agent's uid and gid, and
// for any process when the agent has CAP_SYS_PTRACE. See privilege.go for the
// modes the processor runs in when it lacks that capability.
package nativesymbolizer

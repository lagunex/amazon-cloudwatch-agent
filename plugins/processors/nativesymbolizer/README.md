# Native Symbolizer Processor

The Native Symbolizer Processor names the native (C, C++, Rust, ...) frames of OTLP profiles that arrive with no function name, by reading the ELF symbol tables of the binaries on the agent's host. A flame graph of a native service then shows the service's own functions instead of only the frames that the profiler could name where it sampled (kernel, Go, interpreted code).

| Status                   |                           |
| ------------------------ |---------------------------|
| Stability                | development               |
| Supported pipeline types | profiles                  |
| Supported OS             | Linux only                |
| Distributions            | amazon-cloudwatch-agent   |

The processor is compiled into the Linux agent only. On Windows and macOS the component does not exist, so a configuration that lists it is rejected at startup with `unknown type: "nativesymbolizer"`.

## Overview

Many sampling profilers name only the frames they can name cheaply where they sample, and send each native frame as a mapping (the file and its build ID) plus an address, with an empty `lines` list. Naming those frames is left to the backend. This processor does it in the agent, once per report, for any sender: it depends only on OTLP profiles and the OpenTelemetry semantic conventions, not on a particular profiler.

For each location with no `lines`, it:

1. finds the file of the location's mapping, through the process that the resource describes;
2. checks that the file is the one the sender sampled (see [Identity](#identity));
3. places the address in the file's ELF virtual-address space, and looks up the function symbol (`.symtab`, falling back to `.dynsym`) that covers it;
4. writes the name (demangled, by default) into the profiles dictionary, as a `Function` and a `Line` on the location.

A frame it cannot name is left exactly as it arrived. The processor never drops samples, locations or attributes, and never fails the pipeline: a panic while reading an ELF file is recovered, counted, and that file version is not read again.

### Input

| Where    | Attribute / field                    | Use |
|----------|--------------------------------------|-----|
| Resource | `process.pid`                        | Finds the process's files through `/proc/<pid>`. Optional, but without it a containerized process cannot be resolved. |
| Resource | `process.executable.path`            | Optional. Identifies the main executable, and is tried as a path. |
| Mapping  | filename                             | A basename (`libc.so.6`) or an absolute path. |
| Mapping  | `process.executable.build_id.gnu`    | The GNU build ID of the file. |
| Mapping  | `process.executable.build_id.htlhash`| The semantic-convention htlhash of the file, for files with no GNU build ID. |
| Mapping  | `memory_start`, `memory_limit`, `file_offset` | Where the mapping was loaded. Runtime addresses and file-relative (ELF virtual) addresses are both supported. |
| Location | `profile.frame.type`                 | When present, only `native` frames are named. |
| Location | `lines`                              | A location that already has lines is never changed. |

The process is resolved in the agent's pid namespace, against the agent's view of the filesystem. So the sender must profile processes on the same host as the agent, and the agent must see them: for example a profiler that sends to the agent from the same host, a node, or a pod in the host pid namespace. Frames of processes the agent cannot see pass through unnamed.

### Identity

A frame is named only from a file that proves it is the file the sender sampled. A rebuilt binary would otherwise resolve every address to a plausible but **wrong** name, which is worse than no name. The proof is:

- the same GNU build ID, when the mapping has one;
- otherwise the same htlhash: SHA-256 of the first 4 KiB, the last 4 KiB and the big-endian 64-bit length of the file, cut to 128 bits, as the semantic conventions define `process.executable.build_id.htlhash`.

A mapping with neither is left unresolved (`no_build_id`). A file that fails the check is not used (`build_id_mismatch`, `htlhash_mismatch`).

### Finding the file

Every candidate must still pass the identity check, so a wrong candidate can only cost a lookup, never a wrong name.

- Main executable (the mapping's basename is the basename of `process.executable.path`): `/proc/<pid>/exe`, then `/proc/<pid>/root` + the executable path, then the executable path as reported.
- Shared object: for each executable line of `/proc/<pid>/maps` with the mapping's basename and file offset, `/proc/<pid>/map_files/<start>-<end>` (the exact inode, which survives a replaced file) and `/proc/<pid>/root` + the full path of that line. `maps` is read at most once per process per report, and only for a file that is not resolved yet.
- Then, for both: `/proc/<pid>/root` + the mapping filename, and the mapping filename as reported.

A path under a process root is opened with `openat2(RESOLVE_IN_ROOT)`, so a symlink inside a container cannot lead to a host file.

### Addresses

The address is placed in the file as `address - memory_start + vaddr(file_offset)`, where `vaddr(file_offset)` comes from the file's executable `PT_LOAD` segment that holds `file_offset`. This is correct for any segment layout and for both conventions a sender may use: runtime addresses (`memory_start` is the load address) and file-relative addresses (`memory_start` is `vaddr(file_offset)`). An address outside `[memory_start, memory_limit)`, or a `file_offset` in no executable segment, is refused (`mapping_bias_unexpected`). A mapping with no range at all (`memory_start`, `memory_limit` and `file_offset` all zero) is taken to carry ELF virtual addresses.

## Privileges

Reading `/proc/<pid>/{exe,maps,root}` passes the kernel's ptrace read check. That check succeeds without any capability for a *dumpable* process whose uids and gids are the agent's own. For any other process it needs `CAP_SYS_PTRACE`. The processor needs none of the other capabilities a profiler needs to sample (`CAP_PERFMON`, `CAP_BPF`, `CAP_SYSLOG`).

| Capability | Needed for | Without it |
|---|---|---|
| `CAP_SYS_PTRACE` | `/proc/<pid>` of processes of other users | Limited mode (below). |
| `CAP_CHECKPOINT_RESTORE` (or `CAP_SYS_ADMIN`) | following `/proc/<pid>/map_files` links, for any user | Those candidates are skipped. Only a binary replaced on disk since its process started is lost; the path candidates cover the rest. |
| `CAP_DAC_READ_SEARCH` | binaries that are not world-readable | Those files are counted `permission_denied`. |

At startup the processor probes what it may read, once per configuration, and runs in one of three modes:

| Mode | When | Behavior |
|---|---|---|
| `full` | `CAP_SYS_PTRACE` is effective (the agent runs as root, which is the default on EC2 and on premises). | Every process the agent can see. |
| `limited` | No `CAP_SYS_PTRACE` (for example `run_as_user` set to a non-root user, or a container without the capability). | Before touching `/proc/<pid>`, the processor compares the owner the kernel shows for `/proc/<pid>/maps` (the process's effective uid and gid, or root for a non-dumpable process) with the agent's. It reads `/proc` only for processes of its own uid and gid, and still tries the paths the sender reported, so world-readable binaries in the agent's own filesystem are named for processes of any user. Containerized processes of other users, and shared objects reported by basename only, pass through unnamed. One warning is logged at startup. |
| `inactive` | The agent cannot reopen files through its own `/proc/self/fd`, which every file read uses (no `/proc` in its mount namespace). | Profiles pass through untouched, with no per-frame work. One warning is logged at startup. |

A frame that stays unnamed because the agent may not read what would name it is counted `permission_denied`: a file or `/proc` entry refused with `EACCES`/`EPERM`, a process skipped in limited mode, or a process hidden by `/proc` mounted with `hidepid=invisible`. There is no per-frame log at Info or Warn level. A Debug line explains the first misses of each binary.

### Deployment

- **EC2 and on premises.** The agent runs as root by default, so the processor runs in full mode with nothing to grant. With `run_as_user` set to another user, the agent switches users without keeping capabilities, and the processor runs in limited mode.
- **Amazon EKS / Kubernetes.** To name the frames of every pod on the node, run the agent DaemonSet with `hostPID: true` and add `SYS_PTRACE` (and optionally `CHECKPOINT_RESTORE`) to the container's capabilities. Without them, the processor runs in limited mode and sees only the processes in its own pid namespace.
- **Amazon ECS.** On the EC2 launch type, use `pidMode: host` and add `SYS_PTRACE` under `linuxParameters.capabilities`. On Fargate, `pidMode: task` lets the agent see the processes of its own task.

## Configuration

```yaml
processors:
  nativesymbolizer:
    max_cached_binaries: 256      # LRU bound on parsed symbol tables
    max_cached_bytes: 268435456   # LRU bound on their estimated heap size; 0 = no byte bound
    require_build_id_match: true  # refuse files that do not prove their identity; keep on
    demangle: true                # decode Rust (v0 and legacy) and C++ names
    root_path_prefix: ""          # where the host's /proc is mounted, for an agent in a container
```

All fields are optional, and `nativesymbolizer: {}` uses the defaults above. There is no `enabled` flag: the processor is turned on by listing it in a profiles pipeline, before the exporter.

`require_build_id_match: false` exists only for diagnostics: a stale binary then yields wrong names, and every report walks the candidates again.

### Cache

Parsed symbol tables are cached by the identity of the sampled file (its GNU build ID or htlhash), so an entry never goes stale, and every process that maps the same library shares one table. The processor instances of all pipelines that list the same `nativesymbolizer` configuration share one cache. A mapping that cannot be resolved in a process (the vDSO, for example, which is never a file) is not tried again in that process for one minute. Keep `max_cached_bytes` well above the tables that one report needs, the binaries and libraries of the profiled processes. Below that, the tables evict each other and every report parses them again, which `symbol_tables_parsed` shows.

## Self-telemetry

Each counter is a collector metric named `otelcol_processor_nativesymbolizer_<key>`. In the agent, collector metrics are exported only when self-telemetry is enabled (`agent.self_telemetry.enabled`). The same counters, the mode and the cache size are also logged at Info level (`nativesymbolizer summary`) on the first report and every 60 reports, so the outcome is visible at the default log level.

| Key | Counts |
|---|---|
| `frames_seen` | native frames with no name that the processor tried to name |
| `frames_resolved` | frames named |
| `frames_resolved_by_htlhash` | named frames whose file has no GNU build ID (part of `frames_resolved`) |
| `no_candidate` | no file found, or the matching file has no usable symbols |
| `no_symbol` | file matched, no function covers the address |
| `no_build_id` | no GNU build ID and no htlhash to prove the file |
| `build_id_mismatch` | every file found had another GNU build ID |
| `htlhash_mismatch` | no GNU build ID, and every file found had another htlhash |
| `mapping_bias_unexpected` | address outside its mapping, or mapping in no executable segment |
| `permission_denied` | the agent may not read the process or the file that would name the frame |
| `symbol_tables_parsed` | symbol tables read |
| `symbol_table_panics` | panics recovered while reading an ELF file |
| `proc_maps_reads` | reads of `/proc/<pid>/maps` |
| `mode` (gauge) | 2 full, 1 limited, 0 inactive |

`frames_seen` is the sum of `frames_resolved` and the seven miss keys. The counters carry no pipeline attribute, so all pipelines that list the processor add into one series per counter.

## Agent integration plan

The processor is registered as a component of the Linux agent, but no configuration translated from the agent's JSON lists it yet. The OTLP profiles pipeline that it belongs to is being added in [#2300](https://github.com/aws/amazon-cloudwatch-agent/pull/2300) (generate `profiles/otlp` from `opentelemetry.collect.otlp`) and [#2357](https://github.com/aws/amazon-cloudwatch-agent/pull/2357) (enrich it with resource detection, Kubernetes attributes and identity statements). Both are open at the time of writing, and #2357 is stacked on #2300.

Once both have merged and the agent generates the profiles pipeline:

1. **Translator.** Add `translator/translate/otel/processor/nativesymbolizer/translator.go`, a translator with ID `nativesymbolizer` that returns the factory's default configuration.
2. **Wiring.** In `translator/translate/otel/pipeline/opentelemetry/otlp/translator_profiles.go`, add the translator to the processors of every profiles pipeline whenever the agent is translated for Linux, as the **first** processor, before `resource/opentelemetry`, `resourcedetection`, `k8s_attributes` and `transform/identity`. It needs only the attributes the sender stamped (`process.pid`, `process.executable.path`), and running first keeps its in-place mutation ahead of any fan-out. There is no JSON flag and no `run_as_user` condition: what the agent may read is decided at runtime by the privilege probe (full, limited or inactive mode), and a non-root agent runs in limited mode. The translator must not add the processor for Windows or macOS, where the component does not exist.
3. **Golden files.** Update every `translator/tocwconfig/sampleConfig/opentelemetry*` YAML whose Linux translation renders `profiles/otlp`, and check that the Windows and macOS sample configurations do not change.
4. **Kubernetes.** In the Helm chart and the operator, give the agent DaemonSet `hostPID: true` and the `SYS_PTRACE` capability, in its own PR that links to the agent PR, so the processor runs in full mode on EKS.
5. **Tests.** Add an integration test to [amazon-cloudwatch-agent-test](https://github.com/aws/amazon-cloudwatch-agent-test): a sender on the same host profiles a native binary with symbols and sends to the agent's OTLP receiver, and the test asserts that the exported profile names its native frames. Run it as root and as a non-root `run_as_user`, to cover full and limited mode. Add a performance run with before and after numbers for the agent's CPU and memory.
6. **Documentation.** Document the capabilities and the modes in the agent's user documentation for profiles.

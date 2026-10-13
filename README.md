# syzcall-trace

[![build](https://github.com/sairex53/syzcall-trace/actions/workflows/ci.yml/badge.svg)](https://github.com/sairex53/syzcall-trace/actions/workflows/ci.yml)

`syzcall-trace` records the syscalls made by a command and its child processes using Linux eBPF tracepoints. It is meant for looking at a syzbot reproducer's *actual* execution: which syscall numbers ran, on which thread, when each call started, how long it took, and what return value it produced.

Syzkaller programs can execute calls concurrently, so a reproducer describes the workload but not the exact schedule of a particular run. The official syzkaller documentation notes that calls may execute in parallel and some bugs depend on rare races. This tool adds a local syscall timeline without changing the reproducer.

## Build

Build on Linux with kernel BTF enabled (`/sys/kernel/btf/vmlinux` present) and the raw syscall and scheduler tracepoints. On Ubuntu 26.04, install:

```sh
sudo apt install clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev pkg-config build-essential
make
```

On Ubuntu 24.04, install `linux-tools-common` and the tools package matching the running kernel instead of `bpftool`:

```sh
sudo apt install clang llvm linux-tools-common "linux-tools-$(uname -r)" libbpf-dev libelf-dev zlib1g-dev pkg-config build-essential
```

The JSON formatter has a userspace-only test that can also run on macOS:

```sh
make check
```

## Run a reproducer

Run this inside a disposable Linux VM with the syzkaller tools and reproducer already copied there:

```sh
sudo ./build/syzcall-trace --output run.jsonl -- \
  ./bin/linux_amd64/syz-execprog -enable=all -repeat=1 repro.syz
```

The collector attaches before starting the command and uses a start gate so the first child syscall is included. It follows descendants through `sched_process_fork`, waits until tracked descendants exit, and removes task IDs on exit. The child process's normal stdout and stderr remain attached to the terminal; trace records go to the JSONL file.

Illustrative record (values are not from a syzbot run):

```json
{"type":"syscall","arch":"x86_64","start_ns":8123456700,"duration_ns":18420,"tgid":412,"tid":417,"comm":"syz-executor","syscall_nr":257,"ret":3}
{"type":"summary","exit_code":0,"signal":0,"lost_events":0}
```

`syscall_nr` is the raw number for the VM's syscall ABI. Events are written when syscalls finish; `start_ns` is monotonic time and can be used to order overlapping calls by their start. If the ring buffer fills, the final summary reports the number of dropped events.

By default, syscall arguments are omitted. `--args` includes the six raw argument values, which may contain addresses or application data; review the output before sharing it.

## Scope and limits

- This is a syscall timeline, not a deterministic replay system. It does not capture kernel function calls, memory accesses, or the scheduler's complete decisions.
- Tracepoints are attached system-wide and events are filtered by the command's process tree inside eBPF. This still adds overhead, so timings are observations from an instrumented run, not baseline performance measurements.
- A missing crash in one run does not prove a patch fixed the bug. Races can disappear even without tracing.
- A nonzero `lost_events` count means the trace is incomplete.
- The program needs permission to load BPF programs and attach tracepoints. Use a disposable VM for untrusted syzbot reproducers; do not run them on a workstation with valuable data.

## How it works

The BPF side tracks the command's thread ID, propagates that membership to children, stores syscall-entry data in a hash map, and emits the matching exit record through a ring buffer. The userspace C++ collector launches the command behind a pipe gate, drains the ring buffer, and writes JSON Lines. Raw arguments are copied only when `--args` is selected.

## License

MIT. The eBPF program itself declares `GPL` so it can use the required kernel helpers.

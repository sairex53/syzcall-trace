#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "event.h"

const volatile bool capture_args = false;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u8);
} tracked_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, struct syzcall_event);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} active_tasks SEC(".maps");

static __always_inline void count_lost(void)
{
    __u32 zero = 0;
    __u64 *lost = bpf_map_lookup_elem(&lost_events, &zero);
    if (lost)
        (*lost)++;
}

SEC("tracepoint/sched/sched_process_fork")
int track_child(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 parent_tid = (__u32)bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&tracked_tids, &parent_tid))
        return 0;

    __u32 child_tid = (__u32)ctx->child_pid;
    __u8 tracked = 1;
    if (bpf_map_update_elem(&tracked_tids, &child_tid, &tracked, BPF_ANY))
        count_lost();
    else {
        __u32 zero = 0;
        __u64 *active = bpf_map_lookup_elem(&active_tasks, &zero);
        if (active)
            __sync_fetch_and_add(active, 1);
        else {
            bpf_map_delete_elem(&tracked_tids, &child_tid);
            count_lost();
        }
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int untrack_task(void *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&tracked_tids, &tid)) {
        bpf_map_delete_elem(&tracked_tids, &tid);
        __u32 zero = 0;
        __u64 *active = bpf_map_lookup_elem(&active_tasks, &zero);
        if (active)
            __sync_fetch_and_sub(active, 1);
        else
            count_lost();
    }
    bpf_map_delete_elem(&pending, &tid);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int record_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    if (!bpf_map_lookup_elem(&tracked_tids, &tid))
        return 0;

    struct syzcall_event event = {};
    event.start_ns = bpf_ktime_get_ns();
    event.syscall_nr = ctx->id;
    event.tgid = (__u32)(pid_tgid >> 32);
    event.tid = tid;
    bpf_get_current_comm(event.comm, sizeof(event.comm));

    if (capture_args) {
#pragma unroll
        for (int i = 0; i < SYZCALL_ARGS_COUNT; i++)
            event.args[i] = ctx->args[i];
    }
    if (bpf_map_update_elem(&pending, &tid, &event, BPF_ANY))
        count_lost();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int record_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct syzcall_event *pending_event = bpf_map_lookup_elem(&pending, &tid);
    if (!pending_event)
        return 0;

    pending_event->duration_ns = bpf_ktime_get_ns() - pending_event->start_ns;
    pending_event->ret = ctx->ret;
    struct syzcall_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (out) {
        __builtin_memcpy(out, pending_event, sizeof(*out));
        bpf_ringbuf_submit(out, 0);
    } else {
        count_lost();
    }
    bpf_map_delete_elem(&pending, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#ifndef SYZCALL_EVENT_H
#define SYZCALL_EVENT_H

/* Shared wire format between the BPF program and the userspace collector. */
typedef unsigned char sc_u8;
typedef unsigned int sc_u32;
typedef unsigned long long sc_u64;
typedef long long sc_s64;

#define SYZCALL_ARGS_COUNT 6
#define SYZCALL_COMM_LEN 16

struct syzcall_event {
    sc_u64 start_ns;
    sc_u64 duration_ns;
    sc_u64 args[SYZCALL_ARGS_COUNT];
    sc_s64 syscall_nr;
    sc_s64 ret;
    sc_u32 tgid;
    sc_u32 tid;
    char comm[SYZCALL_COMM_LEN];
};

#endif

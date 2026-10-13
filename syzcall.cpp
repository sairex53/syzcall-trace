#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "format.hpp"
#include "syzcall.skel.h"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

struct output_context {
    std::ostream *out;
    std::string arch;
    bool capture_args;
    bool failed;
};

static int on_event(void *opaque, void *data, size_t size)
{
    auto *ctx = static_cast<output_context *>(opaque);
    if (size != sizeof(syzcall_event)) {
        ctx->failed = true;
        return 0;
    }

    const auto *event = static_cast<const syzcall_event *>(data);
    *ctx->out << event_json(*event, ctx->arch, ctx->capture_args) << '\n';
    ctx->out->flush();
    if (!*ctx->out) {
        ctx->failed = true;
        return 0;
    }
    return 0;
}

static void usage(const char *program)
{
    std::cerr << "Usage: " << program
              << " [-o FILE] [--args] -- COMMAND [ARG ...]\n"
              << "Trace syscalls made by COMMAND and its descendants with eBPF.\n"
              << "  -o, --output FILE  JSONL destination (default: syzcall.jsonl)\n"
              << "      --args         include raw syscall arguments (off by default)\n";
}

static bool read_lost_events(int fd, unsigned long long &total)
{
    const int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0)
        return false;
    std::vector<__u64> per_cpu(static_cast<size_t>(cpus));
    __u32 zero = 0;
    if (bpf_map_lookup_elem(fd, &zero, per_cpu.data()) != 0)
        return false;
    total = 0;
    for (const auto value : per_cpu)
        total += value;
    return true;
}

static bool read_active_tasks(int fd, __u64 &active)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(fd, &zero, &active) == 0;
}

int main(int argc, char **argv)
{
    std::string output_path = "syzcall.jsonl";
    bool capture_args = false;
    int command_index = -1;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--") {
            command_index = i + 1;
            break;
        }
        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return 0;
        }
        if (arg == "--args") {
            capture_args = true;
            continue;
        }
        if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            output_path = argv[++i];
            continue;
        }
        std::cerr << "Unknown option: " << arg << '\n';
        usage(argv[0]);
        return 2;
    }
    if (command_index < 0 || command_index >= argc) {
        usage(argv[0]);
        return 2;
    }

    std::ofstream output(output_path, std::ios::out | std::ios::trunc);
    if (!output) {
        std::cerr << "Cannot open output file: " << output_path << '\n';
        return 1;
    }

    struct utsname system_info {};
    const std::string arch = uname(&system_info) == 0 ? system_info.machine : "unknown";

    struct syzcall_bpf *skel = syzcall_bpf__open();
    if (!skel) {
        std::cerr << "Failed to open generated BPF skeleton\n";
        return 1;
    }
    skel->rodata->capture_args = capture_args;
    int err = syzcall_bpf__load(skel);
    if (err) {
        std::cerr << "Failed to load BPF program: " << std::strerror(-err) << '\n';
        syzcall_bpf__destroy(skel);
        return 1;
    }
    err = syzcall_bpf__attach(skel);
    if (err) {
        std::cerr << "Failed to attach tracepoints: " << std::strerror(-err) << '\n';
        syzcall_bpf__destroy(skel);
        return 1;
    }

    output_context ctx{&output, arch, capture_args, false};
    struct ring_buffer *ring = ring_buffer__new(
        bpf_map__fd(skel->maps.events), on_event, &ctx, nullptr);
    if (!ring) {
        std::cerr << "Failed to create ring buffer\n";
        syzcall_bpf__destroy(skel);
        return 1;
    }

    int gate[2];
    if (pipe2(gate, O_CLOEXEC) != 0) {
        std::cerr << "pipe2: " << std::strerror(errno) << '\n';
        ring_buffer__free(ring);
        syzcall_bpf__destroy(skel);
        return 1;
    }

    const pid_t child = fork();
    if (child < 0) {
        std::cerr << "fork: " << std::strerror(errno) << '\n';
        close(gate[0]);
        close(gate[1]);
        ring_buffer__free(ring);
        syzcall_bpf__destroy(skel);
        return 1;
    }
    if (child == 0) {
        close(gate[1]);
        char go = 0;
        const ssize_t n = read(gate[0], &go, 1);
        close(gate[0]);
        if (n != 1 || go != 'G')
            _exit(125);
        execvp(argv[command_index], &argv[command_index]);
        std::cerr << "execvp " << argv[command_index] << ": "
                  << std::strerror(errno) << '\n';
        _exit(127);
    }

    close(gate[0]);
    __u32 zero = 0;
    const __u64 initial_active = 1;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.active_tasks),
                            &zero, &initial_active, BPF_ANY) != 0) {
        std::cerr << "Cannot initialize active task counter: "
                  << std::strerror(errno) << '\n';
        const char cancel = 'X';
        (void)write(gate[1], &cancel, 1);
        close(gate[1]);
        (void)waitpid(child, nullptr, 0);
        ring_buffer__free(ring);
        syzcall_bpf__destroy(skel);
        return 1;
    }

    const __u32 child_tid = static_cast<__u32>(child);
    const __u8 tracked = 1;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_tids),
                            &child_tid, &tracked, BPF_ANY) != 0) {
        std::cerr << "Cannot add command to the BPF filter: "
                  << std::strerror(errno) << '\n';
        const char cancel = 'X';
        (void)write(gate[1], &cancel, 1);
        close(gate[1]);
        (void)waitpid(child, nullptr, 0);
        ring_buffer__free(ring);
        syzcall_bpf__destroy(skel);
        return 1;
    }

    const char go = 'G';
    if (write(gate[1], &go, 1) != 1) {
        std::cerr << "Cannot release command start gate\n";
        close(gate[1]);
        (void)kill(child, SIGTERM);
        (void)waitpid(child, nullptr, 0);
        ring_buffer__free(ring);
        syzcall_bpf__destroy(skel);
        return 1;
    }
    close(gate[1]);

    int status = 0;
    bool child_reaped = false;
    bool done = false;
    bool poll_failed = false;
    while (!done) {
        const int events = ring_buffer__poll(ring, 100);
        if (events < 0 && events != -EINTR) {
            std::cerr << "Ring buffer poll failed: " << std::strerror(-events) << '\n';
            poll_failed = true;
            (void)kill(child, SIGTERM);
            (void)waitpid(child, &status, 0);
            break;
        }
        if (!child_reaped) {
            const pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child)
                child_reaped = true;
            else if (waited < 0 && errno != EINTR) {
                std::cerr << "waitpid: " << std::strerror(errno) << '\n';
                poll_failed = true;
                break;
            }
        }
        if (child_reaped) {
            __u64 active = 0;
            if (!read_active_tasks(bpf_map__fd(skel->maps.active_tasks), active)) {
                std::cerr << "Cannot read active task counter: "
                          << std::strerror(errno) << '\n';
                poll_failed = true;
                break;
            }
            done = active == 0;
        }
    }

    for (int i = 0; i < 3; ++i) {
        const int events = ring_buffer__poll(ring, 20);
        if (events <= 0)
            break;
    }

    int exit_code = 0;
    int child_signal = 0;
    if (WIFEXITED(status))
        exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) {
        child_signal = WTERMSIG(status);
        exit_code = 128 + child_signal;
    } else {
        exit_code = 125;
    }

    unsigned long long lost = 0;
    if (!read_lost_events(bpf_map__fd(skel->maps.lost_events), lost)) {
        std::cerr << "Cannot read lost event counter: "
                  << std::strerror(errno) << '\n';
        ring_buffer__free(ring);
        syzcall_bpf__destroy(skel);
        return 1;
    }
    output << summary_json(exit_code, child_signal, lost) << '\n';
    output.flush();

    ring_buffer__free(ring);
    syzcall_bpf__destroy(skel);
    if (ctx.failed || !output) {
        std::cerr << "Failed while writing trace output\n";
        return 1;
    }
    if (poll_failed)
        return 1;
    return exit_code;
}

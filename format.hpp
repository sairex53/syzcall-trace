#ifndef SYZCALL_FORMAT_HPP
#define SYZCALL_FORMAT_HPP

#include "event.h"

#include <string>
#include <string_view>
#include <sstream>
#include <iomanip>
#include <cstring>

inline std::string json_escape(std::string_view value)
{
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20)
                out << "\\u00" << std::hex << std::setw(2)
                    << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
            else
                out << static_cast<char>(c);
        }
    }
    return out.str();
}

inline std::string event_json(const syzcall_event &event, std::string_view arch,
                              bool include_args)
{
    const auto comm_len = ::strnlen(event.comm, sizeof(event.comm));
    std::ostringstream out;
    out << "{\"type\":\"syscall\",\"arch\":\"" << json_escape(arch)
        << "\",\"start_ns\":" << event.start_ns
        << ",\"duration_ns\":" << event.duration_ns
        << ",\"tgid\":" << event.tgid
        << ",\"tid\":" << event.tid
        << ",\"comm\":\"" << json_escape({event.comm, comm_len})
        << "\",\"syscall_nr\":" << event.syscall_nr
        << ",\"ret\":" << event.ret;
    if (include_args) {
        out << ",\"args\":[";
        for (int i = 0; i < SYZCALL_ARGS_COUNT; ++i) {
            if (i)
                out << ',';
            out << event.args[i];
        }
        out << ']';
    }
    out << '}';
    return out.str();
}

inline std::string summary_json(int exit_code, int signal, unsigned long long lost)
{
    std::ostringstream out;
    out << "{\"type\":\"summary\",\"exit_code\":" << exit_code
        << ",\"signal\":" << signal
        << ",\"lost_events\":" << lost << '}';
    return out.str();
}

#endif

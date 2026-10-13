#include "format.hpp"

#include <cassert>
#include <cstring>

int main()
{
    assert(json_escape("a\"b\\c\n") == "a\\\"b\\\\c\\n");

    syzcall_event event{};
    event.start_ns = 1234;
    event.duration_ns = 56;
    event.syscall_nr = 257;
    event.ret = -2;
    event.tgid = 10;
    event.tid = 11;
    std::memcpy(event.comm, "syz\"worker", 10);
    for (int i = 0; i < SYZCALL_ARGS_COUNT; ++i)
        event.args[i] = static_cast<sc_u64>(i + 1);

    const auto without_args = event_json(event, "x86_64", false);
    assert(without_args.find("\"comm\":\"syz\\\"worker\"") != std::string::npos);
    assert(without_args.find("\"syscall_nr\":257") != std::string::npos);
    assert(without_args.find("\"args\"") == std::string::npos);

    const auto with_args = event_json(event, "x86_64", true);
    assert(with_args.find("\"args\":[1,2,3,4,5,6]") != std::string::npos);
    assert(summary_json(0, 0, 3) ==
           "{\"type\":\"summary\",\"exit_code\":0,\"signal\":0,\"lost_events\":3}");
}

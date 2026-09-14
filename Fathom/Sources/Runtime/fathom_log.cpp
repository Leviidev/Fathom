#include "fathom_log.h"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace fathom {
namespace {

std::mutex g_sink_mutex;
fathom_log_sink g_sink = nullptr;
void* g_sink_context = nullptr;
std::atomic<int> g_level {FATHOM_LOG_INFO};

} // namespace

bool LogEnabled(fathom_log_level level) {
    return static_cast<int>(level) >= g_level.load(std::memory_order_relaxed);
}

void Log(fathom_log_level level, const char* format, ...) {
    if (!LogEnabled(level)) {
        return;
    }

    char message[1024];
    va_list args;
    va_start(args, format);
    std::vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    fathom_log_sink sink = nullptr;
    void* context = nullptr;
    {
        std::scoped_lock lock {g_sink_mutex};
        sink = g_sink;
        context = g_sink_context;
    }

    if (sink != nullptr) {
        sink(context, level, message);
    } else {
        // Before Swift installs its sink (early startup, or a unit test harness) there is
        // still value in the line existing somewhere.
        std::fprintf(stderr, "[fathom] %s\n", message);
    }
}

} // namespace fathom

extern "C" void fathom_set_log_sink(fathom_log_sink sink, void* context) {
    std::scoped_lock lock {fathom::g_sink_mutex};
    fathom::g_sink = sink;
    fathom::g_sink_context = context;
}

extern "C" void fathom_set_log_level(fathom_log_level level) {
    fathom::g_level.store(static_cast<int>(level), std::memory_order_relaxed);
}

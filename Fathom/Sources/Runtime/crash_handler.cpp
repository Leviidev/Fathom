// crash_handler.cpp -- the last thing Fathom does when the process is about to die.
//
// A sideloaded app has no debugger attached and no crash report you can read on the
// device, and a hard fault inside the JIT simply ends the process: the log file stops
// mid-line with no indication of why. This writes one final record first.
//
// Everything here runs inside a signal handler after something has already gone badly
// wrong, so it uses only async-signal-safe calls: a file descriptor opened ahead of
// time, write(), and hand-rolled number formatting. No malloc, no stdio, no locks.

#include "fathom_api.h"

#include <atomic>
#include <csignal>
#include <initializer_list>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace fathom {
namespace {

int g_crash_fd = -1;

// Updated on every guest syscall. Plain atomics, so reading them from a signal handler
// is safe -- and the last syscall the guest made is usually the single most useful fact
// about where it died.
std::atomic<uint64_t> g_last_syscall {UINT64_MAX};
std::atomic<uint64_t> g_last_syscall_arg {0};
std::atomic<uint64_t> g_syscall_count {0};
std::atomic<uint64_t> g_last_guest_rip {0};

void WriteRaw(const char* text, size_t length) {
    if (g_crash_fd < 0) {
        return;
    }
    ssize_t ignored = write(g_crash_fd, text, length);
    (void)ignored;
}

void WriteText(const char* text) {
    WriteRaw(text, std::strlen(text));
}

void WriteHex(uint64_t value) {
    char buffer[19];
    buffer[0] = '0';
    buffer[1] = 'x';
    size_t position = sizeof(buffer);
    if (value == 0) {
        buffer[--position] = '0';
    }
    while (value != 0 && position > 2) {
        const auto digit = static_cast<unsigned>(value & 0xF);
        buffer[--position] = static_cast<char>(digit < 10 ? '0' + digit : 'a' + (digit - 10));
        value >>= 4;
    }
    WriteRaw("0x", 2);
    WriteRaw(buffer + position, sizeof(buffer) - position);
}

void WriteDecimal(uint64_t value) {
    char buffer[21];
    size_t position = sizeof(buffer);
    if (value == 0) {
        buffer[--position] = '0';
    }
    while (value != 0 && position > 0) {
        buffer[--position] = static_cast<char>('0' + (value % 10));
        value /= 10;
    }
    WriteRaw(buffer + position, sizeof(buffer) - position);
}

const char* SignalName(int number) {
    switch (number) {
    case SIGSEGV: return "SIGSEGV (bad memory access)";
    case SIGBUS: return "SIGBUS (bad address / alignment)";
    case SIGILL: return "SIGILL (illegal instruction)";
    case SIGTRAP: return "SIGTRAP (breakpoint -- usually a JIT trap with no debugger to service it)";
    case SIGABRT: return "SIGABRT (abort)";
    case SIGFPE: return "SIGFPE (arithmetic)";
    default: return "signal";
    }
}

void Handle(int number, siginfo_t* info, void* context) {
    (void)context;

    WriteText("\n=== FATHOM CRASH ===\nsignal: ");
    WriteText(SignalName(number));
    WriteText("\nfault address: ");
    WriteHex(info == nullptr ? 0 : reinterpret_cast<uint64_t>(info->si_addr));

    WriteText("\nguest syscalls so far: ");
    WriteDecimal(g_syscall_count.load(std::memory_order_relaxed));

    const uint64_t last = g_last_syscall.load(std::memory_order_relaxed);
    if (last != UINT64_MAX) {
        WriteText("\nlast guest syscall: ");
        WriteDecimal(last);
        WriteText(" arg0=");
        WriteHex(g_last_syscall_arg.load(std::memory_order_relaxed));
    } else {
        WriteText("\nlast guest syscall: none (died before the guest made one)");
    }

    const uint64_t rip = g_last_guest_rip.load(std::memory_order_relaxed);
    if (rip != 0) {
        WriteText("\nlast known guest RIP: ");
        WriteHex(rip);
    }
    WriteText("\n=== END ===\n");

    fsync(g_crash_fd);

    // Restore the default action and re-raise, so the process still dies the way it
    // would have and iOS still records its own crash report.
    signal(number, SIG_DFL);
    raise(number);
}

} // namespace

void NoteSyscall(uint64_t number, uint64_t first_argument, uint64_t count) {
    g_last_syscall.store(number, std::memory_order_relaxed);
    g_last_syscall_arg.store(first_argument, std::memory_order_relaxed);
    g_syscall_count.store(count, std::memory_order_relaxed);
}

void NoteGuestRip(uint64_t rip) {
    g_last_guest_rip.store(rip, std::memory_order_relaxed);
}

} // namespace fathom

extern "C" void fathom_install_crash_handler(const char* log_path) {
    if (log_path == nullptr) {
        return;
    }
    // Opened now, while everything still works. Opening a file from inside a signal
    // handler is exactly the kind of thing that fails when it matters.
    fathom::g_crash_fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fathom::g_crash_fd < 0) {
        return;
    }

    struct sigaction action {};
    action.sa_sigaction = fathom::Handle;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);

    for (const int number : {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP}) {
        sigaction(number, &action, nullptr);
    }
}

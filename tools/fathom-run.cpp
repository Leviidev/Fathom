// fathom-run.cpp -- Fathom's emulator runtime as a macOS command-line program.
//
// The same runtime the iOS app embeds, running natively on the Mac. It exists because the
// device loop is slow: build an unsigned IPA, sideload it, enable JIT through StikDebug,
// drive the app by hand, pull the log back off the phone. Here a change can be run in
// seconds, which is the difference between finding a bug like "the forked child resumed
// on the syscall instruction instead of after it" in one minute or in one afternoon.
//
// Nothing here is a simulation of the emulator. It is the emulator, compiled for a
// different host, with a terminal instead of a SwiftUI view.

#include "fathom_api.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

fathom_session* g_session = nullptr;
std::atomic<bool> g_running {true};
termios g_saved_termios {};
bool g_termios_saved = false;

void WriteOut(void* /*context*/, int fd, const char* bytes, size_t length) {
    // Straight through, unbuffered: the guest's idea of when output appears is the whole
    // point of a terminal, and a libc buffer in the middle would hide it.
    ::write(fd == 2 ? STDERR_FILENO : STDOUT_FILENO, bytes, length);
}

void LogLine(void* /*context*/, fathom_log_level level, const char* message) {
    if (message != nullptr) {
        std::fprintf(stderr, "[fathom:%d] %s\n", static_cast<int>(level), message);
    }
}

void RestoreTerminal() {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_termios_saved = false;
    }
}

/// Puts the *host* terminal in raw mode, so keystrokes reach the guest one at a time
/// rather than a line at a time. The guest has its own idea of terminal mode, which it
/// sets through ioctl; this is only about not letting the Mac's line discipline eat the
/// keys first.
void RawTerminal() {
    if (!isatty(STDIN_FILENO)) {
        return;
    }
    if (tcgetattr(STDIN_FILENO, &g_saved_termios) != 0) {
        return;
    }
    g_termios_saved = true;
    std::atexit(RestoreTerminal);

    termios raw = g_saved_termios;
    raw.c_lflag &= ~static_cast<tcflag_t>(ICANON | ECHO | ISIG);
    raw.c_iflag &= ~static_cast<tcflag_t>(IXON | ICRNL);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

void Usage() {
    std::fprintf(stderr,
                 "usage: fathom-run [options] <program> [args...]\n"
                 "\n"
                 "  --root DIR     host directory presented to the guest as \"/\"\n"
                 "  --cwd DIR      guest-absolute starting directory (default \"/\")\n"
                 "  --env K=V      add an environment variable (repeatable)\n"
                 "  --trace        log every guest syscall\n"
                 "  --tso          emulate x86 memory ordering (every unaligned access then faults)\n"
                 "  --arena MB     guest address space reservation\n"
                 "\n"
                 "The program path is guest-absolute when --root is given, so\n"
                 "  fathom-run --root ./rootfs /bin/sh\n"
                 "runs the shell out of that root filesystem.\n");
}

} // namespace

int main(int argc, char** argv) {
    std::string root;
    std::string cwd = "/";
    std::vector<std::string> env;
    bool trace = false;
    bool tso = false;
    bool multiblock = true;
    bool avx = true;
    uint64_t arena_mb = 0;

    int index = 1;
    for (; index < argc; ++index) {
        const std::string option = argv[index];
        if (option == "--root" && index + 1 < argc) {
            root = argv[++index];
        } else if (option == "--cwd" && index + 1 < argc) {
            cwd = argv[++index];
        } else if (option == "--env" && index + 1 < argc) {
            env.emplace_back(argv[++index]);
        } else if (option == "--trace") {
            trace = true;
        } else if (option == "--no-multiblock") {
            // Changes how FEX stitches guest basic blocks together. If a fault goes away
            // with this off, the problem is in the JIT rather than in the guest.
            multiblock = false;
        } else if (option == "--no-avx") {
            avx = false;
        } else if (option == "--tso") {
            // Emulating x86's memory ordering makes FEX emit acquire and release for
            // every guest load and store, and those require natural alignment on ARM64
            // while x86 permits none. Every unaligned guest access then raises SIGBUS and
            // is emulated by hand -- Steam's client spends over ninety per cent of its
            // time in that handler. Off by default for that reason, and on here only when
            // a guest's threads are racing in a way that needs the stricter ordering.
            tso = true;
        } else if (option == "--arena" && index + 1 < argc) {
            arena_mb = std::strtoull(argv[++index], nullptr, 10);
        } else if (option == "--help" || option == "-h") {
            Usage();
            return 0;
        } else {
            break;
        }
    }
    if (index >= argc) {
        Usage();
        return 2;
    }

    const std::string guest_program = argv[index];
    std::vector<std::string> guest_argv;
    for (int arg = index; arg < argc; ++arg) {
        guest_argv.emplace_back(argv[arg]);
    }

    if (env.empty()) {
        env.emplace_back("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        env.emplace_back("HOME=/root");
        env.emplace_back("TERM=xterm-256color");
        env.emplace_back("PS1=fathom:\\w\\$ ");
    }

    // Not optional. This installs the SIGBUS handler that FEXCore's alignment-fault
    // recovery runs from: x86 allows unaligned stores, ARM64's store-release does not,
    // and emulating x86's memory ordering means FEX emits store-release constantly. With
    // no handler the first unaligned one kills the process outright.
    fathom_install_crash_handler((std::string {getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp"} +
                                  "/fathom-run.crash.log").c_str());

    fathom_set_log_sink(&LogLine, nullptr);
    fathom_set_log_level(trace ? FATHOM_LOG_DEBUG : FATHOM_LOG_INFO);

    // A guest-absolute path resolved against the root, the same way the app does it, so
    // "/bin/sh" means the shell inside the root filesystem rather than the Mac's own.
    std::string host_program = guest_program;
    if (!root.empty() && !guest_program.empty() && guest_program.front() == '/') {
        host_program = root + guest_program;
    }

    std::vector<const char*> argv_pointers;
    for (const auto& entry : guest_argv) {
        argv_pointers.push_back(entry.c_str());
    }
    std::vector<const char*> env_pointers;
    for (const auto& entry : env) {
        env_pointers.push_back(entry.c_str());
    }

    fathom_session_config config;
    fathom_session_config_defaults(&config);
    config.program_path = host_program.c_str();
    config.guest_root = root.empty() ? nullptr : root.c_str();
    config.work_dir = cwd.c_str();
    config.argv = argv_pointers.data();
    config.argc = static_cast<int>(argv_pointers.size());
    config.envp = env_pointers.data();
    config.envc = static_cast<int>(env_pointers.size());
    config.trace_syscalls = trace;
    config.tso_enabled = tso;
    config.multiblock = multiblock;
    config.disable_avx = !avx;
    if (arena_mb != 0) {
        config.address_space_size = arena_mb * 1024 * 1024;
    }

    char error[512] = {};
    g_session = fathom_session_create(&config, error, sizeof(error));
    if (g_session == nullptr) {
        std::fprintf(stderr, "fathom-run: %s\n", error[0] != '\0' ? error : "could not create session");
        return 1;
    }

    fathom_session_set_output_sink(g_session, &WriteOut, nullptr);
    RawTerminal();

    // Host stdin into the guest. Detached because the guest decides when the program
    // ends, and a thread parked in read() must not hold that up.
    std::thread input {[] {
        char buffer[256];
        while (g_running.load(std::memory_order_relaxed)) {
            const ssize_t count = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count <= 0) {
                // No terminal, or the one there was has gone. The guest is told, so that
                // a program reading standard input sees end-of-file instead of waiting.
                fathom_session_close_input(g_session);
                break;
            }
            fathom_session_send_input(g_session, buffer, static_cast<size_t>(count));
        }
    }};
    input.detach();

    const int status = fathom_session_run(g_session);

    g_running.store(false, std::memory_order_relaxed);
    RestoreTerminal();

    fathom_session_status final_status {};
    fathom_session_get_status(g_session, &final_status);

    // Which of these it was matters: a guest that halted did not call exit, it ran off
    // into memory that was not code. Reporting that as a clean exit 0 hides real crashes.
    const char* outcome = "unknown";
    switch (final_status.state) {
    case FATHOM_STATE_EXITED: outcome = "exited"; break;
    case FATHOM_STATE_STOPPED: outcome = "stopped"; break;
    case FATHOM_STATE_FAULTED: outcome = "FAULTED"; break;
    case FATHOM_STATE_RUNNING: outcome = "still running"; break;
    default: break;
    }
    const char* message = final_status.message[0] != '\0' ? final_status.message : "";
    std::fprintf(stderr, "\n[fathom-run] %s (status %d) after %llu syscalls at rip %#llx%s%s\n",
                 outcome, status, static_cast<unsigned long long>(final_status.syscall_count),
                 static_cast<unsigned long long>(final_status.rip),
                 message[0] != '\0' ? ": " : "", message);

    fathom_session_destroy(g_session);
    return status;
}

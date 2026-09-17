// guest_console.h -- the parts of the guest system that are not any one process's.
//
// Until now there was exactly one guest process, so the console it typed at, the display
// it drew on, and the flag that stopped it could all live inside its syscall handler.
// Processes change that: a shell and the command it runs are two processes with two file
// descriptor tables and two address spaces, but they share one keyboard and one screen,
// and stopping is something that happens to all of them at once.
//
// This holds precisely the shared half. Everything still in LinuxSyscalls -- the open
// files, the working directory, the heap -- is per-process, and is what a fork has to
// copy and an exec has to replace.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>

namespace fathom {

/// Where a guest's stdout and stderr go.
using OutputCallback = void (*)(void* context, int fd, const char* bytes, size_t length);

class GuestConsole {
public:
    struct Framebuffer {
        uint64_t address {};
        uint32_t width {};
        uint32_t height {};
        uint32_t stride {};
        uint32_t bits_per_pixel {};
    };

    // --- the console every process writes to -------------------------------------
    void SetOutputCallback(OutputCallback callback, void* context);
    void Write(int fd, const char* bytes, size_t length);

    /// Queues bytes for whichever process is reading fd 0. Safe from any thread.
    void SendInput(const char* bytes, size_t length);

    /// Reads up to `max` bytes, blocking until a key arrives unless stdin is
    /// non-blocking. Returns the count, 0 if stopped, or -1 meaning EAGAIN.
    int64_t ReadInput(char* out, size_t max);

    bool InputAvailable() const;

    /// Says there will be no more input, ever. A guest reading standard input then gets
    /// end-of-file rather than waiting: a program run without a terminal -- Steam, started
    /// from a script -- reads it once at startup, and a read that never returns is a main
    /// loop that never runs again.
    void CloseInput();

    /// Sleeps until a key arrives or the slice elapses; used by poll.
    void WaitForInput(int milliseconds);

    void SetRawMode(bool raw) { raw_mode_.store(raw, std::memory_order_relaxed); }
    bool WantsKeys() const { return raw_mode_.load(std::memory_order_relaxed); }
    void SetNonblockingStdin(bool value) { nonblocking_stdin_.store(value, std::memory_order_relaxed); }

    // --- the display -------------------------------------------------------------
    void SetFramebuffer(const Framebuffer& framebuffer);
    Framebuffer Display() const;
    void NotePresentation() { frame_presentations_.fetch_add(1, std::memory_order_relaxed); }
    uint64_t FramePresentations() const { return frame_presentations_.load(std::memory_order_relaxed); }

    // --- lifecycle, which applies to every process at once ------------------------
    void RequestStop();
    bool StopRequested() const { return stop_requested_.load(std::memory_order_relaxed); }

    void NoteSyscall() { syscall_count_.fetch_add(1, std::memory_order_relaxed); }
    uint64_t SyscallCount() const { return syscall_count_.load(std::memory_order_relaxed); }

private:
    mutable std::mutex output_mutex_;
    OutputCallback output_ {};
    void* output_context_ {};

    std::atomic<bool> input_closed_ {false};
    mutable std::mutex input_mutex_;
    std::condition_variable input_ready_;
    std::deque<char> input_;
    std::atomic<bool> raw_mode_ {false};
    std::atomic<bool> nonblocking_stdin_ {false};

    mutable std::mutex framebuffer_mutex_;
    Framebuffer framebuffer_;
    std::atomic<uint64_t> frame_presentations_ {0};

    std::atomic<bool> stop_requested_ {false};
    std::atomic<uint64_t> syscall_count_ {0};
};

} // namespace fathom

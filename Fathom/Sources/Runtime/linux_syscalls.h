// linux_syscalls.h -- the "kernel" half of the emulator.
//
// FEXCore translates x86-64 instructions to ARM64; it does not implement Linux. When
// the guest executes a SYSCALL instruction, everything the guest asked the operating
// system for lands here, and this file answers it using iOS facilities.
//
// Two things are emulated rather than forwarded, and both matter:
//
//   * Paths. The guest sees a root filesystem rooted at a directory inside the app's
//     container. A guest-absolute path is resolved against that root, with ".." unable
//     to climb out, so a guest program cannot reach the rest of the device.
//
//   * Structure layouts. Linux's struct stat, dirent64, utsname and timeval are not
//     Darwin's. Every one of them is written out field by field at the offsets an
//     x86-64 Linux binary expects, rather than memcpy'ing a host struct across.
#pragma once

#include "guest_console.h"
#include "guest_memory.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace fathom {

/// What the syscall layer needs from whatever is driving the CPU.
class GuestThreadControl {
public:
    virtual ~GuestThreadControl() = default;

    /// Backing store for the guest's FS segment base, which is where its thread-local
    /// storage lives. Set through arch_prctl(ARCH_SET_FS) during libc startup.
    virtual void SetFsBase(uint64_t base) = 0;
    virtual uint64_t GetFsBase() const = 0;

    /// Unwinds out of the JIT and ends the run. Never returns.
    [[noreturn]] virtual void ExitGuest(int status) = 0;
};

struct SyscallConfig {
    std::string guest_root;  ///< Host directory presented to the guest as "/".
    std::string work_dir {"/"};
    bool trace {};
};

class LinuxSyscalls {
public:
    LinuxSyscalls(GuestAddressSpace& space, GuestThreadControl& control, GuestConsole& console,
                  SyscallConfig config);
    ~LinuxSyscalls();

    /// Entry point from FEXCore. `number` is RAX; the arguments are RDI, RSI, RDX, R10,
    /// R8, R9 in that order. The return value is what lands back in RAX, with errors
    /// returned as a negated errno the way the Linux kernel does it.
    uint64_t Handle(uint64_t number, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
                    uint64_t arg5, uint64_t arg6);

    void SetOutputCallback(OutputCallback callback, void* context) { console_.SetOutputCallback(callback, context); }

    /// Queues bytes for the guest to read from fd 0. Safe from any thread.
    void SendInput(const char* bytes, size_t length) { console_.SendInput(bytes, length); }

    /// True once the guest has asked for raw (non-canonical) terminal mode.
    bool WantsKeys() const { return console_.WantsKeys(); }

    using Framebuffer = GuestConsole::Framebuffer;

    /// The guest's display, once it has opened /dev/fb0. `address` is 0 until then.
    Framebuffer Display() const { return console_.Display(); }
    uint64_t FramePresentations() const { return console_.FramePresentations(); }

    /// Asks every guest process to stop at its next syscall. Safe from any thread.
    void RequestStop() { console_.RequestStop(); }
    bool StopRequested() const { return console_.StopRequested(); }

    uint64_t SyscallCount() const { return console_.SyscallCount(); }
    int ExitStatus() const { return exit_status_; }

    /// Where the guest's heap starts; established once the program image is loaded.
    void InitialiseHeap(uint64_t base, uint64_t reserved);

private:
    struct OpenFile {
        int host_fd {-1};
        std::string guest_path;
        void* directory {};      ///< DIR* once getdents64 has been used on this fd.
        bool is_framebuffer {};  ///< A virtual fd for /dev/fb0, backed by no host file.
    };

    // Path handling.
    std::string NormaliseGuestPath(const std::string& path) const;
    std::string ResolveGuestPath(const std::string& path) const;
    std::string ResolveAt(int dirfd, const char* path, std::string* guest_path_out);

    // Guest memory helpers. Every pointer a guest hands over is checked before use --
    // a wild guest pointer must fail the syscall, not fault the whole app.
    bool ReadGuestString(uint64_t address, std::string* out, size_t limit = 4096) const;
    void* GuestPointer(uint64_t address, uint64_t size, bool writable) const;

    /// The switch itself. Split out from Handle so tracing can wrap it and log what
    /// each call actually returned.
    uint64_t Dispatch(uint64_t number, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
                      uint64_t arg5, uint64_t arg6);

    // Individual syscalls that are long enough to deserve a name.
    uint64_t DoOpenAt(int dirfd, uint64_t path_address, int flags, int mode);
    uint64_t DoRead(int fd, uint64_t buffer, uint64_t count);
    uint64_t DoPoll(uint64_t fds_address, uint64_t count, int timeout_ms);
    uint64_t DoWrite(int fd, uint64_t buffer, uint64_t count);
    uint64_t DoWritev(int fd, uint64_t iov, uint64_t count);
    uint64_t DoReadv(int fd, uint64_t iov, uint64_t count);
    uint64_t DoStatAt(int dirfd, uint64_t path_address, uint64_t stat_address, int flags);
    uint64_t DoFstat(int fd, uint64_t stat_address);
    uint64_t DoGetdents64(int fd, uint64_t buffer, uint64_t size);
    uint64_t DoMmap(uint64_t address, uint64_t length, int protection, int flags, int fd, int64_t offset);
    uint64_t DoBrk(uint64_t requested);
    uint64_t DoUname(uint64_t address);
    uint64_t DoFramebufferIoctl(uint64_t request, uint64_t argument);
    bool EnsureFramebuffer();
    uint64_t DoClockGettime(int clock, uint64_t address);
    uint64_t DoReadlinkAt(int dirfd, uint64_t path_address, uint64_t buffer, uint64_t size);

    OpenFile* FindFile(int fd);
    int RegisterFile(int host_fd, std::string guest_path);
    void CloseAll();

    GuestAddressSpace& space_;
    GuestThreadControl& control_;
    GuestConsole& console_;
    SyscallConfig config_;

    mutable std::mutex mutex_;
    std::map<int, OpenFile> files_;
    std::string cwd_ {"/"};

    /// Per-process: what this process passed to exit, and where set_tid_address pointed.
    int exit_status_ {};

    uint64_t heap_base_ {};
    uint64_t heap_limit_ {};
    uint64_t heap_break_ {};

    /// Guest address passed to set_tid_address, cleared on exit the way Linux does.
    uint64_t clear_child_tid_ {};

};

} // namespace fathom

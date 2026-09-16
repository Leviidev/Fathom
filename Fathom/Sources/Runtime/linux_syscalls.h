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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <atomic>
#include <memory>
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

    /// Installs a thread-local-storage descriptor in the guest's GDT. This is how a
    /// 32-bit guest does what a 64-bit one does with arch_prctl: set_thread_area fills in
    /// a descriptor, and the guest then loads %gs with (entry << 3) | 3 so that every
    /// %gs-relative access lands on its thread's storage. `base` is a guest address.
    virtual void SetTlsDescriptor(int entry, uint32_t base, uint32_t limit) = 0;

    /// Unwinds out of the JIT and ends the run. Never returns.
    [[noreturn]] virtual void ExitGuest(int status) = 0;

    /// Unwinds out of the JIT so the process can restart on a newly loaded image.
    [[noreturn]] virtual void ExecGuest() = 0;
};

class LinuxSyscalls;

/// What the syscall layer needs from whatever owns the process table.
///
/// fork, execve and wait4 are the three syscalls a process cannot answer by itself: they
/// are about the set of processes, not about this one. Everything to do with creating
/// threads, loading images and reaping children lives on the other side of this.
class ProcessHost {
public:
    virtual ~ProcessHost() = default;

    /// Creates a child sharing this process's memory, and blocks the caller until that
    /// child execs or exits -- vfork's bargain, and what makes sharing memory safe.
    /// Returns the child's pid, or a negated errno.
    virtual int64_t ForkProcess(int caller_pid) = 0;

    /// Loads `path` for the calling process. On success the caller does not return here:
    /// it unwinds out of the JIT and is restarted on the new image.
    virtual int64_t ExecProcess(int caller_pid, const std::string& path,
                                std::vector<std::string> argv, std::vector<std::string> envp) = 0;

    /// Blocks until a child exits. Returns the reaped pid, or a negated errno.
    virtual int64_t WaitForChild(int caller_pid, int wanted_pid, int* exit_status, int options) = 0;

    /// Creates a thread of the calling process: same memory, same descriptors, same pid,
    /// running from the same instruction on a stack of its own. Returns the new thread
    /// id, or a negated errno.
    virtual int64_t CreateThread(int caller_pid, uint64_t flags, uint64_t stack,
                                 uint64_t parent_tid_address, uint64_t child_tid_address,
                                 uint64_t tls) = 0;
};

struct SyscallConfig {
    std::string guest_root;  ///< Host directory presented to the guest as "/".
    std::string work_dir {"/"};
    bool trace {};
    /// True when the guest is an i386 binary, whose syscalls are numbered differently.
    bool guest_is_32bit {};
    /// Where this process's address space starts in the host's. Zero for a 64-bit guest,
    /// which is mapped one to one; the arena's base for a 32-bit one, whose pointers are
    /// only 32 bits wide and cannot reach where the arena actually lives. It is a
    /// property of the process rather than of the address space, because a 32-bit program
    /// can start a 64-bit one -- Steam's client is i386 and the process that draws its
    /// interface is x86-64.
    uint64_t guest_base {};
};

class LinuxSyscalls {
public:
    LinuxSyscalls(GuestAddressSpace& space, GuestThreadControl& control, GuestConsole& console,
                  SyscallConfig config);

    /// Who this process is, and who owns the table it belongs to. Set once, before it runs.
    void SetProcess(int pid, int ppid, ProcessHost* host);
    int Pid() const { return pid_; }

    /// Distinguishes a thread from the process it belongs to. getpid reports the process,
    /// gettid this; for a process's first thread they are the same number.
    void SetThreadId(int tid) { tid_ = tid; }
    int Tid() const { return tid_ != 0 ? tid_ : pid_; }

    /// Where the guest asked for this thread's id to be cleared when it exits, which is
    /// how pthread_join learns the thread is gone. Zero when it asked for nothing.
    uint64_t ClearChildTid() const { return clear_child_tid_; }
    void SetClearChildTid(uint64_t address) { clear_child_tid_ = address; }

    /// Clears that word and wakes anything waiting on it. Called as a thread ends.
    void ReleaseThreadId();

    /// Wakes every guest thread waiting on `address`. Used by thread teardown, which has
    /// to do what the kernel does on the way out.
    static void WakeFutex(uint64_t host_address);

    /// Duplicates this process's open files, working directory and heap into `child`,
    /// which is what a fork inherits.
    void CloneInto(LinuxSyscalls& child) const;

    /// Points `thread` at this process's own descriptor table and heap rather than a copy.
    /// This is the difference between a fork and a thread, and it is the whole of it as
    /// far as this layer is concerned.
    void ShareInto(LinuxSyscalls& thread) const;

    /// Points the process at a new program image after an execve.
    void AdoptImage(uint64_t heap_base, uint64_t heap_reserved, const std::string& path);

    /// An exec can change the process's word size -- a 32-bit program can exec a 64-bit
    /// one -- and with it where its address space sits in the host's.
    void AdoptWordSize(bool is_32bit, uint64_t base) {
        config_.guest_is_32bit = is_32bit;
        config_.guest_base = base;
    }

    /// The guest path of the program this process is running. Reported through
    /// /proc/self/exe, which a program uses to find and re-run its own binary.
    void SetProgramPath(std::string path) { program_path_ = std::move(path); }
    const std::string& ProgramPath() const { return program_path_; }
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

    /// Asks the threads of *this* process to stop, without touching any other process.
    /// A process whose first thread has returned has to bring its others back before it
    /// can be destroyed: they are still inside the JIT holding references to state that
    /// goes away with it.
    void RequestProcessStop() { process_stopping_->store(true, std::memory_order_release); }
    void ClearProcessStop() { process_stopping_->store(false, std::memory_order_release); }

    /// What every blocking loop here waits on: either the session stopping or this
    /// process stopping.
    bool ShouldStop() const {
        return console_.StopRequested() || process_stopping_->load(std::memory_order_acquire);
    }

    uint64_t SyscallCount() const { return console_.SyscallCount(); }
    int ExitStatus() const { return exit_status_; }

    /// What this process has mapped, so a fork knows which of the arena's writable
    /// regions belong to it. The arena is shared by every process, so asking it directly
    /// would sweep up the memory of unrelated ones.
    std::vector<std::pair<uint64_t, uint64_t>> Mappings() const;

    /// Closes everything this process had open. Called when it *exits*, not when it is
    /// reaped: a pipe reaches end-of-file only once every copy of its write end is gone,
    /// and a parent blocked reading that pipe is in no position to reap anybody.
    void ReleaseDescriptors() { CloseAll(); }

    /// How far brk has grown: the part of the heap a fork actually has to preserve.
    uint64_t HeapBreak() const;

    /// Where the guest's heap starts; established once the program image is loaded.
    void InitialiseHeap(uint64_t base, uint64_t reserved);

    /// The argument vector this process was started with, which /proc/self/cmdline reports.
    void SetCommandLine(std::vector<std::string> argv);

private:
    /// The counter behind an eventfd.
    ///
    /// Darwin has no eventfd, so one is built out of a pipe plus this: the pipe exists
    /// only so that poll and select can see the descriptor become readable, and the
    /// value the guest reads and writes lives here. Shared through a pointer because a
    /// fork inherits the same object the way it inherits the same pipe.
    struct EventCounter {
        std::mutex mutex;
        uint64_t value {};
        bool semaphore {};    ///< EFD_SEMAPHORE: a read takes one, not all of it.
        int signal_write_fd {-1};
        bool signalled {};    ///< Whether the pipe currently holds its wake-up byte.
    };

    /// One descriptor's registration in an epoll set.
    struct EpollInterest {
        uint32_t events {};
        uint64_t data {};
    };

    /// An epoll set. Level-triggered only, answered by polling the registered
    /// descriptors -- which is what epoll is, minus the kernel's readiness list.
    struct EpollSet {
        std::mutex mutex;
        std::map<int, EpollInterest> interests;
    };

    /// What the threads of one process share, and what a fork duplicates instead.
    ///
    /// Every guest thread gets its own LinuxSyscalls, because each needs its own thread
    /// id, its own GuestThreadControl and its own exit status. Linux gives all of them
    /// one descriptor table and one heap, though, and a program that opens a file on one
    /// thread and reads it on another depends on precisely that.
    struct OpenFile {
        int host_fd {-1};
        std::string guest_path;
        void* directory {};      ///< DIR* once getdents64 has been used on this fd.
        bool is_framebuffer {};  ///< A virtual fd for /dev/fb0, backed by no host file.
        /// 0, 1 or 2 when this descriptor is the console itself rather than a file. A
        /// shell redirects by pointing fd 1 somewhere else, so "is this the terminal" has
        /// to be a property of the entry, not of the number.
        int console_stream {-1};
        /// Set when this descriptor is an eventfd or an epoll set rather than a file.
        std::shared_ptr<EventCounter> event;
        std::shared_ptr<EpollSet> epoll;
        /// Set when this descriptor is a timerfd. Darwin has no timerfd, but it has
        /// kqueue, whose descriptor becomes readable exactly when a timer it carries
        /// fires -- so poll and epoll see it without knowing it is anything unusual.
        bool is_timer {};
        /// What the guest last asked for, because timerfd_gettime has to answer with it.
        int64_t timer_interval_ns {};
        int64_t timer_value_ns {};
    };

    /// What the threads of one process share, and what a fork duplicates instead.
    ///
    /// Every guest thread gets its own LinuxSyscalls, because each needs its own thread
    /// id, its own GuestThreadControl and its own exit status. Linux gives all of them
    /// one descriptor table and one heap, though, and a program that opens a file on one
    /// thread and reads it on another depends on precisely that.
    struct ProcessFiles {
        mutable std::mutex mutex;
        std::map<int, OpenFile> files;
        std::string cwd {"/"};
        uint64_t heap_base {};
        uint64_t heap_limit {};
        uint64_t heap_break {};
        /// Address and length of each live mmap the process made.
        std::vector<std::pair<uint64_t, uint64_t>> mappings;
    };

    /// Lowest unused guest descriptor, which is the number open() and pipe() must return:
    /// a shell closes fd 0 and opens a file precisely because it knows it gets fd 0 back.
    int AllocateFd();
    bool IsConsole(int fd);
    /// The host descriptor behind a guest one, or -1.
    int HostFdFor(int guest_fd);
    uint64_t DoMessage(int fd, uint64_t header_address, int flags, bool sending);
    /// sendmmsg and recvmmsg: an array of msghdrs, each with the byte count written back.
    uint64_t DoMultiMessage(int fd, uint64_t vector_address, uint64_t count, int flags, bool sending);
    int DuplicateTo(const OpenFile& file, int target);
    void CloseFd(int fd);

    // Path handling.
    std::string NormaliseGuestPath(const std::string& path) const;
    std::string ResolveGuestPath(const std::string& path, bool follow_final = true) const;
    std::string ResolveAt(int dirfd, const char* path, std::string* guest_path_out,
                          bool follow_final = true);

    // Guest memory helpers. Every pointer a guest hands over is checked before use --
    // a wild guest pointer must fail the syscall, not fault the whole app.
    bool ReadGuestString(uint64_t address, std::string* out, size_t limit = 4096) const;
    bool ReadGuestStringArray(uint64_t address, std::vector<std::string>* out) const;
    void* GuestPointer(uint64_t address, uint64_t size, bool writable) const;

    /// This process's view of the address space. Identity for a 64-bit guest.
    uint64_t ToHost(uint64_t guest_address) const { return guest_address + config_.guest_base; }
    uint64_t ToGuest(uint64_t host_address) const { return host_address - config_.guest_base; }

    /// The switch itself. Split out from Handle so tracing can wrap it and log what
    /// each call actually returned.
    uint64_t Dispatch(uint64_t number, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
                      uint64_t arg5, uint64_t arg6);

    // Individual syscalls that are long enough to deserve a name.
    uint64_t DoOpenAt(int dirfd, uint64_t path_address, int flags, int mode);
    uint64_t DoRead(int fd, uint64_t buffer, uint64_t count);
    uint64_t DoPoll(uint64_t fds_address, uint64_t count, int timeout_ms);
    uint64_t DoSelect(int count, uint64_t read_address, uint64_t write_address,
                      uint64_t except_address, int64_t timeout_us);
    uint64_t DoWrite(int fd, uint64_t buffer, uint64_t count);
    /// Reads a guest iovec array as (base, length) pairs, at the guest's pointer width.
    bool ReadGuestIovec(uint64_t address, uint64_t count,
                        std::vector<std::pair<uint64_t, uint64_t>>* out) const;
    uint64_t DoWritev(int fd, uint64_t iov, uint64_t count);
    uint64_t DoReadv(int fd, uint64_t iov, uint64_t count);
    /// Writes a host stat into guest memory in the layout the guest was built for.
    uint64_t WriteGuestStat(uint64_t address, const struct stat& host);
    uint64_t DoStatAt(int dirfd, uint64_t path_address, uint64_t stat_address, int flags);
    uint64_t DoFstat(int fd, uint64_t stat_address);
    uint64_t DoGetdents64(int fd, uint64_t buffer, uint64_t size);
    uint64_t DoMmap(uint64_t address, uint64_t length, int protection, int flags, int fd, int64_t offset);
    uint64_t DoBrk(uint64_t requested);
    uint64_t DoUname(uint64_t address);
    /// True only for the literal /proc/self/exe, never for a path that merely resolves to
    /// the same file.
    bool IsProcSelfExe(const std::string& path) const;
    uint64_t DoSetThreadArea(uint64_t descriptor_address);
    uint64_t DoSocketcall(uint64_t call, uint64_t arguments_address);
    uint64_t DoLlseek(int fd, uint32_t offset_high, uint32_t offset_low, uint64_t result_address,
                      int whence);
    /// Translates a guest socket address, resolving a unix socket's path against the
    /// guest root. Returns 0 and sets errno on failure.
    uint32_t ToHostSocketAddress(const void* guest_address, uint64_t guest_length,
                                 sockaddr_storage* out) const;
    /// The reverse, for getsockname, getpeername and accept.
    uint32_t ToGuestSocketAddress(sockaddr_storage* host_address, void* guest_address,
                                  uint64_t capacity) const;
    uint64_t DoIpc(uint64_t call, uint64_t first, uint64_t second, uint64_t third, uint64_t pointer);
    uint64_t DoSemget(int32_t key, int count, int flags);
    uint64_t DoSemop(int id, uint64_t operations_address, uint64_t count);
    uint64_t DoSemctl(int id, int index, int command, uint64_t argument);
    uint64_t DoShmget(int32_t key, uint64_t size, int flags);
    uint64_t DoShmat(int id, uint64_t address, int flags);
    uint64_t DoShmdt(uint64_t address);
    uint64_t DoShmctl(int id, int command, uint64_t buffer);

    uint64_t DoTimerfdCreate(int clock_id, int flags);
    uint64_t DoTimerfdSettime(int fd, int flags, uint64_t new_value, uint64_t old_value);
    uint64_t DoTimerfdGettime(int fd, uint64_t current_value);
    uint64_t DoTimerfdRead(OpenFile& file, uint64_t buffer);

    uint64_t DoEventfd(uint64_t initial, int flags);
    uint64_t DoEventfdRead(OpenFile& file, uint64_t buffer);
    uint64_t DoEventfdWrite(OpenFile& file, uint64_t buffer);
    uint64_t DoEpollCreate(int flags);
    uint64_t DoEpollCtl(int epoll_fd, int operation, int fd, uint64_t event_address);
    uint64_t DoEpollWait(int epoll_fd, uint64_t events_address, int max_events, int timeout_ms);
    uint64_t DoMknodAt(int dirfd, uint64_t path_address, uint32_t mode);
    uint64_t DoPrctl(uint64_t option, uint64_t arg2);
    /// Answers a read of a /proc file Fathom synthesises. Returns false for anything else.
    bool ProcFileContents(const std::string& guest_path, std::string* out) const;
    uint64_t DoFramebufferIoctl(uint64_t request, uint64_t argument);
    bool EnsureFramebuffer();
    uint64_t DoClockGettime(int clock, uint64_t address);
    /// How wide the time_t in a struct timespec or timeval is for the call being handled.
    /// Eight bytes everywhere except an i386 guest's original time32 syscalls, which it
    /// still uses alongside the _time64 ones it gained later.
    size_t TimeWidth() const { return narrow_time_ ? 4 : 8; }
    bool ReadGuestTimespec(uint64_t address, int64_t* seconds, int64_t* nanoseconds) const;
    bool WriteGuestTimespec(uint64_t address, int64_t seconds, int64_t nanoseconds) const;
    uint64_t DoReadlinkAt(int dirfd, uint64_t path_address, uint64_t buffer, uint64_t size);

    OpenFile* FindFile(int fd);
    int RegisterFile(int host_fd, std::string guest_path);
    void CloseAll();

    GuestAddressSpace& space_;
    GuestThreadControl& control_;
    GuestConsole& console_;
    SyscallConfig config_;

    int pid_ {1};
    int tid_ {0};
    int ppid_ {0};
    ProcessHost* host_ {};

    std::shared_ptr<ProcessFiles> shared_;

    /// Shared by the threads of one process, and by nothing else: a fork gets its own.
    std::shared_ptr<std::atomic<bool>> process_stopping_;

    /// Per-process: what this process passed to exit, and where set_tid_address pointed.
    int exit_status_ {};

    /// Guest address passed to set_tid_address, cleared on exit the way Linux does.
    uint64_t clear_child_tid_ {};

    /// What set_robust_list registered, so get_robust_list can report it back.
    uint64_t robust_list_head_ {};
    uint64_t robust_list_size_ {};

    /// Next free GDT slot for set_thread_area. Linux reserves entries 12 through 14 for
    /// userspace TLS and hands them out in order; glibc asks for one and remembers the
    /// number it was given.
    uint32_t next_tls_entry_ {12};

    /// Set for the duration of one i386 time32 syscall. See TimeWidth.
    bool narrow_time_ {};

    /// What prctl(PR_SET_NAME) was told to call this thread.
    std::string thread_name_;

    /// argv as the process was started with, so /proc/self/cmdline can answer.
    std::vector<std::string> command_line_;

    /// The guest path of the program this process is running, which is what
    /// /proc/self/exe names. Steam's launcher re-executes itself through it.
    std::string program_path_;

};

} // namespace fathom

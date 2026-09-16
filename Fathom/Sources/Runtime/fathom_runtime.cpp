// fathom_runtime.cpp -- the C API's implementation: loads a program, wires the syscall
// layer to the JIT, and runs it.

#include "fathom_api.h"

#include "crash_handler.h"
#include "elf_loader.h"
#include "fathom_log.h"
#include "fex_engine.h"
#include "guest_console.h"
#include "guest_memory.h"
#include "guest_path.h"
#include "linux_syscalls.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <condition_variable>
#include <map>
#include <thread>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr uint64_t kDefaultAddressSpace = 2ULL * 1024 * 1024 * 1024; // 2 GB

/// A 32-bit guest can address exactly 4GB and no more, so its arena is capped there --
/// and the whole of it is reserved, not committed, so it costs address space and nothing
/// else until the guest actually writes.
constexpr uint64_t k32BitAddressSpace = 4ULL * 1024 * 1024 * 1024;

/// Converts an image's outward-facing addresses -- the ones that end up in registers and
/// in the auxiliary vector -- from the host's numbering to the guest's. Identity for a
/// 64-bit guest, where the two are the same.
void ToGuestAddresses(uint64_t guest_base, fathom::LoadedImage* image) {
    if (guest_base == 0) {
        return;
    }
    const uint64_t host_begin = image->image_begin;
    image->entry -= guest_base;
    image->phdr_address = image->phdr_address != 0 ? image->phdr_address - guest_base : 0;
    image->image_begin -= guest_base;
    image->image_end -= guest_base;
    // load_base is an addend applied to p_vaddr, not an address, so it shifts by however
    // much the image's start moved.
    image->load_base -= (host_begin - image->image_begin);
}
constexpr uint64_t kDefaultStack = 8ULL * 1024 * 1024;               // 8 MB
// Per process, and the arena is shared by all of them, so this is a budget rather than a
// gift: 512MB each meant four processes exhausted a 2GB arena. Busybox and its applets
// want a fraction of this.
constexpr uint64_t kHeapReservation = 128ULL * 1024 * 1024;          // brk headroom

void CopyString(char* destination, size_t capacity, const std::string& source) {
    if (destination == nullptr || capacity == 0) {
        return;
    }
    const size_t length = std::min(capacity - 1, source.size());
    std::memcpy(destination, source.data(), length);
    destination[length] = '\0';
}

fathom_program_kind ToApiKind(fathom::ProgramKind kind) {
    switch (kind) {
    case fathom::ProgramKind::Static: return FATHOM_PROGRAM_STATIC;
    case fathom::ProgramKind::StaticPie: return FATHOM_PROGRAM_STATIC_PIE;
    case fathom::ProgramKind::Dynamic: return FATHOM_PROGRAM_DYNAMIC;
    default: return FATHOM_PROGRAM_UNKNOWN;
    }
}

/// The syscall layer needs somewhere to send arch_prctl and exit_group before the engine
/// that answers them exists -- and the engine, in turn, needs the syscall layer to hand
/// to FEXCore. This breaks that cycle: it is handed to the syscall layer at construction
/// and pointed at the engine as soon as there is one.
class DeferredThreadControl final : public fathom::GuestThreadControl {
public:
    void Bind(fathom::GuestThreadControl* target) { target_ = target; }

    void SetFsBase(uint64_t base) override {
        if (target_ != nullptr) {
            target_->SetFsBase(base);
        } else {
            pending_fs_base_ = base;
        }
    }

    uint64_t GetFsBase() const override {
        return target_ != nullptr ? target_->GetFsBase() : pending_fs_base_;
    }

    void SetTlsDescriptor(int entry, uint32_t base, uint32_t limit) override {
        if (target_ != nullptr) {
            target_->SetTlsDescriptor(entry, base, limit);
        }
    }

    [[noreturn]] void ExecGuest() override {
        if (target_ != nullptr) {
            target_->ExecGuest();
        }
        FATHOM_ERROR("execve with no engine bound");
        std::abort();
    }

    [[noreturn]] void ExitGuest(int status) override {
        if (target_ != nullptr) {
            target_->ExitGuest(status);
        }
        // Only reachable if a guest syscall somehow ran before the engine was bound,
        // which the construction order below makes impossible.
        FATHOM_ERROR("guest exit with no engine bound");
        std::abort();
    }

private:
    fathom::GuestThreadControl* target_ {};
    uint64_t pending_fs_base_ {};
};

extern "C" int csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
constexpr unsigned int kCsOpsStatus = 0;
constexpr uint32_t kCsDebugged = 0x10000000;

} // namespace

/// Everything loading a program produces: where it landed, the stack it starts on, and
/// the entry point to entering it. Shared by session startup and by execve, which differ
/// only in which process ends up running the result.
struct LoadedProgram {
    fathom::LoadedImage image {};
    fathom::LoadedImage interpreter {};
    fathom::StackImage stack {};
    bool dynamic {};
    uint64_t heap {};
    uint64_t entry {};
    /// Carried with the program so that releasing it does not need the process that ran it.
    bool is_32bit {};
    uint64_t guest_base {};
};

bool LoadProgram(fathom::GuestAddressSpace& space, uint64_t guest_base,
                 const std::string& guest_root, const std::string& host_path,
                 const std::vector<std::string>& argv, const std::vector<std::string>& envp,
                 uint64_t stack_size, LoadedProgram* out, std::string& error) {
    const auto inspection = fathom::InspectElf(host_path);
    if (!inspection.ok) {
        error = inspection.error;
        return false;
    }

    if (!fathom::LoadElf(host_path, space, 0, guest_base, &out->image, error)) {
        return false;
    }
    ToGuestAddresses(guest_base, &out->image);

    // A dynamically linked program does not begin at its own entry point. The kernel maps
    // its interpreter -- ld.so -- alongside it and enters *that*; ld.so then loads the
    // shared libraries the program needs and jumps to the program itself. AT_BASE on the
    // initial stack is how ld.so discovers where it was placed.
    if (inspection.kind == fathom::ProgramKind::Dynamic) {
        if (guest_root.empty()) {
            error = "this program is dynamically linked and needs " + inspection.interpreter +
                    ", but no guest root filesystem is configured.";
            return false;
        }
        const std::string loader = fathom::ResolveGuestPathOnHost(guest_root, inspection.interpreter);
        if (access(loader.c_str(), R_OK) != 0) {
            error = "this program needs its dynamic loader, " + inspection.interpreter +
                    ", which the guest root filesystem does not provide.";
            return false;
        }
        if (!fathom::LoadElf(loader, space, out->image.image_end + guest_base, guest_base,
                             &out->interpreter, error)) {
            error = "could not load the dynamic loader " + inspection.interpreter + ": " + error;
            return false;
        }
        ToGuestAddresses(guest_base, &out->interpreter);
        out->dynamic = true;
    }

    if (!fathom::BuildInitialStack(space, guest_base, out->image, argv, envp, host_path,
                                   out->dynamic ? out->interpreter.load_base : 0, stack_size,
                                   &out->stack, error)) {
        return false;
    }

    // The heap goes right after the image so a guest malloc that walks up from brk sees
    // the layout it expects. Reserved, not touched: nothing is paged in until the guest
    // actually writes to it.
    const uint64_t images_end = std::max(out->image.image_end, out->interpreter.image_end);
    const uint64_t heap_host = space.Allocate(kHeapReservation, images_end + guest_base,
                                              fathom::kGuestProtRead | fathom::kGuestProtWrite);
    if (heap_host == 0) {
        error = "could not reserve the guest heap";
        return false;
    }
    out->heap = heap_host - guest_base;

    out->entry = out->dynamic ? out->interpreter.entry : out->image.entry;
    out->is_32bit = inspection.is_32bit;
    out->guest_base = guest_base;
    return true;
}

/// Hands back the regions a program used that are only ever data. Its image is
/// deliberately kept: FEXCore caches translations by guest address, and returning code
/// addresses to the pool for reuse risks running a stale one. Images are about a
/// megabyte, so leaking them costs far less than getting that wrong.
void ReleaseProgramData(fathom::GuestAddressSpace& space, const LoadedProgram& program) {
    // Everything here goes back to the arena, and all of it in host addresses. Two of
    // these were wrong and both leaked: the heap was released with the *guest* number the
    // loader reports, which frees nothing, and the image was never released at all. A
    // shell script that runs sixty commands then exhausts a 4GB address space and the
    // next exec fails with "could not allocate the guest stack", a long way from the
    // process that actually leaked.
    if (program.stack.stack_base != 0 && program.stack.stack_size != 0) {
        space.Release(program.stack.stack_base, program.stack.stack_size);
    }
    if (program.heap != 0) {
        space.Release(program.heap + program.guest_base, kHeapReservation);
    }
    // The images are deliberately not released here. They are a few megabytes against the
    // heap's hundred and twenty-eight, and a program's code can still be reached after it
    // has stopped running -- a forked child that never exec'd is standing in it. Freeing
    // them costs far less than it risks.
}

/// One guest process: its own registers, its own file descriptors, its own heap. Fathom's
/// processes share one address space -- see guest_console.h -- so what distinguishes them
/// is exactly this, not the memory they can reach.
struct GuestProcess {
    int pid {};
    int ppid {};
    /// This process's word size, and where its address space starts in the host's. Both
    /// belong to the process rather than the session: Steam's client is i386 and the
    /// process that draws its interface is x86-64, and they run side by side.
    bool is_32bit {};
    uint64_t guest_base {};
    std::string path;

    std::unique_ptr<DeferredThreadControl> control;
    std::unique_ptr<fathom::LinuxSyscalls> syscalls;
    std::unique_ptr<fathom::GuestThread> thread;
    LoadedProgram program;
    /// Whether this process loaded `program` itself. A forked child does not: it shares
    /// its parent's image, stack and heap until it execs, and freeing them on its behalf
    /// pulls the ground out from under the still-running parent.
    bool owns_program {};

    /// What this process was running before an execve replaced it, kept only so its stack
    /// and heap can be given back once the switch is complete -- and only if they were
    /// ever this process's to give.
    LoadedProgram previous_program;
    bool has_previous {};

    /// A pthread rather than a std::thread, purely so its stack can be sized. FEXCore's
    /// dispatcher and the JIT's own frames live on it, and the default 512KB is nowhere
    /// near enough -- the same reason the first guest thread is given 16MB by the caller.
    pthread_t host_thread {};
    bool thread_started {};

    /// Where execve left the replacement image for this process's run loop to pick up.
    uint64_t exec_entry {};
    uint64_t exec_rsp {};

    bool finished {};
    bool joined {};
    int exit_status {};
    /// A vforked parent waits for this: set when the child execs or exits, whichever
    /// comes first, because either one means it is no longer using the parent's stack.
    bool released {};

    /// The parent's writable memory, as it was at the moment of the fork.
    ///
    /// Sharing memory with the parent is what makes this fork cheap, and it is also what
    /// breaks it: busybox calls fork() and expects a private copy of everything, so the
    /// child returns through its parent's stack frames, writes to its parent's globals,
    /// and allocates out of its parent's heap, all before reaching exec. The parent then
    /// resumes into the wreckage.
    ///
    /// Holding a copy and putting it back before the parent runs again gives the parent
    /// the fork semantics it was promised, for the case that matters -- a child that
    /// execs or exits promptly. It is not general: a child that keeps running without
    /// execing still shares memory, and real copy-on-write is what that would need. The
    /// regions are small (a shell at a fork has a few kilobytes of live stack and heap,
    /// and about a megabyte of image), so the copy costs well under a millisecond.
    /// Address and contents of each region held for the parent.
    struct BorrowedRegion {
        uint64_t address {};
        std::vector<uint8_t> bytes;
    };
    std::vector<BorrowedRegion> borrowed;

    /// One thread of this process beyond the first.
    ///
    /// A thread is far less machinery than a process: it shares the address space and the
    /// descriptor table outright, so there is nothing to copy and nothing to hand back.
    /// What it needs of its own is a guest register file, a host thread to run on, and a
    /// syscall layer carrying its own thread id and exit status.
    struct GuestThreadRecord {
        int tid {};
        std::unique_ptr<DeferredThreadControl> control;
        std::unique_ptr<fathom::LinuxSyscalls> syscalls;
        std::unique_ptr<fathom::GuestThread> thread;
        pthread_t host_thread {};
        bool started {};
        /// The top of the stack clone was given, so that a fork made from this thread
        /// knows which stack the child is about to run on.
        uint64_t stack_top {};
        /// Set when the thread's run loop returns. Read without the process lock, which
        /// is why it is atomic: fork asks whether this process still has other threads
        /// running, and the answer changes underneath it.
        std::atomic<bool> finished {false};
    };
    std::vector<std::unique_ptr<GuestThreadRecord>> threads;
};

struct fathom_session final : fathom::ProcessHost {
    /// Shared by every guest process: one keyboard, one screen, one stop.
    fathom::GuestConsole console;

    std::unique_ptr<fathom::GuestAddressSpace> space;
    /// One JIT context per word size. FEXCore decides how to decode and where the guest's
    /// memory starts when the context is created, so a session that runs both needs both.
    /// They share the one address space.
    std::unique_ptr<fathom::FexEngine> engine32;
    std::unique_ptr<fathom::FexEngine> engine64;
    fathom::EngineOptions engine_options;

    fathom::FexEngine* EngineFor(bool is_32bit, std::string& error);

    std::string program_path;
    std::string guest_root;
    uint64_t stack_size {};
    bool trace {};
    /// Whether this session's guest is an i386 one, which every process it forks needs to
    /// be told: its syscalls are numbered differently, and a child that is not told
    /// dispatches its parent's numbers as though they were x86-64's.
    bool guest_is_32bit {};
    /// The arena's base, used by 32-bit processes. A 64-bit one runs at zero.
    uint64_t guest_base {};

    // The process table. pid 1 is the program the session was created for; everything
    // else got here through a fork.
    mutable std::mutex process_mutex;
    std::condition_variable process_changed;
    std::map<int, std::unique_ptr<GuestProcess>> processes;
    int next_pid {2};

    /// pid 1's syscall layer, which is what the C API's console entry points talk to.
    fathom::LinuxSyscalls* syscalls {};

    GuestProcess* Find(int pid) {
        const auto entry = processes.find(pid);
        return entry == processes.end() ? nullptr : entry->second.get();
    }

    fathom::RunResult RunProcess(GuestProcess* process);
    /// Asks every guest thread to stop at its next syscall and waits for all of them.
    void StopAndJoinThreads();
    /// The same for one process's threads, which has to happen before that process can be
    /// destroyed -- its threads hold references to everything it owns.
    void StopAndJoinThreadsOf(GuestProcess* process);
    void NotifyProcessChanged() { process_changed.notify_all(); }

    /// The same, but leaving the thread that asked -- which is what execve needs.
    void StopAndJoinOtherThreadsOf(GuestProcess* process);
    void JoinFinishedChildren();
    void ReleaseParent(GuestProcess* process);

    // ProcessHost
    int64_t ForkProcess(int caller_pid) override;
    int64_t ExecProcess(int caller_pid, const std::string& path, std::vector<std::string> argv,
                        std::vector<std::string> envp) override;
    int64_t WaitForChild(int caller_pid, int wanted_pid, int* exit_status, int options) override;
    int64_t CreateThread(int caller_pid, uint64_t flags, uint64_t stack,
                         uint64_t parent_tid_address, uint64_t child_tid_address,
                         uint64_t tls) override;

    std::atomic<int> state {FATHOM_STATE_IDLE};
    std::atomic<int> exit_code {0};
    mutable std::mutex message_mutex;
    std::string message;

    void SetMessage(const std::string& value) {
        std::scoped_lock lock {message_mutex};
        message = value;
    }

    std::string Message() const {
        std::scoped_lock lock {message_mutex};
        return message;
    }
};

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

namespace {

/// Matches the stack the first guest thread is given on the Swift side.
constexpr size_t kGuestThreadStack = 16 * 1024 * 1024;

struct ChildStart {
    fathom_session* session;
    GuestProcess* process;
};

void* RunChildThread(void* raw);

} // namespace

fathom::FexEngine* fathom_session::EngineFor(bool is_32bit, std::string& error) {
    auto& slot = is_32bit ? engine32 : engine64;
    if (slot == nullptr) {
        fathom::EngineOptions options = engine_options;
        options.guest_is_32bit = is_32bit;
        // A 32-bit guest's pointers cannot reach where the arena actually lives, so its
        // addresses are offset into it. A 64-bit guest needs no such trick -- the arena's
        // addresses fit in its pointers -- so it runs one to one.
        options.guest_memory_base = is_32bit ? guest_base : 0;
        slot = fathom::FexEngine::Create(*space, options, error);
        if (slot == nullptr) {
            FATHOM_ERROR("could not start a %d-bit JIT context: %s", is_32bit ? 32 : 64,
                         error.c_str());
        } else {
            FATHOM_INFO("started a %d-bit JIT context", is_32bit ? 32 : 64);
        }
    }
    return slot.get();
}

fathom::RunResult fathom_session::RunProcess(GuestProcess* process) {
    fathom::RunResult result;
    for (;;) {
        result = process->thread->Run();
        if (result.outcome != fathom::RunOutcome::Execed) {
            break;
        }

        // execve unwound out of the JIT rather than returning, and left a freshly loaded
        // image behind. The thread is replaced only now, once Run() has returned and the
        // old thread's frames are gone from this host stack.
        std::string reason;
        auto* engine = EngineFor(process->is_32bit, reason);
        auto fresh = engine == nullptr ? nullptr
                                       : engine->StartThread(process->exec_entry, process->exec_rsp,
                                                             *process->syscalls, reason);
        if (fresh == nullptr) {
            FATHOM_ERROR("execve could not start the new image: %s", reason.c_str());
            result.outcome = fathom::RunOutcome::Faulted;
            result.message = reason;
            break;
        }
        // The outgoing thread is kept alive until the control block points at the new
        // one, so there is no instant where it refers to a destroyed thread.
        auto outgoing = std::move(process->thread);
        process->thread = std::move(fresh);
        process->control->Bind(process->thread.get());
        outgoing.reset();

        // Now, and not before, the child counts as having exec'd.
        ReleaseParent(process);

        // Safe only here: the replaced program's stack is no longer under any guest
        // register, and its heap is unreachable.
        if (process->has_previous) {
            ReleaseProgramData(*space, process->previous_program);
            process->has_previous = false;
        }
    }
    return result;
}

void fathom_session::StopAndJoinOtherThreadsOf(GuestProcess* process) {
    if (process->threads.empty()) {
        return;
    }
    // execve on Linux ends every other thread in the thread group before the new image is
    // loaded, and that is not a detail: the old image's stack and heap are released here,
    // and a thread still running on them reads whatever the arena hands out next. It
    // surfaces as a thread whose stack pointer has walked off the bottom of the address
    // space, a long way from the exec that caused it.
    const pthread_t self = pthread_self();
    process->syscalls->RequestProcessStop();
    process_changed.notify_all();
    for (auto& thread : process->threads) {
        if (thread->started && !pthread_equal(thread->host_thread, self)) {
            pthread_join(thread->host_thread, nullptr);
            thread->started = false;
        }
    }
    // The flag is shared with the thread that is doing the exec, which is still inside a
    // syscall and has not looked at it yet. Cleared before it does.
    process->syscalls->ClearProcessStop();
    process->threads.clear();
}

void fathom_session::StopAndJoinThreadsOf(GuestProcess* process) {
    if (process->threads.empty()) {
        return;
    }
    process->syscalls->RequestProcessStop();
    process_changed.notify_all();
    for (auto& thread : process->threads) {
        if (thread->started) {
            pthread_join(thread->host_thread, nullptr);
            thread->started = false;
        }
    }
    process->threads.clear();
}

void fathom_session::StopAndJoinThreads() {
    console.RequestStop();

    std::vector<pthread_t> waiting;
    {
        std::scoped_lock lock {process_mutex};
        for (auto& [pid, process] : processes) {
            for (auto& thread : process->threads) {
                if (thread->started) {
                    waiting.push_back(thread->host_thread);
                    thread->started = false;
                }
            }
            if (process->thread_started && !process->finished) {
                waiting.push_back(process->host_thread);
                process->thread_started = false;
            }
        }
    }
    process_changed.notify_all();

    for (pthread_t thread : waiting) {
        pthread_join(thread, nullptr);
    }
}

void fathom_session::JoinFinishedChildren() {
    std::vector<pthread_t> done;
    {
        std::scoped_lock lock {process_mutex};
        for (auto& [pid, process] : processes) {
            if (process->finished && process->thread_started && !process->joined) {
                done.push_back(process->host_thread);
                process->joined = true;
            }
        }
    }
    for (auto thread : done) {
        pthread_join(thread, nullptr);
    }
}

void fathom_session::ReleaseParent(GuestProcess* process) {
    {
        std::scoped_lock lock {process_mutex};
        for (auto& region : process->borrowed) {
            // The parent may have let this go while the child was running -- a thread of
            // its own unmapping a region, or the heap shrinking under it. Writing to a
            // page the arena has since protected away is a fault on the child's thread
            // with the parent's address in it, which reads as a wild pointer and is not.
            if (!space->Validate(region.address, region.bytes.size(),
                                 fathom::kGuestProtWrite)) {
                continue;
            }
            // Put the parent's memory back exactly as the fork found it, before anything
            // lets the parent run on it again.
            std::memcpy(reinterpret_cast<void*>(region.address), region.bytes.data(),
                        region.bytes.size());
        }
        process->borrowed.clear();
        process->borrowed.shrink_to_fit();
        process->released = true;
    }
    process_changed.notify_all();
}

namespace {

struct ThreadStart {
    fathom_session* session;
    GuestProcess* process;
    GuestProcess::GuestThreadRecord* record;
};

void* RunGuestThread(void* raw) {
    std::unique_ptr<ThreadStart> start {static_cast<ThreadStart*>(raw)};
    FATHOM_INFO("tid %d: running", start->record->tid);
    fathom::NoteGuestIdentity(start->process->pid, start->record->tid,
                              start->process->is_32bit, start->process->path.c_str());
    const auto result = start->record->thread->Run();

    // A thread's descriptors are the process's, so nothing is closed here. What does have
    // to happen is the kernel's own parting act: clear the word the thread was created
    // with and wake whoever is waiting on it, which is how pthread_join returns.
    start->record->syscalls->ReleaseThreadId();
    start->record->finished.store(true, std::memory_order_release);
    // A fault in one thread ends the whole thread group on Linux, and a process left
    // running with a thread missing is worse than one that stopped: whatever that thread
    // was holding is never released and the rest deadlock on it.
    if (result.outcome == fathom::RunOutcome::Faulted) {
        FATHOM_WARN("tid %d faulted; ending pid %d with it", start->record->tid,
                    start->process->pid);
        start->process->syscalls->RequestProcessStop();
        start->session->NotifyProcessChanged();
    }
    FATHOM_INFO("tid %d: finished (%s, status %d, rip=%#llx)", start->record->tid,
                result.message.c_str(), result.status,
                static_cast<unsigned long long>(result.rip));
    return nullptr;
}

} // namespace

int64_t fathom_session::CreateThread(int caller_pid, uint64_t flags, uint64_t stack,
                                     uint64_t parent_tid_address, uint64_t child_tid_address,
                                     uint64_t tls) {
    constexpr uint64_t kCloneParentSettid = 0x00100000;
    constexpr uint64_t kCloneChildCleartid = 0x00200000;
    constexpr uint64_t kCloneChildSettid = 0x01000000;
    constexpr uint64_t kCloneSettls = 0x00080000;

    if (stack == 0) {
        // Without CLONE_VM this would be a fork; with it and no stack, the new thread
        // would run on its creator's, which is not something to guess at.
        return -22; // -EINVAL
    }

    GuestProcess::GuestThreadRecord* record_raw = nullptr;
    GuestProcess* process_raw = nullptr;
    int tid = 0;
    {
        std::scoped_lock lock {process_mutex};
        auto* process = Find(caller_pid);
        if (process == nullptr) {
            return -1;
        }
        tid = next_pid++;

        auto record = std::make_unique<GuestProcess::GuestThreadRecord>();
        record->tid = tid;
        record->stack_top = stack;
        record->control = std::make_unique<DeferredThreadControl>();

        fathom::SyscallConfig thread_config;
        thread_config.guest_root = guest_root;
        thread_config.work_dir = "/";
        thread_config.trace = trace;
        thread_config.guest_is_32bit = process->is_32bit;
        thread_config.guest_base = process->guest_base;
        record->syscalls = std::make_unique<fathom::LinuxSyscalls>(*space, *record->control, console,
                                                                   thread_config);
        // Shared rather than copied: this is the entire difference between a thread and a
        // fork as far as the syscall layer is concerned.
        process->syscalls->ShareInto(*record->syscalls);
        record->syscalls->SetProcess(process->pid, process->ppid, this);
        record->syscalls->SetThreadId(tid);
        if ((flags & kCloneChildCleartid) != 0) {
            record->syscalls->SetClearChildTid(child_tid_address);
        }

        // The thread that actually made the clone call, which is not necessarily the
        // process's first one: a program whose threads create further threads would
        // otherwise copy the main thread's registers into the new one, and the new thread
        // would resume at whatever the main thread happened to be doing.
        auto* caller = fathom::FexEngine::Current();
        if (caller == nullptr) {
            caller = process->thread.get();
        }

        std::string reason;
        auto* engine = EngineFor(process->is_32bit, reason);
        record->thread = engine == nullptr
                             ? nullptr
                             : engine->ForkThread(*caller, *record->syscalls, reason, stack);
        if (record->thread == nullptr) {
            FATHOM_ERROR("could not create a guest thread: %s", reason.c_str());
            return -11; // -EAGAIN
        }
        record->control->Bind(record->thread.get());

        // The tid goes into whichever of the two words the guest asked for. Both are in
        // shared memory, so the creating thread writes them and the new one sees them.
        const auto write_tid = [&](uint64_t address) {
            if (address == 0) {
                return;
            }
            auto* slot = reinterpret_cast<int32_t*>(address + process->guest_base);
            if (space->Validate(address + process->guest_base, sizeof(int32_t),
                                fathom::kGuestProtRead)) {
                *slot = tid;
            }
        };
        if ((flags & kCloneParentSettid) != 0) {
            write_tid(parent_tid_address);
        }
        if ((flags & kCloneChildSettid) != 0) {
            write_tid(child_tid_address);
        }

        // CLONE_SETTLS means something different on the two architectures: a 64-bit guest
        // passes the FS base directly, while an i386 one passes a user_desc of the kind
        // set_thread_area takes, and expects %gs to be loaded from it afterwards.
        if ((flags & kCloneSettls) != 0 && tls != 0) {
            // Which of the two this is depends on the process, not on the session: a
            // 64-bit web helper creating threads inside a 32-bit Steam session passes an
            // FS base, and reading that as a pointer to a user_desc gives every one of its
            // threads a wrong TCB -- which shows up as a jump through a garbage function
            // pointer the first time the thread reads anything out of it.
            if (process->is_32bit) {
                auto* descriptor = reinterpret_cast<uint32_t*>(tls + process->guest_base);
                if (space->Validate(tls + process->guest_base, 16, fathom::kGuestProtRead)) {
                    const uint32_t entry = descriptor[0] == 0xFFFF'FFFFU ? 12 : descriptor[0];
                    constexpr uint32_t kLimitInPages = 1u << 4;
                    const uint32_t limit = (descriptor[3] & kLimitInPages) != 0
                                               ? descriptor[2]
                                               : descriptor[2] >> 12;
                    record->control->SetTlsDescriptor(static_cast<int>(entry), descriptor[1], limit);
                    // The TCB header's first words are the thread pointer, the stack
                    // guard and the pointer guard. glibc mangles the stack pointer and
                    // return address it stores in a jmp_buf against that pointer guard, so
                    // a thread holding a different one longjmps to a demangled address
                    // that is simply wrong -- and lands with both its instruction pointer
                    // and its stack pointer pointing at nothing.
                    const uint64_t tcb = static_cast<uint64_t>(descriptor[1]) + process->guest_base;
                    if (space->Validate(tcb, 32, fathom::kGuestProtRead)) {
                        const auto* header = reinterpret_cast<const uint32_t*>(tcb);
                        FATHOM_INFO("clone: tid %d tcb=%#x self=%#x stack guard=%#x pointer guard=%#x",
                                    tid, descriptor[1], header[0], header[5], header[6]);
                    }
                } else {
                    // Not recoverable and not quiet: a thread whose TLS was never
                    // installed reads its own descriptor out of whatever is at zero.
                    FATHOM_ERROR("clone: tid %d asked for TLS at %#llx, which is not mapped",
                                 tid, static_cast<unsigned long long>(tls));
                }
            } else {
                record->control->SetFsBase(tls);
            }
        }

        record_raw = record.get();
        process->threads.push_back(std::move(record));
        process_raw = process;
    }

    auto* start = new ThreadStart {this, process_raw, record_raw};
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setstacksize(&attributes, kGuestThreadStack);
    const int created = pthread_create(&record_raw->host_thread, &attributes, &RunGuestThread, start);
    pthread_attr_destroy(&attributes);
    if (created != 0) {
        delete start;
        FATHOM_ERROR("could not start a host thread for tid %d: %s", tid, std::strerror(created));
        return -11;
    }
    record_raw->started = true;
    FATHOM_INFO("clone: pid %d created tid %d on stack %#llx, resuming at %#llx", caller_pid, tid,
                static_cast<unsigned long long>(stack),
                static_cast<unsigned long long>(record_raw->thread->Rip()));
    return tid;
}

int64_t fathom_session::ForkProcess(int caller_pid) {
    GuestProcess* child_raw = nullptr;
    int child_pid = 0;

    // A child that has finished may still have a host thread winding down, and creating
    // a new guest thread in the same FEXCore context while that happens leaves the new
    // one with a corrupted register file -- a zeroed stack pointer, and a fault at a
    // near-null address the moment it pushes anything. Waiting for the old thread to be
    // properly gone costs nothing: it has already exited.
    JoinFinishedChildren();

    {
        std::scoped_lock lock {process_mutex};
        auto* parent = Find(caller_pid);
        if (parent == nullptr) {
            return -1; // -EPERM
        }
        child_pid = next_pid++;

        auto child = std::make_unique<GuestProcess>();
        child->pid = child_pid;
        child->ppid = caller_pid;
        child->path = parent->path;
        // Shared, not owned: until this child execs it is running inside its parent's
        // image and on its parent's stack.
        child->program = parent->program;
        child->is_32bit = parent->is_32bit;
        child->guest_base = parent->guest_base;
        child->owns_program = false;
        child->control = std::make_unique<DeferredThreadControl>();

        fathom::SyscallConfig child_config;
        child_config.guest_root = guest_root;
        child_config.work_dir = "/";
        // Inherited, or a forked child's syscalls are invisible in the log exactly when
        // the interesting thing is what the child did.
        child_config.trace = trace;
        child_config.guest_is_32bit = parent->is_32bit;
        child_config.guest_base = parent->guest_base;
        child->syscalls = std::make_unique<fathom::LinuxSyscalls>(*space, *child->control, console,
                                                                  child_config);
        parent->syscalls->CloneInto(*child->syscalls);
        child->syscalls->SetProcess(child_pid, caller_pid, this);

        // As in CreateThread: the registers a fork copies are the calling thread's, and a
        // process with more than one thread can fork from any of them.
        auto* caller = fathom::FexEngine::Current();
        if (caller == nullptr) {
            caller = parent->thread.get();
        }

        std::string reason;
        auto* engine = EngineFor(parent->is_32bit, reason);
        child->thread = engine == nullptr ? nullptr
                                          : engine->ForkThread(*caller, *child->syscalls, reason);
        if (child->thread == nullptr) {
            FATHOM_ERROR("fork failed: %s", reason.c_str());
            return -11; // -EAGAIN
        }
        child->control->Bind(child->thread.get());
        FATHOM_INFO("fork: child pid %d starts at rip=%#llx rsp=%#llx rax=%#llx", child_pid,
                    static_cast<unsigned long long>(child->thread->Rip()),
                    static_cast<unsigned long long>(child->thread->Rsp()),
                    static_cast<unsigned long long>(child->thread->Rax()));

        // Taken before the child runs a single instruction.
        //
        // Everything the parent can write to, not just its image and stack: a libc that
        // allocates through mmap rather than brk keeps its heap in mappings that belong
        // to no segment, and a child that allocates before exec quietly corrupts them.
        // That is what a pipeline does -- the shell forks twice and allocates in each
        // child -- and it showed up as a malloc assertion inside the parent afterwards.
        //
        // Two ranges are clamped because they are reserved far larger than they are used:
        // the stack is only live above the stack pointer, and the heap only up to brk.
        // Everything below is a host address, because that is what gets dereferenced.
        // Three of these are kept in guest numbering elsewhere -- the heap because the
        // loader reports it to the guest, the stack pointer because it comes out of a
        // guest register -- and for a relocated 32-bit guest the two are nowhere near
        // each other. Copying from a guest address here reads unmapped memory.
        uint64_t held = 0;
        // Whose stack, and how far down it: the calling thread's, which in a process with
        // more than one is usually not the first. Taking the main thread's bounds here
        // held a region the child never touches and left the frames it does touch -- the
        // ones the calling thread is parked in, waiting for the exec -- to be overwritten
        // and never put back. The thread woke up in frames the child had rewritten, with
        // whatever the child left in them for a stack pointer and a return address.
        uint64_t stack_low = parent->program.stack.stack_base;
        uint64_t stack_top = stack_low + parent->program.stack.stack_size;
        for (const auto& thread : parent->threads) {
            if (thread->thread.get() == caller && thread->stack_top != 0) {
                stack_top = thread->stack_top + parent->guest_base;
                // A cloned thread's stack is the guest's own allocation and its extent is
                // not reported to us, so the low bound is the calling thread's stack
                // pointer itself: everything live is above it.
                stack_low = 0;
                break;
            }
        }
        const uint64_t rsp = caller->Rsp() + parent->guest_base;
        if (stack_low == 0) {
            stack_low = rsp;
        }
        const uint64_t heap_low =
            parent->program.heap == 0 ? 0 : parent->program.heap + parent->guest_base;
        const uint64_t heap_used = parent->syscalls->HeapBreak() == 0
                                       ? 0
                                       : parent->syscalls->HeapBreak() + parent->guest_base;

        const uint64_t heap_top = heap_low + kHeapReservation;
        const auto overlaps = [](uint64_t a1, uint64_t a2, uint64_t b1, uint64_t b2) {
            return a1 < b2 && b1 < a2;
        };

        // Whether anything else in the parent is still running decides how much of it can
        // be held. Linux only gives the child the thread that called fork, and says the
        // child may do nothing but exec afterwards -- so a threaded parent's child touches
        // its stack and essentially nothing else.
        //
        // That restriction is not pedantry here, it is the only thing that can be right.
        // The parent's other threads keep running while the child does, writing to the
        // same heap and the same globals. Putting a snapshot of those back would throw
        // away everything they did in the meantime, and Steam -- eighty-odd threads, seven
        // hundred megabytes of heap, a fork every time it runs a helper -- would be handed
        // its own memory as it was a second ago, over and over. It also means copying that
        // seven hundred megabytes twice per fork, which is the difference between a fork
        // costing a millisecond and costing a second.
        bool threaded = false;
        for (const auto& thread : parent->threads) {
            if (thread->started && !thread->finished.load(std::memory_order_acquire)) {
                threaded = true;
                break;
            }
        }

        // The parent's own regions only. The arena is shared, so asking it for every
        // writable range sweeps in whatever sibling processes have mapped -- which on a
        // pipeline's second fork meant copying the first child's entire 128MB heap.
        std::vector<std::pair<uint64_t, uint64_t>> owned;
        if (!threaded) {
            owned = parent->syscalls->Mappings();
            // ToGuestAddresses put an image's bounds into the guest's numbering, because
            // that is what the guest is told about them. Copying needs the host's.
            owned.emplace_back(parent->program.image.image_begin + parent->guest_base,
                               parent->program.image.image_end - parent->program.image.image_begin);
            if (parent->program.dynamic) {
                owned.emplace_back(parent->program.interpreter.image_begin + parent->guest_base,
                                   parent->program.interpreter.image_end - parent->program.interpreter.image_begin);
            }
            if (heap_low != 0) {
                owned.emplace_back(heap_low, kHeapReservation);
            }
        }
        // The stack is held either way: the child returns out of fork through its parent's
        // frames whatever else is true, and it is a few kilobytes.
        owned.emplace_back(stack_low, stack_top - stack_low);

        for (const auto& [owned_begin, owned_size] : owned) {
            const fathom::GuestRange range {owned_begin, owned_size, 0};
            uint64_t from = range.begin;
            uint64_t to = range.end();

            // Clamped to the part of the heap brk has actually handed out.
            if (heap_low != 0 && overlaps(from, to, heap_low, heap_top)) {
                from = std::max(from, heap_low);
                to = std::min(to, std::max(heap_used, heap_low));
            }
            // Clamped to the live part of the stack, which grows down from the top.
            if (overlaps(from, to, stack_low, stack_top)) {
                from = std::max(from, rsp);
                to = std::min(to, stack_top);
            }
            if (to <= from) {
                continue;
            }
            const auto* bytes = reinterpret_cast<const uint8_t*>(from);
            child->borrowed.push_back({from, std::vector<uint8_t>(bytes, bytes + (to - from))});
            held += to - from;
        }

        FATHOM_INFO("fork: holding %llu KB of pid %d's %s while pid %d borrows it",
                    static_cast<unsigned long long>(held / 1024), caller_pid,
                    threaded ? "stack" : "memory", child_pid);

        child_raw = child.get();
        processes[child_pid] = std::move(child);
    }

    {
        auto* start = new ChildStart {this, child_raw};
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setstacksize(&attributes, kGuestThreadStack);
        const int created = pthread_create(&child_raw->host_thread, &attributes, &RunChildThread, start);
        pthread_attr_destroy(&attributes);
        if (created != 0) {
            delete start;
            FATHOM_ERROR("could not start a host thread for pid %d: %s", child_pid,
                         std::strerror(created));
            std::scoped_lock lock {process_mutex};
            processes.erase(child_pid);
            return -11; // -EAGAIN
        }
        child_raw->thread_started = true;
    }

    // The vfork bargain: the parent does not run again until the child has stopped using
    // its memory, which happens at the child's execve or at its exit, whichever is first.
    {
        std::unique_lock lock {process_mutex};
        process_changed.wait(lock, [&] { return child_raw->released || console.StopRequested(); });
    }

    FATHOM_INFO("fork: pid %d created pid %d", caller_pid, child_pid);
    return child_pid;
}

int64_t fathom_session::ExecProcess(int caller_pid, const std::string& path,
                                    std::vector<std::string> argv, std::vector<std::string> envp) {
    GuestProcess* process = nullptr;
    {
        std::scoped_lock lock {process_mutex};
        process = Find(caller_pid);
    }
    if (process == nullptr) {
        return -1; // -EPERM
    }

    const std::string host_path = fathom::ResolveGuestPathOnHost(guest_root, path);
    if (access(host_path.c_str(), R_OK) != 0) {
        FATHOM_WARN("execve: pid %d asked for %s, which resolves to %s and is not readable",
                    caller_pid, path.c_str(), host_path.c_str());
        return -2; // -ENOENT
    }
    FATHOM_INFO("execve: pid %d loading %s", caller_pid, path.c_str());
    if (argv.empty()) {
        argv.push_back(path);
    }

    LoadedProgram loaded;
    std::string reason;
    // A script rather than a binary. Linux reads the "#!" line and runs the interpreter
    // named there with the script's path appended, and a program that launches a shell
    // script -- Steam launches its web helper through one -- depends on exec doing that
    // rather than reporting the file as unrunnable.
    {
        char first_line[256] = {};
        const int probe = ::open(host_path.c_str(), O_RDONLY);
        if (probe >= 0) {
            const ssize_t read_bytes = ::read(probe, first_line, sizeof(first_line) - 1);
            ::close(probe);
            if (read_bytes > 2 && first_line[0] == '#' && first_line[1] == '!') {
                std::string line {first_line + 2, static_cast<size_t>(read_bytes) - 2};
                const auto newline = line.find('\n');
                if (newline != std::string::npos) {
                    line.resize(newline);
                }
                // At most one argument after the interpreter, which is what Linux allows.
                const auto space = line.find_first_of(" \t");
                std::string interpreter = line.substr(0, space);
                std::string argument;
                if (space != std::string::npos) {
                    const auto rest = line.find_first_not_of(" \t", space);
                    if (rest != std::string::npos) {
                        argument = line.substr(rest);
                    }
                }
                while (!interpreter.empty() && (interpreter.back() == '\r' || interpreter.back() == ' ')) {
                    interpreter.pop_back();
                }
                if (!interpreter.empty()) {
                    std::vector<std::string> rewritten;
                    rewritten.push_back(interpreter);
                    if (!argument.empty()) {
                        rewritten.push_back(argument);
                    }
                    rewritten.push_back(path);
                    // argv[0] is replaced by the script's path; the rest carries over.
                    for (size_t index = 1; index < argv.size(); ++index) {
                        rewritten.push_back(argv[index]);
                    }
                    FATHOM_INFO("execve %s: running it through %s", path.c_str(), interpreter.c_str());
                    return ExecProcess(caller_pid, interpreter, std::move(rewritten), std::move(envp));
                }
            }
        }
    }

    // Before anything is loaded or released: the threads of the image being replaced.
    StopAndJoinOtherThreadsOf(process);

    // exec is where a process's word size is decided, and it need not match the one that
    // called it: Steam's client is i386 and the process that draws its interface is
    // x86-64. The new image gets whichever JIT context matches it, and an address space
    // offset only if it is 32-bit.
    const auto inspection = fathom::InspectElf(host_path);
    if (!inspection.ok) {
        FATHOM_WARN("execve %s: %s", path.c_str(), inspection.error.c_str());
        return -8; // -ENOEXEC
    }
    const uint64_t new_base = inspection.is_32bit ? this->guest_base : 0;
    if (EngineFor(inspection.is_32bit, reason) == nullptr) {
        FATHOM_WARN("execve %s: no %d-bit JIT context: %s", path.c_str(),
                    inspection.is_32bit ? 32 : 64, reason.c_str());
        return -8;
    }

    if (!LoadProgram(*space, new_base, guest_root, host_path, argv, envp, stack_size, &loaded, reason)) {
        FATHOM_WARN("execve %s: %s", path.c_str(), reason.c_str());
        return -8; // -ENOEXEC
    }

    process->previous_program = process->program;
    process->has_previous = process->owns_program;
    process->program = loaded;
    process->owns_program = true;
    process->is_32bit = inspection.is_32bit;
    process->guest_base = new_base;
    process->syscalls->AdoptWordSize(inspection.is_32bit, new_base);
    process->path = path;
    process->exec_entry = loaded.entry;
    process->exec_rsp = loaded.stack.rsp;
    process->syscalls->AdoptImage(loaded.heap, kHeapReservation, path);
    process->syscalls->SetCommandLine(argv);

    FATHOM_INFO("execve: pid %d is now %s (entry %#llx)", caller_pid, path.c_str(),
                static_cast<unsigned long long>(loaded.entry));

    // Deliberately not released here. The parent may only resume once the child is
    // running its new image: until then the child is still creating a thread inside the
    // same FEXCore context the parent would be executing in, and the two racing there is
    // a segfault with no useful backtrace. RunProcess releases it.

    // Never returns: unwinds out of the JIT, and this process's run loop restarts it on
    // the image just loaded.
    process->control->ExecGuest();
}

namespace {

void* RunChildThread(void* raw) {
    std::unique_ptr<ChildStart> start {static_cast<ChildStart*>(raw)};
    auto* session = start->session;
    auto* process = start->process;

    FATHOM_INFO("pid %d: running", process->pid);
    fathom::NoteGuestIdentity(process->pid, process->pid, process->is_32bit,
                              process->path.c_str());
    const auto result = session->RunProcess(process);

    // Its own threads first: they are still running inside the JIT, and everything they
    // are holding -- this process's syscall state, its descriptor table, its stop flag --
    // belongs to the process that is about to be reaped.
    session->StopAndJoinThreadsOf(process);

    // Before anything else: a process that has stopped running must not still be holding
    // file descriptors. Its copy of a pipe's write end would keep that pipe open, and the
    // parent reading the other end would wait for an end-of-file that can never come.
    process->syscalls->ReleaseDescriptors();

    // If this child exited without ever execing, the parent is still waiting and its
    // stack is still borrowed.
    session->ReleaseParent(process);
    FATHOM_INFO("pid %d: finished (%s, status %d, rip=%#llx)", process->pid, result.message.c_str(),
                result.status, static_cast<unsigned long long>(result.rip));
    // A child that exited without ever execing is still standing on its parent's stack.
    if (process->owns_program) {
        ReleaseProgramData(*session->space, process->program);
    }
    {
        std::scoped_lock lock {session->process_mutex};
        process->finished = true;
        process->exit_status = result.status;
        process->released = true;
    }
    session->process_changed.notify_all();
    return nullptr;
}

} // namespace

int64_t fathom_session::WaitForChild(int caller_pid, int wanted_pid, int* exit_status, int options) {
    constexpr int kWNoHang = 1;

    std::unique_lock lock {process_mutex};
    for (;;) {
        bool any_children = false;
        int reaped = 0;
        for (const auto& [pid, candidate] : processes) {
            if (candidate->ppid != caller_pid) {
                continue;
            }
            if (wanted_pid > 0 && pid != wanted_pid) {
                continue;
            }
            any_children = true;
            if (candidate->finished) {
                reaped = pid;
                break;
            }
        }

        if (reaped != 0) {
            // Lifted out of the table before the lock is dropped, so nothing can reach a
            // process that is about to be destroyed. The join has to happen outside the
            // lock, and before the process it belongs to goes away.
            auto node = processes.extract(reaped);
            lock.unlock();
            if (exit_status != nullptr) {
                *exit_status = node.mapped()->exit_status;
            }
            if (node.mapped()->thread_started && !node.mapped()->joined) {
                pthread_join(node.mapped()->host_thread, nullptr);
                node.mapped()->joined = true;
            }
            FATHOM_INFO("wait4: pid %d reaped pid %d (status %d)", caller_pid, reaped,
                        node.mapped()->exit_status);
            return reaped;
        }

        if (!any_children) {
            return -10; // -ECHILD
        }
        if ((options & kWNoHang) != 0) {
            return 0;
        }
        if (console.StopRequested()) {
            return -4; // -EINTR
        }
        process_changed.wait_for(lock, std::chrono::milliseconds(100));
    }
}


extern "C" {

bool fathom_runtime_available(void) {
    return true;
}

const char* fathom_runtime_fex_revision(void) {
    return fathom::FexEngine::FexRevision();
}

size_t fathom_host_page_size(void) {
    return static_cast<size_t>(sysconf(_SC_PAGESIZE));
}

bool fathom_inspect_program(const char* path, fathom_program_info* out_info) {
    if (path == nullptr || out_info == nullptr) {
        return false;
    }
    std::memset(out_info, 0, sizeof(*out_info));

    const auto inspection = fathom::InspectElf(path);
    out_info->ok = inspection.ok;
    out_info->kind = ToApiKind(inspection.kind);
    out_info->loadable = inspection.loadable;
    out_info->entry = inspection.entry;
    out_info->image_size = inspection.image_size;
    out_info->min_vaddr = inspection.min_vaddr;
    CopyString(out_info->machine, sizeof(out_info->machine), inspection.machine);
    CopyString(out_info->interpreter, sizeof(out_info->interpreter), inspection.interpreter);
    CopyString(out_info->error, sizeof(out_info->error), inspection.error);
    return inspection.ok;
}

void fathom_session_config_defaults(fathom_session_config* config) {
    if (config == nullptr) {
        return;
    }
    std::memset(config, 0, sizeof(*config));
    config->address_space_size = kDefaultAddressSpace;
    config->stack_size = kDefaultStack;
    config->max_inst_per_block = 0; // Keep FEXCore's own default.
    config->multiblock = true;
    // Off, as the app has always had it. Emulating x86's memory ordering means every
    // ordinary guest load and store becomes an acquire or release, and those require
    // natural alignment on ARM64 while x86 does not -- so every unaligned guest access
    // raises SIGBUS and has to be emulated by hand. Steam's client spends more than nine
    // tenths of its time in that handler with this on. What it buys is stricter ordering
    // for a guest whose threads race on shared memory, which is a real thing to lose, but
    // not at this price.
    config->tso_enabled = false;
    config->reduced_precision_x87 = false;
    config->trace_syscalls = false;
}

fathom_session* fathom_session_create(const fathom_session_config* config, char* error, size_t error_size) {
    const auto fail = [error, error_size](const std::string& reason) -> fathom_session* {
        FATHOM_ERROR("session create failed: %s", reason.c_str());
        CopyString(error, error_size, reason);
        return nullptr;
    };

    if (config == nullptr || config->program_path == nullptr) {
        return fail("no program was given");
    }

    // A guest process writing to a pipe whose reader has gone is ordinary -- Steam does
    // it every time a helper exits -- and on Linux the signal goes to that process alone.
    // Here every guest process is a thread of this one, so the default action would take
    // the whole session down with it. Ignored, the write returns EPIPE, which is what the
    // guest's own libc is expecting to see.
    signal(SIGPIPE, SIG_IGN);

    auto session = std::make_unique<fathom_session>();
    session->program_path = config->program_path;

    // A program that lives inside the guest root is reached the way the guest would reach
    // it. /bin/sh is a symlink to "/bin/busybox", and only the guest's root makes that
    // mean anything.
    {
        const std::string guest_root = config->guest_root == nullptr ? "" : config->guest_root;
        const std::string as_guest = fathom::GuestPathForHostPath(guest_root, session->program_path);
        if (!as_guest.empty()) {
            session->program_path = fathom::ResolveGuestPathOnHost(guest_root, as_guest);
        }
    }
    session->state.store(FATHOM_STATE_LOADING);

    std::string reason;
    // Read before anything is reserved: an i386 guest needs a differently sized and
    // differently placed arena, and that decision cannot be made after the fact.
    const auto first_look = fathom::InspectElf(session->program_path);
    if (!first_look.ok) {
        return fail(first_look.error);
    }
    const bool guest_is_32bit = first_look.is_32bit;
    const uint64_t arena_size =
        guest_is_32bit ? k32BitAddressSpace
                       : (config->address_space_size != 0 ? config->address_space_size : kDefaultAddressSpace);
    session->space.reset(fathom::GuestAddressSpace::Reserve(arena_size, reason));
    if (session->space == nullptr) {
        return fail(reason);
    }
    if (guest_is_32bit) {
        // The guest sees its address space starting at zero; it really starts here.
        // Recorded on the session as well, because a 64-bit process started later by this
        // 32-bit one runs one to one and must not use it.
        session->guest_base = session->space->Base();
        session->space->SetGuestBase(session->space->Base());
        FATHOM_INFO("i386 guest: 4GB arena at %#llx, which the guest sees as 0",
                    static_cast<unsigned long long>(session->space->Base()));
    }

    session->guest_root = config->guest_root == nullptr ? "" : config->guest_root;
    session->stack_size = config->stack_size != 0 ? config->stack_size : kDefaultStack;
    session->trace = config->trace_syscalls;

    std::vector<std::string> argv;
    if (config->argv != nullptr && config->argc > 0) {
        argv.reserve(static_cast<size_t>(config->argc));
        for (int index = 0; index < config->argc; ++index) {
            argv.emplace_back(config->argv[index] == nullptr ? "" : config->argv[index]);
        }
    } else {
        argv.emplace_back(session->program_path);
    }

    std::vector<std::string> envp;
    if (config->envp != nullptr && config->envc > 0) {
        envp.reserve(static_cast<size_t>(config->envc));
        for (int index = 0; index < config->envc; ++index) {
            envp.emplace_back(config->envp[index] == nullptr ? "" : config->envp[index]);
        }
    }

    auto process = std::make_unique<GuestProcess>();
    process->pid = 1;
    process->ppid = 0;
    process->path = session->program_path;
    process->owns_program = true;

    if (!LoadProgram(*session->space, session->guest_base, session->guest_root,
                     session->program_path, argv, envp,
                     session->stack_size, &process->program, reason)) {
        return fail(reason);
    }
    if (process->program.dynamic) {
        FATHOM_INFO("dynamic: loader based at %#llx, program entry %#llx",
                    static_cast<unsigned long long>(process->program.interpreter.load_base),
                    static_cast<unsigned long long>(process->program.image.entry));
    }

    fathom::SyscallConfig syscall_config;
    syscall_config.guest_root = session->guest_root;
    syscall_config.work_dir = config->work_dir == nullptr ? "/" : config->work_dir;
    syscall_config.trace = config->trace_syscalls;
    syscall_config.guest_is_32bit = guest_is_32bit;
    syscall_config.guest_base = guest_is_32bit ? session->guest_base : 0;
    session->guest_is_32bit = guest_is_32bit;
    process->is_32bit = guest_is_32bit;
    process->guest_base = syscall_config.guest_base;

    process->control = std::make_unique<DeferredThreadControl>();
    process->syscalls = std::make_unique<fathom::LinuxSyscalls>(*session->space, *process->control,
                                                                session->console, syscall_config);
    process->syscalls->InitialiseHeap(process->program.heap, kHeapReservation);
    process->syscalls->SetCommandLine(argv);
    // The guest's own name for the binary, not the host path it lives at: it is what
    // /proc/self/exe has to report, and what an exec of that link has to resolve.
    process->syscalls->SetProgramPath(
        fathom::GuestPathForHostPath(session->guest_root, session->program_path));
    process->syscalls->SetProcess(1, 0, session.get());

    fathom::EngineOptions options;
    options.max_inst_per_block = config->max_inst_per_block;
    options.multiblock = config->multiblock;
    options.tso_enabled = config->tso_enabled;
    options.reduced_precision_x87 = config->reduced_precision_x87;
    options.disassemble = false;
    options.disable_avx = config->disable_avx;
    options.guest_is_32bit = guest_is_32bit;
    // Kept so a second context can be made later on the same terms: a 32-bit program can
    // start a 64-bit one, and each needs a JIT told which it is.
    session->engine_options = options;

    auto* engine = session->EngineFor(guest_is_32bit, reason);
    if (engine == nullptr) {
        return fail(reason);
    }

    process->thread = engine->StartThread(process->program.entry, process->program.stack.rsp,
                                          *process->syscalls, reason);
    if (process->thread == nullptr) {
        return fail(reason);
    }
    process->control->Bind(process->thread.get());

    session->syscalls = process->syscalls.get();
    session->processes[1] = std::move(process);

    session->state.store(FATHOM_STATE_IDLE);
    session->SetMessage("ready");
    FATHOM_INFO("session ready for %s", session->program_path.c_str());
    return session.release();
}

void fathom_session_set_output_sink(fathom_session* session, fathom_output_sink sink, void* context) {
    if (session == nullptr || session->syscalls == nullptr) {
        return;
    }
    session->syscalls->SetOutputCallback(reinterpret_cast<fathom::OutputCallback>(sink), context);
}

void fathom_session_send_input(fathom_session* session, const char* bytes, size_t length) {
    if (session == nullptr || session->syscalls == nullptr) {
        return;
    }
    session->syscalls->SendInput(bytes, length);
}

bool fathom_session_framebuffer(fathom_session* session, fathom_framebuffer* out) {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));
    if (session == nullptr || session->syscalls == nullptr) {
        return false;
    }

    const auto display = session->syscalls->Display();
    if (display.address == 0) {
        return false;
    }
    out->active = true;
    out->width = display.width;
    out->height = display.height;
    out->stride = display.stride;
    out->bits_per_pixel = display.bits_per_pixel;
    out->pixels = reinterpret_cast<const void*>(display.address);
    out->writes = session->syscalls->FramePresentations();
    return true;
}

bool fathom_session_wants_keys(fathom_session* session) {
    return session != nullptr && session->syscalls != nullptr && session->syscalls->WantsKeys();
}

int fathom_session_run(fathom_session* session) {
    if (session == nullptr || session->processes.empty()) {
        return -1;
    }
    auto* init = session->Find(1);
    if (init == nullptr) {
        return -1;
    }

    session->state.store(FATHOM_STATE_RUNNING);
    session->SetMessage("running");

    const auto result = session->RunProcess(init);

    // The first thread returning means the guest is finished, but its other threads are
    // still inside the JIT -- parked in a futex, or polling -- holding references to state
    // this session is about to destroy. Asking them to stop and waiting for them is the
    // difference between a clean exit and a segfault in a thread that outlived everything
    // it was using.
    session->StopAndJoinThreads();

    switch (result.outcome) {
    case fathom::RunOutcome::Exited:
        session->state.store(FATHOM_STATE_EXITED);
        session->exit_code.store(result.status);
        session->SetMessage("exited with status " + std::to_string(result.status));
        return result.status;
    case fathom::RunOutcome::Halted:
        session->state.store(FATHOM_STATE_EXITED);
        session->exit_code.store(0);
        session->SetMessage("guest halted without calling exit");
        return 0;
    case fathom::RunOutcome::Stopped:
        session->state.store(FATHOM_STATE_STOPPED);
        session->exit_code.store(-1);
        session->SetMessage("stopped");
        return -1;
    case fathom::RunOutcome::Faulted:
    default:
        session->state.store(FATHOM_STATE_FAULTED);
        session->exit_code.store(-1);
        session->SetMessage(result.message.empty() ? "guest faulted" : result.message);
        return -1;
    }
}

void fathom_session_request_stop(fathom_session* session) {
    if (session == nullptr || session->syscalls == nullptr) {
        return;
    }
    FATHOM_INFO("stop requested");
    session->syscalls->RequestStop();
}

void fathom_session_get_status(fathom_session* session, fathom_session_status* out_status) {
    if (out_status == nullptr) {
        return;
    }
    std::memset(out_status, 0, sizeof(*out_status));
    if (session == nullptr) {
        return;
    }

    out_status->state = static_cast<fathom_session_state>(session->state.load());
    out_status->exit_code = session->exit_code.load();
    if (session->engine32 != nullptr || session->engine64 != nullptr) {
        auto* init = const_cast<fathom_session*>(session)->Find(1);
        out_status->rip = init == nullptr ? 0 : init->thread->Rip();
        out_status->rsp = init == nullptr ? 0 : init->thread->Rsp();
    }
    if (session->syscalls != nullptr) {
        out_status->syscall_count = session->syscalls->SyscallCount();
    }
    CopyString(out_status->message, sizeof(out_status->message), session->Message());
}

void fathom_session_destroy(fathom_session* session) {
    if (session == nullptr) {
        return;
    }
    // Ordering matters. Every process holds a FEXCore thread that can still call into
    // its syscall layer, and those hold descriptors into the address space, so the
    // processes go first -- and any still running are stopped and joined before their
    // state is torn out from under them.
    session->console.RequestStop();
    {
        std::vector<pthread_t> running;
        {
            std::scoped_lock lock {session->process_mutex};
            for (auto& [pid, process] : session->processes) {
                if (process->thread_started && !process->joined) {
                    running.push_back(process->host_thread);
                    process->joined = true;
                }
            }
        }
        session->process_changed.notify_all();
        for (auto thread : running) {
            pthread_join(thread, nullptr);
        }
    }
    session->processes.clear();
    session->syscalls = nullptr;
    session->engine32.reset();
    session->engine64.reset();
    session->space.reset();
    delete session;
}

void fathom_probe_device(fathom_diagnostics* out_diagnostics) {
    if (out_diagnostics == nullptr) {
        return;
    }
    std::memset(out_diagnostics, 0, sizeof(*out_diagnostics));

    uint32_t flags = 0;
    const bool csops_ok = csops(getpid(), kCsOpsStatus, &flags, sizeof(flags)) == 0;
    out_diagnostics->debugger_attached = csops_ok && (flags & kCsDebugged) != 0;

    // A JIT-capable mapping is the single thing FEXCore cannot work without. Asking for
    // one directly is a far better signal than reading entitlements and inferring.
    const auto page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
#ifdef MAP_JIT
    void* jit = mmap(nullptr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
    void* jit = MAP_FAILED;
#endif
    out_diagnostics->jit_available = jit != MAP_FAILED;
    out_diagnostics->has_dynamic_codesigning = out_diagnostics->jit_available;
    if (jit != MAP_FAILED) {
        munmap(jit, page_size);
    }

    // Largest contiguous reservation, halving until one is granted. This is address
    // space, not memory: nothing here is ever written to.
    for (uint64_t size = 8ULL << 30; size >= (16ULL << 20); size /= 2) {
        void* reservation = mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (reservation != MAP_FAILED) {
            munmap(reservation, size);
            out_diagnostics->largest_reservation = size;
            break;
        }
    }

    // How low a fixed mapping can go decides whether a non-PIE guest can ever run: those
    // binaries link at 0x400000, and an iOS arm64 process reserves the low 4GB.
    static const uint64_t candidates[] = {
        0x400000ULL, 0x1000000ULL, 0x40000000ULL, 0x100000000ULL, 0x200000000ULL, 0x400000000ULL,
    };
    for (const uint64_t candidate : candidates) {
        void* fixed = mmap(reinterpret_cast<void*>(candidate), page_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (fixed != MAP_FAILED && reinterpret_cast<uint64_t>(fixed) == candidate) {
            munmap(fixed, page_size);
            out_diagnostics->lowest_mappable = candidate;
            break;
        }
        if (fixed != MAP_FAILED) {
            munmap(fixed, page_size);
        }
    }

    char detail[512];
    std::snprintf(detail, sizeof(detail),
                  "host page size %zu; JIT mapping %s; largest reservation %llu MB; lowest fixed "
                  "mapping %#llx; process %s",
                  page_size, out_diagnostics->jit_available ? "granted" : "refused",
                  static_cast<unsigned long long>(out_diagnostics->largest_reservation >> 20),
                  static_cast<unsigned long long>(out_diagnostics->lowest_mappable),
                  out_diagnostics->debugger_attached ? "is debugged (JIT permitted)"
                                                     : "is not debugged");
    CopyString(out_diagnostics->detail, sizeof(out_diagnostics->detail), detail);
    FATHOM_INFO("device probe: %s", detail);
}

} // extern "C"

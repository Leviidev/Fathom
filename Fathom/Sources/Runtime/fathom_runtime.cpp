// fathom_runtime.cpp -- the C API's implementation: loads a program, wires the syscall
// layer to the JIT, and runs it.

#include "fathom_api.h"

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
#include <unistd.h>
#include <vector>

namespace {

constexpr uint64_t kDefaultAddressSpace = 2ULL * 1024 * 1024 * 1024; // 2 GB
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
};

bool LoadProgram(fathom::GuestAddressSpace& space, const std::string& guest_root,
                 const std::string& host_path, const std::vector<std::string>& argv,
                 const std::vector<std::string>& envp, uint64_t stack_size, LoadedProgram* out,
                 std::string& error) {
    const auto inspection = fathom::InspectElf(host_path);
    if (!inspection.ok) {
        error = inspection.error;
        return false;
    }

    if (!fathom::LoadElf(host_path, space, 0, &out->image, error)) {
        return false;
    }

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
        if (!fathom::LoadElf(loader, space, out->image.image_end, &out->interpreter, error)) {
            error = "could not load the dynamic loader " + inspection.interpreter + ": " + error;
            return false;
        }
        out->dynamic = true;
    }

    if (!fathom::BuildInitialStack(space, out->image, argv, envp, host_path,
                                   out->dynamic ? out->interpreter.load_base : 0, stack_size,
                                   &out->stack, error)) {
        return false;
    }

    // The heap goes right after the image so a guest malloc that walks up from brk sees
    // the layout it expects. Reserved, not touched: nothing is paged in until the guest
    // actually writes to it.
    const uint64_t images_end = std::max(out->image.image_end, out->interpreter.image_end);
    out->heap = space.Allocate(kHeapReservation, images_end,
                               fathom::kGuestProtRead | fathom::kGuestProtWrite);
    if (out->heap == 0) {
        error = "could not reserve the guest heap";
        return false;
    }

    out->entry = out->dynamic ? out->interpreter.entry : out->image.entry;
    return true;
}

/// Hands back the regions a program used that are only ever data. Its image is
/// deliberately kept: FEXCore caches translations by guest address, and returning code
/// addresses to the pool for reuse risks running a stale one. Images are about a
/// megabyte, so leaking them costs far less than getting that wrong.
void ReleaseProgramData(fathom::GuestAddressSpace& space, const LoadedProgram& program) {
    if (program.stack.stack_base != 0 && program.stack.stack_size != 0) {
        space.Release(program.stack.stack_base, program.stack.stack_size);
    }
    if (program.heap != 0) {
        space.Release(program.heap, kHeapReservation);
    }
}

/// One guest process: its own registers, its own file descriptors, its own heap. Fathom's
/// processes share one address space -- see guest_console.h -- so what distinguishes them
/// is exactly this, not the memory they can reach.
struct GuestProcess {
    int pid {};
    int ppid {};
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
};

struct fathom_session final : fathom::ProcessHost {
    /// Shared by every guest process: one keyboard, one screen, one stop.
    fathom::GuestConsole console;

    std::unique_ptr<fathom::GuestAddressSpace> space;
    std::unique_ptr<fathom::FexEngine> engine;

    std::string program_path;
    std::string guest_root;
    uint64_t stack_size {};
    bool trace {};

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
    void JoinFinishedChildren();
    void ReleaseParent(GuestProcess* process);

    // ProcessHost
    int64_t ForkProcess(int caller_pid) override;
    int64_t ExecProcess(int caller_pid, const std::string& path, std::vector<std::string> argv,
                        std::vector<std::string> envp) override;
    int64_t WaitForChild(int caller_pid, int wanted_pid, int* exit_status, int options) override;

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
        auto fresh = engine->StartThread(process->exec_entry, process->exec_rsp, *process->syscalls,
                                         reason);
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
        child->owns_program = false;
        child->control = std::make_unique<DeferredThreadControl>();

        fathom::SyscallConfig child_config;
        child_config.guest_root = guest_root;
        child_config.work_dir = "/";
        // Inherited, or a forked child's syscalls are invisible in the log exactly when
        // the interesting thing is what the child did.
        child_config.trace = trace;
        child->syscalls = std::make_unique<fathom::LinuxSyscalls>(*space, *child->control, console,
                                                                  child_config);
        parent->syscalls->CloneInto(*child->syscalls);
        child->syscalls->SetProcess(child_pid, caller_pid, this);

        std::string reason;
        child->thread = engine->ForkThread(*parent->thread, *child->syscalls, reason);
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
        uint64_t held = 0;
        const uint64_t stack_low = parent->program.stack.stack_base;
        const uint64_t stack_top = stack_low + parent->program.stack.stack_size;
        const uint64_t rsp = parent->thread->Rsp();
        const uint64_t heap_low = parent->program.heap;
        const uint64_t heap_used = parent->syscalls->HeapBreak();

        const uint64_t heap_top = heap_low + kHeapReservation;
        const auto overlaps = [](uint64_t a1, uint64_t a2, uint64_t b1, uint64_t b2) {
            return a1 < b2 && b1 < a2;
        };

        // The parent's own regions only. The arena is shared, so asking it for every
        // writable range sweeps in whatever sibling processes have mapped -- which on a
        // pipeline's second fork meant copying the first child's entire 128MB heap.
        std::vector<std::pair<uint64_t, uint64_t>> owned = parent->syscalls->Mappings();
        owned.emplace_back(parent->program.image.image_begin,
                           parent->program.image.image_end - parent->program.image.image_begin);
        if (parent->program.dynamic) {
            owned.emplace_back(parent->program.interpreter.image_begin,
                               parent->program.interpreter.image_end - parent->program.interpreter.image_begin);
        }
        owned.emplace_back(stack_low, stack_top - stack_low);
        owned.emplace_back(heap_low, kHeapReservation);

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

        FATHOM_INFO("fork: holding %llu KB of pid %d's memory while pid %d borrows it",
                    static_cast<unsigned long long>(held / 1024), caller_pid, child_pid);

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
    if (!LoadProgram(*space, guest_root, host_path, argv, envp, stack_size, &loaded, reason)) {
        FATHOM_WARN("execve %s: %s", path.c_str(), reason.c_str());
        return -8; // -ENOEXEC
    }

    process->previous_program = process->program;
    process->has_previous = process->owns_program;
    process->program = loaded;
    process->owns_program = true;
    process->path = path;
    process->exec_entry = loaded.entry;
    process->exec_rsp = loaded.stack.rsp;
    process->syscalls->AdoptImage(loaded.heap, kHeapReservation, path);

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
    const auto result = session->RunProcess(process);
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
    config->tso_enabled = true;
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
    const uint64_t arena_size =
        config->address_space_size != 0 ? config->address_space_size : kDefaultAddressSpace;
    session->space.reset(fathom::GuestAddressSpace::Reserve(arena_size, reason));
    if (session->space == nullptr) {
        return fail(reason);
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

    if (!LoadProgram(*session->space, session->guest_root, session->program_path, argv, envp,
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

    process->control = std::make_unique<DeferredThreadControl>();
    process->syscalls = std::make_unique<fathom::LinuxSyscalls>(*session->space, *process->control,
                                                                session->console, syscall_config);
    process->syscalls->InitialiseHeap(process->program.heap, kHeapReservation);
    process->syscalls->SetProcess(1, 0, session.get());

    fathom::EngineOptions options;
    options.max_inst_per_block = config->max_inst_per_block;
    options.multiblock = config->multiblock;
    options.tso_enabled = config->tso_enabled;
    options.reduced_precision_x87 = config->reduced_precision_x87;
    options.disassemble = false;
    options.disable_avx = config->disable_avx;

    session->engine = fathom::FexEngine::Create(*session->space, options, reason);
    if (session->engine == nullptr) {
        return fail(reason);
    }

    process->thread = session->engine->StartThread(process->program.entry, process->program.stack.rsp,
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
    if (session->engine != nullptr) {
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
    session->engine.reset();
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

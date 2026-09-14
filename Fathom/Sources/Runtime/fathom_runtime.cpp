// fathom_runtime.cpp -- the C API's implementation: loads a program, wires the syscall
// layer to the JIT, and runs it.

#include "fathom_api.h"

#include "elf_loader.h"
#include "fathom_log.h"
#include "fex_engine.h"
#include "guest_memory.h"
#include "linux_syscalls.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr uint64_t kDefaultAddressSpace = 2ULL * 1024 * 1024 * 1024; // 2 GB
constexpr uint64_t kDefaultStack = 8ULL * 1024 * 1024;               // 8 MB
constexpr uint64_t kHeapReservation = 512ULL * 1024 * 1024;          // brk headroom

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

struct fathom_session {
    std::unique_ptr<fathom::GuestAddressSpace> space;
    std::unique_ptr<DeferredThreadControl> control;
    std::unique_ptr<fathom::LinuxSyscalls> syscalls;
    std::unique_ptr<fathom::FexEngine> engine;

    std::string program_path;
    fathom::LoadedImage image {};
    fathom::StackImage stack {};

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
    session->state.store(FATHOM_STATE_LOADING);

    const auto inspection = fathom::InspectElf(session->program_path);
    if (!inspection.ok) {
        return fail(inspection.error);
    }
    if (inspection.kind == fathom::ProgramKind::Dynamic) {
        return fail("this program is dynamically linked and needs " + inspection.interpreter +
                    ", which means a guest root filesystem Fathom does not have yet. A "
                    "statically linked build (ideally -static-pie) runs as-is.");
    }

    std::string reason;
    const uint64_t arena_size =
        config->address_space_size != 0 ? config->address_space_size : kDefaultAddressSpace;
    session->space.reset(fathom::GuestAddressSpace::Reserve(arena_size, reason));
    if (session->space == nullptr) {
        return fail(reason);
    }

    if (!fathom::LoadElf(session->program_path, *session->space, 0, &session->image, reason)) {
        return fail(reason);
    }

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

    const uint64_t stack_size = config->stack_size != 0 ? config->stack_size : kDefaultStack;
    if (!fathom::BuildInitialStack(*session->space, session->image, argv, envp, session->program_path,
                                   0, stack_size, &session->stack, reason)) {
        return fail(reason);
    }

    fathom::SyscallConfig syscall_config;
    syscall_config.guest_root = config->guest_root == nullptr ? "" : config->guest_root;
    syscall_config.work_dir = config->work_dir == nullptr ? "/" : config->work_dir;
    syscall_config.trace = config->trace_syscalls;

    session->control = std::make_unique<DeferredThreadControl>();
    session->syscalls =
        std::make_unique<fathom::LinuxSyscalls>(*session->space, *session->control, syscall_config);

    // The heap is placed right after the image so a guest malloc that walks up from brk
    // sees the layout it expects. It is reserved, not touched -- nothing is paged in
    // until the guest actually writes.
    const uint64_t heap = session->space->Allocate(kHeapReservation, session->image.image_end,
                                                  fathom::kGuestProtRead | fathom::kGuestProtWrite);
    if (heap == 0) {
        return fail("could not reserve the guest heap");
    }
    session->syscalls->InitialiseHeap(heap, kHeapReservation);

    fathom::EngineOptions options;
    options.max_inst_per_block = config->max_inst_per_block;
    options.multiblock = config->multiblock;
    options.tso_enabled = config->tso_enabled;
    options.reduced_precision_x87 = config->reduced_precision_x87;
    options.disassemble = false;

    session->engine = fathom::FexEngine::Create(*session->space, *session->syscalls, options, reason);
    if (session->engine == nullptr) {
        return fail(reason);
    }
    session->control->Bind(session->engine.get());

    if (!session->engine->Prepare(session->image.entry, session->stack.rsp, reason)) {
        return fail(reason);
    }

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

int fathom_session_run(fathom_session* session) {
    if (session == nullptr || session->engine == nullptr) {
        return -1;
    }

    session->state.store(FATHOM_STATE_RUNNING);
    session->SetMessage("running");

    const auto result = session->engine->Run();

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
        out_status->rip = session->engine->Rip();
        out_status->rsp = session->engine->Rsp();
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
    // Ordering matters: the engine holds the FEXCore thread that can still call into the
    // syscall layer, and the syscall layer holds descriptors into the address space.
    session->engine.reset();
    session->syscalls.reset();
    session->control.reset();
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

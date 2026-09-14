#include "fex_engine.h"

#include "crash_handler.h"
#include "fathom_log.h"

#include <Common/Config.h>
#include <Common/HostFeatures.h>

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/LongJump.h>

#ifdef __APPLE__
// Darwin's <ucontext.h> hard-errors on the deprecated getcontext/setcontext declarations
// without this. Only the ucontext_t/mcontext_t types are wanted here, never those calls.
#define _XOPEN_SOURCE 1
#include <mach/arm/thread_status.h>
#include <ucontext.h>
#endif

#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>

namespace fathom {
namespace {

// FEXCore's own logging, routed into Fathom's single log path rather than stderr.
void ForwardFexMessage(LogMan::DebugLevels level, const char* message) {
    switch (level) {
    case LogMan::ASSERT:
    case LogMan::ERROR:
        FATHOM_ERROR("fexcore: %s", message);
        break;
    case LogMan::DEBUG:
    case LogMan::INFO:
        FATHOM_DEBUG("fexcore: %s", message);
        break;
    default:
        FATHOM_INFO("fexcore: %s", message);
        break;
    }
}

void ForwardFexAssert(const char* message) {
    FATHOM_ERROR("fexcore assertion: %s", message);
}

/// FEXCore's configuration is process-global, so it is set up once and torn down when
/// the last engine goes away rather than per session.
class ConfigLease {
public:
    static void Acquire(const EngineOptions& options) {
        std::scoped_lock lock {mutex_};
        if (users_ == 0) {
            FEX::Config::InitializeConfigs(FEX::Config::PortableInformation {});
            FEXCore::Config::Initialize();
            FEXCore::Config::Load();
            LogMan::Throw::InstallHandler(ForwardFexAssert);
            LogMan::Msg::InstallHandler(ForwardFexMessage);
        }
        ++users_;

        FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
        FEXCore::Config::Set(FEXCore::Config::CONFIG_DISABLETELEMETRY, "1");
        FEXCore::Config::Set(FEXCore::Config::CONFIG_MULTIBLOCK, options.multiblock ? "1" : "0");
        FEXCore::Config::Set(FEXCore::Config::CONFIG_TSOENABLED, options.tso_enabled ? "1" : "0");
        FEXCore::Config::Set(FEXCore::Config::CONFIG_X87REDUCEDPRECISION,
                             options.reduced_precision_x87 ? "1" : "0");
        FEXCore::Config::Set(FEXCore::Config::CONFIG_X86DISASSEMBLE, options.disassemble ? "1" : "0");
        if (options.max_inst_per_block != 0) {
            FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,
                                 std::to_string(options.max_inst_per_block));
        }
    }

    static void Release() {
        std::scoped_lock lock {mutex_};
        if (users_ == 0) {
            return;
        }
        if (--users_ == 0) {
            FEXCore::Config::Shutdown();
            LogMan::Msg::UnInstallHandler();
            LogMan::Throw::UnInstallHandler();
        }
    }

private:
    static inline std::mutex mutex_;
    static inline size_t users_ {};
};

/// FEXCore needs somewhere to keep its call/return prediction stack, per guest thread.
class CallRetStack {
public:
    CallRetStack() {
        const auto page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        allocation_size_ = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * page_size;
        page_size_ = page_size;
        address_ = mmap(nullptr, allocation_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (address_ == MAP_FAILED) {
            error_ = errno;
            return;
        }
        // A guard page on each side: an overflow of this stack should fault here rather
        // than quietly scribble over whatever the allocator put next to it.
        if (mprotect(Base(), FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE,
                     PROT_READ | PROT_WRITE) != 0) {
            error_ = errno;
        }
    }

    ~CallRetStack() {
        if (address_ != MAP_FAILED && address_ != nullptr) {
            munmap(address_, allocation_size_);
        }
    }

    CallRetStack(const CallRetStack&) = delete;
    CallRetStack& operator=(const CallRetStack&) = delete;

    bool valid() const { return address_ != MAP_FAILED && error_ == 0; }
    int error() const { return error_; }

    void Attach(FEXCore::Core::InternalThreadState* thread) const {
        thread->CallRetStackBase = Base();
        thread->CurrentFrame->State.callret_sp =
            reinterpret_cast<uint64_t>(Base()) + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4;
    }

private:
    void* Base() const { return static_cast<uint8_t*>(address_) + page_size_; }

    void* address_ {MAP_FAILED};
    size_t allocation_size_ {};
    size_t page_size_ {};
    int error_ {};
};

/// The guest's segment descriptors. x86-64 barely uses segmentation, but the JIT still
/// reads a cached CS base, and leaving it unset produces wrong addresses rather than an
/// obvious failure.
class GuestSegments {
public:
    void Initialise(FEXCore::Core::CPUState& state) {
        state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = gdt_.data();
        state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = gdt_.data();
        state.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
        auto* code_segment = FEXCore::Core::CPUState::GetSegmentFromIndex(state, state.cs_idx);
        FEXCore::Core::CPUState::SetGDTBase(code_segment, 0);
        FEXCore::Core::CPUState::SetGDTLimit(code_segment, 0xF'FFFFU);
        state.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(*code_segment);
        code_segment->L = 1; // 64-bit code segment.
        code_segment->D = 0;
    }

private:
    std::array<FEXCore::Core::CPUState::gdt_segment, 32> gdt_ {};
};

/// The FEXCore thread executing on this host thread, if any.
///
/// The alignment-fault handler needs it, and a signal handler cannot be passed context
/// any other way. Thread-local because FEXCore binds a guest thread to the host thread
/// running it, so this is exactly as wide as it needs to be.
struct ActiveExecution {
    FEXCore::Context::Context* context {};
    FEXCore::Core::InternalThreadState* thread {};
};
thread_local ActiveExecution g_active;

/// Counted so the log can say whether this mechanism is doing anything at all. A run
/// with thousands of these is working correctly; a run with zero means either the guest
/// never touched an odd address or the handler is not being reached.
std::atomic<uint64_t> g_alignment_fixups {0};

/// Fixes up a guest alignment fault and resumes, rather than letting it kill the app.
///
/// x86 lets a program read or write at any address. ARM64 mostly does too -- but not for
/// the acquire/release and atomic instructions FEXCore emits to reproduce x86's memory
/// ordering, which fault unless the address is naturally aligned. So an ordinary
/// unaligned store in ordinary guest code arrives here as SIGBUS, and this is the
/// difference between "runs x86 programs" and "runs x86 programs that never touch an odd
/// address". FEXCore provides the fixup; what is needed here is to recognise the fault,
/// call it, and resume at the instruction it says to resume at.
bool RecoverAlignmentFault(int signal, siginfo_t* info, void* raw_context) {
#if defined(__aarch64__) && defined(__APPLE__)
    if (signal != SIGBUS || info == nullptr || raw_context == nullptr) {
        return false;
    }
    if (g_active.context == nullptr || g_active.thread == nullptr) {
        return false;
    }
    if (info->si_code != BUS_ADRALN) {
        return false; // A real bad-address fault, not an alignment one.
    }

    auto* context = static_cast<ucontext_t*>(raw_context);
    auto& state = context->uc_mcontext->__ss;
    const auto pc = static_cast<uintptr_t>(arm_thread_state64_get_pc(state));

    // Only faults inside FEXCore's own generated code are ours to fix. Anything else is
    // a genuine bug in Fathom and must stay fatal.
    if (!g_active.context->IsAddressInCodeBuffer(g_active.thread, pc)) {
        return false;
    }

    // x0-x28 are plain integers in Darwin's thread state; fp and lr are separate
    // pointer-authentication-opaque fields. FEXCore wants all 31 flat, indexed by the
    // instruction's register field.
    std::array<uint64_t, 31> registers;
    std::memcpy(registers.data(), state.__x, sizeof(state.__x));
    registers[29] = static_cast<uint64_t>(arm_thread_state64_get_fp(state));
    registers[30] = static_cast<uint64_t>(arm_thread_state64_get_lr(state));

    // The fixup rewrites the faulting instruction in place. On iOS the executing address
    // is the execute-only half of a dual mapping and can never be written through, so the
    // writable alias has to be found first -- writing through `pc` would fault inside the
    // handler that exists to prevent exactly this, with the original signal still masked.
    FEXCore::Allocator::ScopedJITWriteProtect write_guard;
    const auto writable_pc =
        reinterpret_cast<uintptr_t>(FEXCore::Allocator::GetWritableAddress(reinterpret_cast<void*>(pc)));

    const auto adjustment = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(
        g_active.thread, FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier,
        writable_pc, registers.data());
    if (!adjustment.has_value()) {
        return false;
    }

    // The patch went in through the writable alias; execution resumes through the
    // executable one. The instruction cache is tagged by virtual address, so invalidating
    // one alias does not invalidate the other -- without this the CPU can re-fetch the
    // pre-patch instruction and run off into whatever happens to be cached.
    __builtin___clear_cache(reinterpret_cast<char*>(pc - 4), reinterpret_cast<char*>(pc + 8));

    std::memcpy(state.__x, registers.data(), sizeof(state.__x));
    arm_thread_state64_set_fp(state, registers[29]);
    arm_thread_state64_set_lr_fptr(state, reinterpret_cast<void*>(registers[30]));
    arm_thread_state64_set_pc_fptr(state, reinterpret_cast<void*>(pc + *adjustment));
    g_alignment_fixups.fetch_add(1, std::memory_order_relaxed);
    return true;
#else
    (void)signal;
    (void)info;
    (void)raw_context;
    return false;
#endif
}

class FathomSignalDelegator final : public FEXCore::SignalDelegator {
public:
    uintptr_t GetThunkCallbackRET() const override {
        // Fathom never calls back into guest code from the host, so no veneer address is
        // ever needed. Anything that reached this would be a FEXCore path Fathom does
        // not use, and zero makes that fail loudly instead of jumping somewhere random.
        return 0;
    }
};

class FathomSyscallHandler final : public FEXCore::HLE::SyscallHandler {
public:
    FathomSyscallHandler(LinuxSyscalls& syscalls, GuestAddressSpace& space)
        : syscalls_ {syscalls}
        , space_ {space} {
        // OS_LINUX64 tells the JIT the guest's syscall ABI, so it hands the arguments
        // over in registers rather than spilling the entire CPU state on every call.
        OSABI = FEXCore::HLE::SyscallOSABI::OS_LINUX64;
    }

    uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* frame, FEXCore::HLE::SyscallArguments* args) override {
        // Under OS_LINUX64 the argument array is {RAX, RDI, RSI, RDX, R10, R8, R9}:
        // the syscall number first, then x86-64 Linux's six argument registers in order.
        //
        // A syscall is the one place the guest's RIP is reliably settled, so it is also
        // the only honest place to record it for the crash handler.
        if (frame != nullptr) {
            NoteGuestRip(frame->State.rip);
        }
        return syscalls_.Handle(args->Argument[0], args->Argument[1], args->Argument[2],
                                args->Argument[3], args->Argument[4], args->Argument[5],
                                args->Argument[6]);
    }

    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState*,
                                                               uint64_t address) override {
        GuestRange range {};
        if (!space_.RangeFor(address, &range)) {
            return {address, 1, false};
        }
        return {range.begin, range.size, (range.protection & kGuestProtWrite) != 0};
    }

    std::optional<FEXCore::ExecutableFileSectionInfo>
    LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t) override {
        // Only used to name regions in FEX's own profiling output.
        return std::nullopt;
    }

private:
    LinuxSyscalls& syscalls_;
    GuestAddressSpace& space_;
};

} // namespace

class FexEngine::Impl {
public:
    Impl(GuestAddressSpace& space, LinuxSyscalls& syscalls)
        : space {space}
        , syscalls {syscalls} {}

    ~Impl() {
        if (context != nullptr && thread != nullptr) {
            context->DestroyThread(thread);
            thread = nullptr;
        }
        context.reset();
        if (config_held) {
            ConfigLease::Release();
        }
    }

    GuestAddressSpace& space;
    LinuxSyscalls& syscalls;

    FEXCore::HostFeatures host_features {};
    fextl::unique_ptr<FEXCore::Context::Context> context;
    std::unique_ptr<FathomSignalDelegator> signals;
    std::unique_ptr<FathomSyscallHandler> handler;
    std::unique_ptr<CallRetStack> callret;
    GuestSegments segments;
    FEXCore::Core::InternalThreadState* thread {};

    FEXCore::UncheckedLongJump::JumpBuf exit_jump {};
    bool exit_jump_armed {};
    int exit_status {};
    bool exit_requested {};
    bool config_held {};
};

FexEngine::FexEngine(std::unique_ptr<Impl> impl)
    : impl_ {std::move(impl)} {}

FexEngine::~FexEngine() = default;

const char* FexEngine::FexRevision() {
#ifdef GIT_DESCRIBE_STRING
    return GIT_DESCRIBE_STRING;
#else
    return "unknown";
#endif
}

std::unique_ptr<FexEngine> FexEngine::Create(GuestAddressSpace& space, LinuxSyscalls& syscalls,
                                             const EngineOptions& options, std::string& error) {
    auto impl = std::make_unique<Impl>(space, syscalls);

    ConfigLease::Acquire(options);
    impl->config_held = true;

    // Reads the real CPU through sysctl rather than the ID_AA64* system registers Linux
    // exposes -- those fault on Darwin, which is one of the fixes that made this FEXCore
    // tree work on Apple hardware at all.
    impl->host_features = FEX::FetchHostFeatures();

    impl->context = FEXCore::Context::Context::CreateNewContext(impl->host_features);
    if (impl->context == nullptr) {
        error = "FEXCore refused to create a context";
        return nullptr;
    }

    impl->signals = std::make_unique<FathomSignalDelegator>();
    impl->handler = std::make_unique<FathomSyscallHandler>(syscalls, space);
    impl->context->SetSignalDelegator(impl->signals.get());
    impl->context->SetSyscallHandler(impl->handler.get());

    // A guest that executes HLT should stop the run, not trap. Normal exits come through
    // exit_group instead, but a jump into unmapped-but-zeroed memory tends to land here.
    impl->context->EnableExitOnHLT();

    if (!impl->context->InitCore()) {
        error = "FEXCore could not initialise its JIT. On iOS this is what a missing JIT "
                "permission looks like: the code buffers cannot be made executable.";
        return nullptr;
    }

    // From here on, a guest alignment fault is recoverable rather than fatal.
    SetFaultRecovery(RecoverAlignmentFault);

    FATHOM_INFO("FEXCore context ready (AVX=%d, SVE128=%d, cache line %u)",
                impl->host_features.SupportsAVX ? 1 : 0, impl->host_features.SupportsSVE128 ? 1 : 0,
                impl->host_features.DCacheLineSize);
    return std::unique_ptr<FexEngine> {new FexEngine {std::move(impl)}};
}

bool FexEngine::Prepare(uint64_t rip, uint64_t rsp, std::string& error) {
    impl_->callret = std::make_unique<CallRetStack>();
    if (!impl_->callret->valid()) {
        error = std::string {"could not reserve the call/return stack: "} +
                std::strerror(impl_->callret->error());
        return false;
    }

    impl_->thread = impl_->context->CreateThread(rip, rsp);
    if (impl_->thread == nullptr) {
        error = "FEXCore could not create the guest thread";
        return false;
    }

    auto& state = impl_->thread->CurrentFrame->State;
    impl_->segments.Initialise(state);
    impl_->callret->Attach(impl_->thread);
    state.rip = rip;
    state.gregs[FEXCore::X86State::REG_RSP] = rsp;

    // A freshly executed Linux program starts with a defined flag state: bit 1 is
    // reserved and always set, everything else clear.
    impl_->context->SetFlagsFromCompactedEFLAGS(impl_->thread, 1U << 1);

    std::array<__uint128_t, FEXCore::Core::CPUState::NUM_XMMS> xmm {};
    std::array<__uint128_t, FEXCore::Core::CPUState::NUM_XMMS> ymm_high {};
    impl_->context->SetXMMRegistersFromState(impl_->thread, xmm.data(),
                                             impl_->host_features.SupportsAVX ? ymm_high.data() : nullptr);

    FATHOM_INFO("guest thread ready: rip=%#llx rsp=%#llx", static_cast<unsigned long long>(rip),
                static_cast<unsigned long long>(rsp));
    return true;
}

RunResult FexEngine::Run() {
    RunResult result;
    if (impl_->thread == nullptr) {
        result.message = "no guest thread";
        return result;
    }

    // The guest leaves the JIT one of two ways. A clean HLT returns from ExecuteThread
    // normally; exit_group happens deep inside a syscall with JIT frames still on the
    // host stack, and the only way out of there is to unwind past them. FEX's own thread
    // exit does exactly this, which is why FEXCore ships the jump buffer used here.
    if (FEXCore::UncheckedLongJump::SetJump(impl_->exit_jump) == 0) {
        impl_->exit_jump_armed = true;
        g_active = ActiveExecution {impl_->context.get(), impl_->thread};
        impl_->context->ExecuteThread(impl_->thread);
        g_active = ActiveExecution {};
        impl_->exit_jump_armed = false;

        result.outcome = RunOutcome::Halted;
        result.status = 0;
        result.message = "guest halted";
    } else {
        // Reached by the long jump out of exit_group, which skips the clear above.
        g_active = ActiveExecution {};
        impl_->exit_jump_armed = false;
        if (impl_->syscalls.StopRequested()) {
            result.outcome = RunOutcome::Stopped;
            result.status = -1;
            result.message = "stopped";
        } else {
            result.outcome = RunOutcome::Exited;
            result.status = impl_->exit_status;
            result.message = "guest exited";
        }
    }

    FATHOM_INFO("run ended: %llu guest alignment faults recovered",
                static_cast<unsigned long long>(g_alignment_fixups.load(std::memory_order_relaxed)));

    const auto& state = impl_->thread->CurrentFrame->State;
    result.rip = state.rip;
    result.rsp = state.gregs[FEXCore::X86State::REG_RSP];
    return result;
}

uint64_t FexEngine::Rip() const {
    return impl_->thread == nullptr ? 0 : impl_->thread->CurrentFrame->State.rip;
}

uint64_t FexEngine::Rsp() const {
    return impl_->thread == nullptr ? 0
                                    : impl_->thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP];
}

void FexEngine::SetFsBase(uint64_t base) {
    if (impl_->thread != nullptr) {
        impl_->thread->CurrentFrame->State.fs_cached = base;
    }
}

uint64_t FexEngine::GetFsBase() const {
    return impl_->thread == nullptr ? 0 : impl_->thread->CurrentFrame->State.fs_cached;
}

void FexEngine::ExitGuest(int status) {
    impl_->exit_status = status;
    impl_->exit_requested = true;
    if (impl_->exit_jump_armed) {
        FEXCore::UncheckedLongJump::LongJump(impl_->exit_jump, 1);
    }
    // Unreachable in practice: Run() arms the jump before the guest can execute a single
    // instruction, so there is no window where a guest syscall arrives without it.
    FATHOM_ERROR("guest exit requested with no unwind point; aborting");
    std::abort();
}

} // namespace fathom

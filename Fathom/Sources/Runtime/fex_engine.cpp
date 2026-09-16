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
#include <cstdio>
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

        // The one setting that changes how every instruction is decoded.
        FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, options.guest_is_32bit ? "0" : "1");
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

/// How many GDT slots the guest gets. FEXCore indexes this array with a selector's top
/// 13 bits, and Linux only ever hands userspace entries 12 through 14.
constexpr int kGdtEntries = 32;

/// The guest's segment descriptors. x86-64 barely uses segmentation, but the JIT still
/// reads a cached CS base, and leaving it unset produces wrong addresses rather than an
/// obvious failure.
class GuestSegments {
public:
    void Initialise(FEXCore::Core::CPUState& state, bool guest_is_32bit = false) {
        state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = gdt_.data();
        state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = gdt_.data();
        state.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
        auto* code_segment = FEXCore::Core::CPUState::GetSegmentFromIndex(state, state.cs_idx);
        FEXCore::Core::CPUState::SetGDTBase(code_segment, 0);
        FEXCore::Core::CPUState::SetGDTLimit(code_segment, 0xF'FFFFU);
        state.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(*code_segment);
        // These two bits are how the guest's word size is actually decided. FEXCore's
        // decoder reads the mode straight off this descriptor -- `Is64BitMode = CSSegment->L`
        // -- and not from any configuration value, so leaving L set here makes a 32-bit
        // program get decoded as x86-64 no matter what else has been configured. The
        // symptom is an `int 0x80` refused as "32-bit syscall from a 64-bit process".
        code_segment->L = guest_is_32bit ? 0 : 1;
        code_segment->D = guest_is_32bit ? 1 : 0;
    }

private:
    std::array<FEXCore::Core::CPUState::gdt_segment, kGdtEntries> gdt_ {};
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

/// Whose syscalls to answer. FEXCore has one syscall handler per context, but Fathom has
/// one LinuxSyscalls per process, so the handler has to route to whichever guest thread
/// is currently executing on this host thread.
thread_local LinuxSyscalls* g_current_syscalls = nullptr;

/// Writes the executing guest thread's registers out for a crash record. Signal-handler
/// context: no allocation, no locks, and g_active is thread-local so it describes the
/// thread that actually faulted.
size_t DescribeGuestState(char* buffer, size_t capacity) {
    if (g_active.thread == nullptr || buffer == nullptr || capacity == 0) {
        return 0;
    }
    const auto& state = g_active.thread->CurrentFrame->State;
    static const char* kNames[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                   "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    int written = std::snprintf(buffer, capacity, "  rip %016llx\n",
                                static_cast<unsigned long long>(state.rip));
    for (size_t index = 0; index < 16 && written > 0 && static_cast<size_t>(written) < capacity; ++index) {
        written += std::snprintf(buffer + written, capacity - static_cast<size_t>(written),
                                 "  %-3s %016llx%s", kNames[index],
                                 static_cast<unsigned long long>(state.gregs[index]),
                                 (index % 2 == 1) ? "\n" : "");
    }
    return written < 0 ? 0 : static_cast<size_t>(written);
}

class FathomSyscallHandler final : public FEXCore::HLE::SyscallHandler {
public:
    FathomSyscallHandler(GuestAddressSpace& space, bool guest_is_32bit)
        : space_ {space} {
        // Which ABI the JIT hands syscall arguments over in, so it passes them in
        // registers rather than spilling the whole CPU state on every call. It also
        // decides whether `int 0x80` is legal: with OS_LINUX64 declared, a 32-bit guest's
        // first syscall is refused with "trying to execute 32-bit syscall from a 64-bit
        // process" and the guest goes no further.
        OSABI = guest_is_32bit ? FEXCore::HLE::SyscallOSABI::OS_LINUX32
                               : FEXCore::HLE::SyscallOSABI::OS_LINUX64;
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
        auto* syscalls = g_current_syscalls;
        if (syscalls == nullptr) {
            FATHOM_ERROR("syscall on a host thread with no guest thread bound");
            return static_cast<uint64_t>(-38); // -ENOSYS
        }
        return syscalls->Handle(args->Argument[0], args->Argument[1], args->Argument[2],
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
    GuestAddressSpace& space_;
};

} // namespace

// ---------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------

class FexEngine::Impl {
public:
    explicit Impl(GuestAddressSpace& space)
        : space {space} {}

    ~Impl() {
        context.reset();
        if (config_held) {
            ConfigLease::Release();
        }
    }

    GuestAddressSpace& space;

    FEXCore::HostFeatures host_features {};
    fextl::unique_ptr<FEXCore::Context::Context> context;
    bool guest_is_32bit {};
    std::unique_ptr<FathomSignalDelegator> signals;
    std::unique_ptr<FathomSyscallHandler> handler;
    bool config_held {};
};

// ---------------------------------------------------------------------------
// A thread
// ---------------------------------------------------------------------------

class GuestThread::Impl {
public:
    Impl(FEXCore::Context::Context* context, LinuxSyscalls& syscalls, bool guest_is_32bit)
        : context {context}
        , syscalls {syscalls}
        , guest_is_32bit {guest_is_32bit} {}

    ~Impl() {
        if (context != nullptr && thread != nullptr) {
            context->DestroyThread(thread);
            thread = nullptr;
        }
    }

    FEXCore::Context::Context* context {};
    LinuxSyscalls& syscalls;
    bool guest_is_32bit {};

    // Per thread, all of it. The call/return stack and the segment table are pointed at
    // from the register file, so a forked child needs its own rather than the copies it
    // would otherwise inherit from its parent.
    std::unique_ptr<CallRetStack> callret;
    GuestSegments segments;
    FEXCore::Core::InternalThreadState* thread {};

    FEXCore::UncheckedLongJump::JumpBuf exit_jump {};
    bool exit_jump_armed {};
    int exit_status {};
    bool exec_requested {};
};

GuestThread::GuestThread(std::unique_ptr<Impl> impl)
    : impl_ {std::move(impl)} {}

GuestThread::~GuestThread() = default;

RunResult GuestThread::Run() {
    RunResult result;
    if (impl_->thread == nullptr) {
        result.message = "no guest thread";
        return result;
    }

    // Bound for the duration of the run: the syscall handler is shared by every thread in
    // the context and finds this thread's syscall state through it.
    g_current_syscalls = &impl_->syscalls;

    // The guest leaves the JIT one of two ways. A clean HLT returns from ExecuteThread
    // normally; exit_group happens deep inside a syscall with JIT frames still on the
    // host stack, and the only way out of there is to unwind past them. FEX's own thread
    // exit does exactly this, which is why FEXCore ships the jump buffer used here.
    if (FEXCore::UncheckedLongJump::SetJump(impl_->exit_jump) == 0) {
        impl_->exit_jump_armed = true;
        g_active = ActiveExecution {impl_->context, impl_->thread};
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
        if (impl_->exec_requested) {
            impl_->exec_requested = false;
            result.outcome = RunOutcome::Execed;
            result.status = 0;
            result.message = "execve";
        } else if (impl_->syscalls.StopRequested()) {
            result.outcome = RunOutcome::Stopped;
            result.status = -1;
            result.message = "stopped";
        } else {
            result.outcome = RunOutcome::Exited;
            result.status = impl_->exit_status;
            result.message = "guest exited";
        }
    }

    g_current_syscalls = nullptr;

    const auto& state = impl_->thread->CurrentFrame->State;
    result.rip = state.rip;
    result.rsp = state.gregs[FEXCore::X86State::REG_RSP];
    return result;
}

void GuestThread::ResetTo(uint64_t rip, uint64_t rsp) {
    // A register file, cleared wholesale: CPUState has no copy assignment, and byte-wise
    // is what "a fresh set of registers" actually means here.
    auto& state = impl_->thread->CurrentFrame->State;
    std::memset(&state, 0, sizeof(state));
    impl_->segments.Initialise(state, impl_->guest_is_32bit);
    impl_->callret->Attach(impl_->thread);
    state.rip = rip;
    state.gregs[FEXCore::X86State::REG_RSP] = rsp;
    impl_->context->SetFlagsFromCompactedEFLAGS(impl_->thread, 1U << 1);
}

uint64_t GuestThread::Rip() const {
    return impl_->thread == nullptr ? 0 : impl_->thread->CurrentFrame->State.rip;
}

uint64_t GuestThread::Rsp() const {
    return impl_->thread == nullptr ? 0
                                    : impl_->thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP];
}

uint64_t GuestThread::Rax() const {
    return impl_->thread == nullptr ? 0 : impl_->thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
}

void GuestThread::SetFsBase(uint64_t base) {
    if (impl_->thread != nullptr) {
        impl_->thread->CurrentFrame->State.fs_cached = base;
    }
}

uint64_t GuestThread::GetFsBase() const {
    return impl_->thread == nullptr ? 0 : impl_->thread->CurrentFrame->State.fs_cached;
}

void GuestThread::SetTlsDescriptor(int entry, uint32_t base, uint32_t limit) {
    if (impl_->thread == nullptr || entry < 0 || entry >= kGdtEntries) {
        return;
    }
    auto& state = impl_->thread->CurrentFrame->State;
    auto* descriptor = &state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT][entry];
    FEXCore::Core::CPUState::SetGDTBase(descriptor, base);
    FEXCore::Core::CPUState::SetGDTLimit(descriptor, limit);
    descriptor->S = 1;      // A code/data descriptor rather than a system one.
    descriptor->Type = 3;   // Data, read/write, accessed.
    descriptor->DPL = 3;    // Userspace.
    descriptor->P = 1;      // Present.
    descriptor->D = 1;      // 32-bit.
    descriptor->G = 1;      // Limit counted in pages.
    // The guest loads %gs from this entry immediately afterwards, and that load recomputes
    // the cached base itself. Refreshing it here matters only when the entry it is
    // rewriting is the one %gs already points at, which is what a second thread does.
    if ((state.gs_idx >> 3) == entry) {
        state.gs_cached = FEXCore::Core::CPUState::CalculateGDTBase(*descriptor);
    }
}

void GuestThread::ExecGuest() {
    impl_->exec_requested = true;
    if (impl_->exit_jump_armed) {
        FEXCore::UncheckedLongJump::LongJump(impl_->exit_jump, 1);
    }
    FATHOM_ERROR("execve requested with no unwind point; aborting");
    std::abort();
}

void GuestThread::ExitGuest(int status) {
    impl_->exit_status = status;
    if (impl_->exit_jump_armed) {
        FEXCore::UncheckedLongJump::LongJump(impl_->exit_jump, 1);
    }
    // Unreachable in practice: Run() arms the jump before the guest can execute a single
    // instruction, so there is no window where a guest syscall arrives without it.
    FATHOM_ERROR("guest exit requested with no unwind point; aborting");
    std::abort();
}

// ---------------------------------------------------------------------------
// Creating them
// ---------------------------------------------------------------------------

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

std::unique_ptr<FexEngine> FexEngine::Create(GuestAddressSpace& space, const EngineOptions& options,
                                             std::string& error) {
    auto impl = std::make_unique<Impl>(space);

    ConfigLease::Acquire(options);
    impl->config_held = true;

    // Reads the real CPU through sysctl rather than the ID_AA64* system registers Linux
    // exposes -- those fault on Darwin, which is one of the fixes that made this FEXCore
    // tree work on Apple hardware at all.
    impl->host_features = FEX::FetchHostFeatures();
    if (options.disable_avx) {
        impl->host_features.SupportsAVX = false;
        FATHOM_INFO("AVX disabled: the guest will be told this CPU has none");
    }

    impl->context = FEXCore::Context::Context::CreateNewContext(impl->host_features);
    if (impl->context == nullptr) {
        error = "FEXCore refused to create a context";
        return nullptr;
    }

    // Told before any code is compiled, because it changes every address the JIT emits.
    impl->context->SetGuestMemoryBase(options.guest_memory_base);
    if (options.guest_memory_base != 0) {
        FATHOM_INFO("32-bit guest: its address space is placed at %#llx in this process",
                    static_cast<unsigned long long>(options.guest_memory_base));
    }

    impl->signals = std::make_unique<FathomSignalDelegator>();
    impl->guest_is_32bit = options.guest_is_32bit;
    impl->handler = std::make_unique<FathomSyscallHandler>(space, options.guest_is_32bit);
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
    SetGuestStateDescriber(DescribeGuestState);

    FATHOM_INFO("FEXCore context ready (AVX=%d, SVE128=%d, cache line %u)",
                impl->host_features.SupportsAVX ? 1 : 0, impl->host_features.SupportsSVE128 ? 1 : 0,
                impl->host_features.DCacheLineSize);
    return std::unique_ptr<FexEngine> {new FexEngine {std::move(impl)}};
}

std::unique_ptr<GuestThread> FexEngine::StartThread(uint64_t rip, uint64_t rsp, LinuxSyscalls& syscalls,
                                                    std::string& error) {
    auto impl = std::make_unique<GuestThread::Impl>(impl_->context.get(), syscalls, impl_->guest_is_32bit);

    impl->callret = std::make_unique<CallRetStack>();
    if (!impl->callret->valid()) {
        error = std::string {"could not reserve the call/return stack: "} +
                std::strerror(impl->callret->error());
        return nullptr;
    }

    impl->thread = impl_->context->CreateThread(rip, rsp);
    if (impl->thread == nullptr) {
        error = "FEXCore could not create the guest thread";
        return nullptr;
    }

    auto& state = impl->thread->CurrentFrame->State;
    impl->segments.Initialise(state, impl->guest_is_32bit);
    impl->callret->Attach(impl->thread);
    state.rip = rip;
    state.gregs[FEXCore::X86State::REG_RSP] = rsp;

    // A freshly executed Linux program starts with a defined flag state: bit 1 is
    // reserved and always set, everything else clear.
    impl_->context->SetFlagsFromCompactedEFLAGS(impl->thread, 1U << 1);

    std::array<__uint128_t, FEXCore::Core::CPUState::NUM_XMMS> xmm {};
    std::array<__uint128_t, FEXCore::Core::CPUState::NUM_XMMS> ymm_high {};
    impl_->context->SetXMMRegistersFromState(impl->thread, xmm.data(),
                                             impl_->host_features.SupportsAVX ? ymm_high.data() : nullptr);

    FATHOM_INFO("guest thread ready: rip=%#llx rsp=%#llx", static_cast<unsigned long long>(rip),
                static_cast<unsigned long long>(rsp));
    return std::unique_ptr<GuestThread> {new GuestThread {std::move(impl)}};
}

std::unique_ptr<GuestThread> FexEngine::ForkThread(const GuestThread& parent, LinuxSyscalls& syscalls,
                                                   std::string& error) {
    const auto& parent_state = parent.impl_->thread->CurrentFrame->State;

    auto impl = std::make_unique<GuestThread::Impl>(impl_->context.get(), syscalls, impl_->guest_is_32bit);
    impl->callret = std::make_unique<CallRetStack>();
    if (!impl->callret->valid()) {
        error = std::string {"could not reserve the child's call/return stack: "} +
                std::strerror(impl->callret->error());
        return nullptr;
    }

    // Where the child resumes is not the parent's rip. During a syscall FEX sets
    // State.rip to the address *of* the syscall instruction, so starting a child there
    // would execute it a second time -- with RAX cleared, that is a read(), which is
    // precisely the wrong thing and looks maddeningly like the child ignoring the fork.
    //
    // The x86-64 syscall instruction puts its own return address in RCX, and FEX honours
    // that, so RCX is the instruction after the syscall: exactly where a returning fork
    // belongs. sysret does the same thing on real hardware.
    const uint64_t resume = parent_state.gregs[FEXCore::X86State::REG_RCX] != 0
                                ? parent_state.gregs[FEXCore::X86State::REG_RCX]
                                : parent_state.rip + 2; // 0F 05, for a guest that got here via int 0x80

    // Handed to CreateThread rather than memcpy'd in afterwards. FEX copies the state
    // first and *then* does its own per-thread setup on top -- InitializeCompiler, and
    // clearing DeferredSignalRefCount. Copying over the register file after the fact
    // undoes exactly that work and leaves the child holding its parent's signal
    // bookkeeping, which is how a second running thread ends up dereferencing null.
    FEXCore::Core::CPUState child_state;
    std::memcpy(&child_state, &parent_state, sizeof(child_state));
    child_state.rip = resume;
    child_state.gregs[FEXCore::X86State::REG_RAX] = 0;

    impl->thread = impl_->context->CreateThread(resume, child_state.gregs[FEXCore::X86State::REG_RSP],
                                                &child_state);
    if (impl->thread == nullptr) {
        error = "FEXCore could not create the child guest thread";
        return nullptr;
    }

    // The call/return stack and the segment table are reached through the register file,
    // and the child must not share its parent's.
    auto& state = impl->thread->CurrentFrame->State;
    impl->segments.Initialise(state, impl->guest_is_32bit);
    impl->callret->Attach(impl->thread);

    FATHOM_INFO("forked guest thread: rip=%#llx rsp=%#llx",
                static_cast<unsigned long long>(state.rip),
                static_cast<unsigned long long>(state.gregs[FEXCore::X86State::REG_RSP]));
    return std::unique_ptr<GuestThread> {new GuestThread {std::move(impl)}};
}

} // namespace fathom

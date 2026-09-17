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
#include <mach/thread_act.h>
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
    /// `inherit` is the descriptor table of the thread this one is being made from.
    ///
    /// A thread's descriptor table is its own -- it must not share its parent's array,
    /// because set_thread_area on one would move the other's TLS -- but its *contents* are
    /// inherited. clone without CLONE_SETTLS means "keep using the thread pointer you were
    /// made with", which is how a program that starts a thread with a raw clone rather
    /// than pthread_create gets its thread-local storage at all. Starting that thread with
    /// an empty table gives it a %gs base of zero, and the first thing it reads out of its
    /// own control block -- the function it was created to run -- comes back as whatever
    /// is at guest address zero.
    void Initialise(FEXCore::Core::CPUState& state, bool guest_is_32bit = false,
                    const GuestSegments* inherit = nullptr) {
        if (inherit != nullptr) {
            gdt_ = inherit->gdt_;
        }
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

/// Serialises every creation and destruction of a FEXCore thread, across every context.
///
/// FEXCore's own CreateThread takes no locks, and the JIT core it builds claims a code
/// buffer from a pool shared by the whole process. Two of them at once leave one thread
/// holding a half-built dispatcher, and the first thing that thread does is call through
/// it -- a jump to address zero, on a thread whose only frame is the one that started it.
/// Fathom reaches this from three directions at once (a program starting, a thread
/// cloning, a process forking) and only one of those was ever under a lock.
std::mutex g_thread_lifecycle;

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
    // Counted, and reported every so often. Each faulting site is meant to be patched
    // once and never fault again; a count that keeps climbing says the patches are not
    // sticking, and that is the difference between memory-ordering emulation costing
    // nothing and costing most of the run.
    const auto fixups = g_alignment_fixups.fetch_add(1, std::memory_order_relaxed) + 1;
    if ((fixups & 0xFFFFF) == 0) {
        FATHOM_INFO("%llu unaligned accesses emulated so far -- an atomic one cannot be\n"
                    "  patched away, so each execution of it costs a signal",
                    static_cast<unsigned long long>(fixups));
    }
    return true;
#else
    (void)signal;
    (void)info;
    (void)raw_context;
    return false;
#endif
}

/// The guest thread this host thread is running, for the code that has only a signal
/// context to go on.
thread_local GuestThread* g_current_guest_thread = nullptr;

/// The guest's arena, so that a signal handler can tell a guest address from any other.
std::atomic<fathom::GuestAddressSpace*> g_arena_space {nullptr};
std::atomic<uint64_t> g_arena_begin {0};

std::atomic<uint64_t> g_arena_end {0};

/// Ends the guest process whose code just faulted, instead of the whole session.
///
/// A fault in guest code is the guest's own bug, and on Linux it kills that process and
/// nothing else: the shell prints "Segmentation fault" and carries on, and Steam notices
/// a helper died and starts another. Here every guest process is a thread of one host
/// process, so the default action takes the emulator down with it -- one crashing helper
/// and the whole session is gone.
///
struct LiveThread {
    FEXCore::Context::Context* context {};
    FEXCore::Core::InternalThreadState* thread {};
    uint64_t guest_base {};
    /// The host thread running it, recorded once that thread is actually running. Needed
    /// because throwing compiled code away has to stop everything that might be executing
    /// it: FEXCore takes its invalidation lock to keep anything from *compiling*, but a
    /// thread running an already-compiled block never takes that lock at all, and a block
    /// unlinked out from under such a thread is a wild pointer in its link list.
    uint32_t port {};
};

std::mutex g_live_threads_mutex;
std::vector<LiveThread> g_live_threads;

/// The same threads again, in a form a signal handler can read.
///
/// Deciding whether a fault happened in generated code means asking each live thread, and
/// a handler must not wait for a lock -- the thread it interrupted may be holding it. A
/// fixed array of slots, published with release stores, can be read at any time; a slot
/// that is stale only costs one wrong answer about a thread that has just gone.
constexpr size_t kLiveSlots = 512;
struct LiveSlot {
    std::atomic<FEXCore::Context::Context*> context {nullptr};
    std::atomic<FEXCore::Core::InternalThreadState*> thread {nullptr};
};
LiveSlot g_live_slots[kLiveSlots];

void PublishLiveThread(FEXCore::Context::Context* context, FEXCore::Core::InternalThreadState* thread) {
    for (auto& slot : g_live_slots) {
        FEXCore::Core::InternalThreadState* empty = nullptr;
        if (slot.thread.compare_exchange_strong(empty, thread, std::memory_order_acq_rel)) {
            slot.context.store(context, std::memory_order_release);
            return;
        }
    }
}

void RetireLiveThread(FEXCore::Core::InternalThreadState* thread) {
    for (auto& slot : g_live_slots) {
        if (slot.thread.load(std::memory_order_acquire) == thread) {
            slot.context.store(nullptr, std::memory_order_release);
            slot.thread.store(nullptr, std::memory_order_release);
            return;
        }
    }
}
/// How many sweeps are using a copy of that list. A thread may not be destroyed while any
/// of them is, because the sweep reaches into it.
size_t g_invalidators {0};
std::condition_variable g_invalidations_done;

/// Unwinding out of a signal handler is only safe because of the check below: the fault
/// must have happened inside FEXCore's generated code, where the guest holds no lock of
/// ours and owns nothing that has to be put back. A fault anywhere else is a bug in
/// Fathom itself and stays fatal, because there the process really is in no state to
/// continue.
bool EndFaultedGuestThread(int signal, siginfo_t* info, void* raw_context) {
#if defined(__aarch64__) && defined(__APPLE__)
    if (raw_context == nullptr || g_current_guest_thread == nullptr) {
        return false;
    }
    auto* context = static_cast<ucontext_t*>(raw_context);
    const auto pc = static_cast<uintptr_t>(arm_thread_state64_get_pc(context->uc_mcontext->__ss));
    bool in_generated_code = g_active.context != nullptr && g_active.thread != nullptr &&
                             g_active.context->IsAddressInCodeBuffer(g_active.thread, pc);
    if (!in_generated_code) {
        // A block compiled into a buffer another thread owns is still generated code, and
        // still this guest's fault -- FEXCore hands a thread whatever buffer had room.
        // Read without a lock: a handler that waits for a lock the thread it interrupted
        // is holding never returns.
        // Every live thread, in any context: a fault in generated code is the guest's
        // whichever buffer it landed in, and the thread that faulted may not be the one
        // bound to this host thread's record any more.
        for (const auto& slot : g_live_slots) {
            auto* thread = slot.thread.load(std::memory_order_acquire);
            auto* owner = slot.context.load(std::memory_order_acquire);
            if (thread == nullptr || owner == nullptr) {
                continue;
            }
            if (owner->IsAddressInCodeBuffer(thread, pc)) {
                in_generated_code = true;
                break;
            }
        }
    }
    if (!in_generated_code) {
        // Not in generated code -- but a guest that jumps to an address with nothing at it
        // faults inside FEXCore's instruction decoder rather than in the code it was
        // about to run, because the decoder is what reads guest memory first. The address
        // being inside the guest's own arena is what says this is still the guest's fault
        // and not ours.
        const auto address = info == nullptr ? 0 : reinterpret_cast<uint64_t>(info->si_addr);
        const uint64_t begin = g_arena_begin.load(std::memory_order_acquire);
        const uint64_t end = g_arena_end.load(std::memory_order_acquire);
        if (begin == 0 || address < begin || address >= end) {
            return false;
        }
    }
    // What the guest was reaching for, and what the address space thinks is there. A fault
    // on memory the arena says is mapped and writable is a different bug from a fault on
    // memory nothing is mapped at, and from outside they look identical.
    if (info != nullptr) {
        const auto address = reinterpret_cast<uint64_t>(info->si_addr);
        auto* space = g_arena_space.load(std::memory_order_acquire);
        fathom::GuestRange range {};
        if (space != nullptr && space->RangeFor(address, &range)) {
            FATHOM_WARN("guest fault at %#llx: mapped %#llx..%#llx, protection %d",
                        static_cast<unsigned long long>(address),
                        static_cast<unsigned long long>(range.begin),
                        static_cast<unsigned long long>(range.end()), range.protection);
        } else {
            FATHOM_WARN("guest fault at %#llx: nothing is mapped there",
                        static_cast<unsigned long long>(address));
        }
    }
    return g_current_guest_thread->EndOnFault(signal);
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
/// Where this host thread's guest address space starts, for turning a guest address into
/// something this process can read. Zero for a 64-bit guest, whose addresses are already
/// this process's.
thread_local uint64_t g_current_guest_base = 0;

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

    // The bytes the guest believes are its next instructions. Worth having in a crash
    // report because the two explanations for a program dying in a function that could
    // not possibly do this look identical from the registers alone: either the data it
    // was given is wrong, or what is at that address is not the code that belongs there.
    // Comparing these against the file it was loaded from says which.
    const uint64_t host_rip = state.rip + g_current_guest_base;
    if (written > 0 && static_cast<size_t>(written) + 64 < capacity) {
        const auto* code = reinterpret_cast<const unsigned char*>(
            g_active.context == nullptr ? nullptr : reinterpret_cast<const void*>(host_rip));
        written += std::snprintf(buffer + written, capacity - static_cast<size_t>(written),
                                 "  code");
        for (int index = 0; index < 16 && code != nullptr; ++index) {
            written += std::snprintf(buffer + written, capacity - static_cast<size_t>(written),
                                     " %02x", code[index]);
        }
        written += std::snprintf(buffer + written, capacity - static_cast<size_t>(written), "\n");
    }

    // And what is on the stack. A guest that has jumped somewhere it should not have gives
    // nothing away in its registers, but the words below its stack pointer are the return
    // addresses of everything that called it -- which is the shape of the path it took.
    const uint64_t stack = state.gregs[FEXCore::X86State::REG_RSP] + g_current_guest_base;
    if (written > 0 && stack != 0) {
        const auto* words = reinterpret_cast<const uint32_t*>(stack);
        for (int row = 0; row < 4 && static_cast<size_t>(written) + 80 < capacity; ++row) {
            written += std::snprintf(buffer + written, capacity - static_cast<size_t>(written),
                                     "  stack+%02x", row * 16);
            for (int column = 0; column < 4; ++column) {
                written += std::snprintf(buffer + written, capacity - static_cast<size_t>(written),
                                         " %08x", words[row * 4 + column]);
            }
            written += std::snprintf(buffer + written, capacity - static_cast<size_t>(written),
                                     "\n");
        }
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

    uint64_t guest_base {};

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
// Compiled code that is no longer the code it was compiled from
// ---------------------------------------------------------------------------

/// Every live guest thread, with the context it runs in and where that context's guest
/// address space starts.
///
/// FEXCore caches compiled blocks by guest address. Guest addresses are handed out again
/// -- an exec releases a program's image and the next one is loaded over it, a library is
/// unmapped and another is mapped where it was -- and nothing in FEXCore notices, because
/// nothing tells it. The new program then runs the old program's compiled code: the same
/// addresses, the same block entries, the wrong instructions. It does not look like a
/// stale cache from the outside. It looks like a program jumping to a nonsense address
/// with a nonsense stack pointer, deterministically, in a place that makes no sense.
void RegisterLiveThread(FEXCore::Context::Context* context, FEXCore::Core::InternalThreadState* thread,
                        uint64_t guest_base) {
    if (context == nullptr || thread == nullptr) {
        return;
    }
    PublishLiveThread(context, thread);
    std::scoped_lock lock {g_live_threads_mutex};
    g_live_threads.push_back(LiveThread {context, thread, guest_base});
}

void ForgetLiveThread(FEXCore::Core::InternalThreadState* thread) {
    RetireLiveThread(thread);
    std::scoped_lock lock {g_live_threads_mutex};
    std::erase_if(g_live_threads, [thread](const LiveThread& live) { return live.thread == thread; });
}

/// Drops every compiled block covering [host_begin, host_end) in every live thread.
///
/// The range is a host one, because that is what the address space deals in; FEXCore
/// keeps its cache in the guest's numbering, so each context's own base comes off first.
std::atomic<uint64_t> g_invalidations {0};

void InvalidateCompiledCode(uint64_t host_begin, uint64_t host_end) {
    if (host_end <= host_begin) {
        return;
    }
    // A way to ask what throwing compiled code away is costing. Everything that waits on
    // FEXCore's invalidation lock waits here, and that lock gives writers priority, so a
    // single one of these stops every thread that wants to compile. With this set nothing
    // is thrown away and stale code runs -- which is wrong, and tells us whether the
    // waiting is what matters.
    static const bool disabled = getenv("FATHOM_NO_INVALIDATE") != nullptr;
    if (disabled) {
        return;
    }
    // Counted because throwing compiled code away is not free and it is easy to do far
    // more often than intended: every block dropped is recompiled from scratch, and every
    // unaligned access inside it faults again, because the patch that stopped it faulting
    // was part of the code that was just discarded.
    const auto count = g_invalidations.fetch_add(1, std::memory_order_relaxed) + 1;
    if ((count & 0x3FF) == 0) {
        FATHOM_INFO("%llu code invalidations so far",
                    static_cast<unsigned long long>(count));
    }
    // The list is copied, and a thread is kept from ending while the copy is in use. A
    // thread that ends mid-sweep takes its lookup cache with it, and the invalidation
    // walks into freed memory -- a null dereference inside FEXCore, reached from an
    // ordinary guest mmap. Holding the lock for the whole sweep would do it too, but the
    // sweep waits on FEXCore's own lock and that wait can be long, so a counter is used
    // instead and thread destruction waits on that.
    std::vector<LiveThread> live;
    {
        std::scoped_lock lock {g_live_threads_mutex};
        live = g_live_threads;
        ++g_invalidators;
    }
    struct Finished {
        ~Finished() {
            std::scoped_lock lock {g_live_threads_mutex};
            --g_invalidators;
            g_invalidations_done.notify_all();
        }
    } finished;
    // Contexts first: a code buffer's lookup table is shared by every thread using it.
    const auto self = pthread_mach_thread_np(pthread_self());
    std::set<FEXCore::Context::Context*> contexts;
    for (const auto& entry : live) {
        if (!contexts.insert(entry.context).second) {
            continue;
        }
        const uint64_t begin = host_begin - entry.guest_base;
        std::unique_lock guard {entry.context->GetCodeInvalidationMutex()};

        // Deliberately not stopping the threads that might be *running* a block being
        // thrown away, tempting as it is: a thread looking a block up holds its own lookup
        // cache's read lock while it does, and the invalidation below takes that same
        // cache's write lock -- so a thread stopped at the wrong instant is a lock nothing
        // can take, and every mmap in the process waits on it forever. Unlinking a block
        // under a thread standing in it is a much rarer accident than that.
        entry.context->InvalidateCodeBuffersCodeRange(begin, host_end - host_begin);
        for (const auto& thread : live) {
            if (thread.context == entry.context) {
                entry.context->InvalidateThreadCachedCodeRange(thread.thread, begin,
                                                               host_end - host_begin);
            }
        }
    }
}

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
            ForgetLiveThread(thread);
            {
                // Nothing may be halfway through a sweep that names this thread.
                std::unique_lock wait {g_live_threads_mutex};
                g_invalidations_done.wait(wait, [] { return g_invalidators == 0; });
            }
            std::scoped_lock guard {g_thread_lifecycle};
            context->DestroyThread(thread);
            thread = nullptr;
        }
    }

    FEXCore::Context::Context* context {};
    LinuxSyscalls& syscalls;
    bool guest_is_32bit {};
    uint64_t guest_base {};

    // Per thread, all of it. The call/return stack and the segment table are pointed at
    // from the register file, so a forked child needs its own rather than the copies it
    // would otherwise inherit from its parent.
    std::unique_ptr<CallRetStack> callret;
    GuestSegments segments;
    FEXCore::Core::InternalThreadState* thread {};

    FEXCore::UncheckedLongJump::JumpBuf exit_jump {};
    /// The signal that killed this guest thread, if one did.
    int fatal_signal {};
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
    g_current_guest_thread = this;
    g_current_guest_base = impl_->guest_base;
    {
        // This host thread is the one that will be running compiled code for this guest
        // thread, and only it can say which it is.
        std::scoped_lock lock {g_live_threads_mutex};
        for (auto& live : g_live_threads) {
            if (live.thread == impl_->thread) {
                live.port = pthread_mach_thread_np(pthread_self());
                break;
            }
        }
    }

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
        } else if (impl_->fatal_signal != 0) {
            result.outcome = RunOutcome::Faulted;
            result.status = 128 + impl_->fatal_signal;
            result.message = "killed by a fault in guest code";
            impl_->fatal_signal = 0;
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
    g_current_guest_thread = nullptr;

    const auto& state = impl_->thread->CurrentFrame->State;
    result.rip = state.rip;
    result.rsp = state.gregs[FEXCore::X86State::REG_RSP];
    return result;
}

bool GuestThread::EndOnFault(int signal) {
    if (!impl_->exit_jump_armed) {
        return false;
    }
    impl_->fatal_signal = signal;
    impl_->exit_jump_armed = false;
    // Never returns. The frames between here and Run() are FEXCore's generated code and
    // its dispatcher, which is exactly what exit_group already unwinds past.
    FEXCore::UncheckedLongJump::LongJump(impl_->exit_jump, 1);
    return true;
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

GuestThread* FexEngine::Current() {
    return g_current_guest_thread;
}

void FexEngine::PauseCompilation() {
    impl_->context->GetCodeInvalidationMutex().lock();
}

void FexEngine::ResumeCompilation() {
    impl_->context->GetCodeInvalidationMutex().unlock();
}

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
    g_arena_space.store(&space, std::memory_order_release);
    g_arena_begin.store(space.Base(), std::memory_order_release);
    g_arena_end.store(space.Base() + space.Size(), std::memory_order_release);
    impl->guest_base = options.guest_memory_base;
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
    SetGuestFaultEnder(EndFaultedGuestThread);
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

    impl->guest_base = impl_->guest_base;
    {
        std::scoped_lock guard {g_thread_lifecycle};
        impl->thread = impl_->context->CreateThread(rip, rsp);
    }
    if (impl->thread == nullptr) {
        error = "FEXCore could not create the guest thread";
        return nullptr;
    }
    RegisterLiveThread(impl->context, impl->thread, impl->guest_base);

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
                                                   std::string& error, uint64_t new_rsp) {
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
    //
    // An i386 guest has no such thing: it arrives through `int 0x80` or `sysenter`,
    // neither of which records a return address, and RCX is that ABI's *third syscall
    // argument*. Both instructions are two bytes, so the instruction after is all there
    // is to go on -- and reading RCX there would resume at whatever the caller happened
    // to pass, which for clone is the new thread's stack pointer.
    const uint64_t resume = impl_->guest_is_32bit || parent_state.gregs[FEXCore::X86State::REG_RCX] == 0
                                ? parent_state.rip + 2  // CD 80, or 0F 05
                                : parent_state.gregs[FEXCore::X86State::REG_RCX];

    // Handed to CreateThread rather than memcpy'd in afterwards. FEX copies the state
    // first and *then* does its own per-thread setup on top -- InitializeCompiler, and
    // clearing DeferredSignalRefCount. Copying over the register file after the fact
    // undoes exactly that work and leaves the child holding its parent's signal
    // bookkeeping, which is how a second running thread ends up dereferencing null.
    FEXCore::Core::CPUState child_state;
    std::memcpy(&child_state, &parent_state, sizeof(child_state));
    child_state.rip = resume;
    child_state.gregs[FEXCore::X86State::REG_RAX] = 0;
    if (new_rsp != 0) {
        child_state.gregs[FEXCore::X86State::REG_RSP] = new_rsp;
    }

    impl->guest_base = impl_->guest_base;
    {
        std::scoped_lock guard {g_thread_lifecycle};
        impl->thread = impl_->context->CreateThread(resume, child_state.gregs[FEXCore::X86State::REG_RSP],
                                                    &child_state);
    }
    if (impl->thread == nullptr) {
        error = "FEXCore could not create the child guest thread";
        return nullptr;
    }
    RegisterLiveThread(impl->context, impl->thread, impl->guest_base);

    // The call/return stack and the segment table are reached through the register file,
    // and the child must not share its parent's -- but the descriptors in it carry over,
    // the way they do across a real clone or fork.
    auto& state = impl->thread->CurrentFrame->State;
    impl->segments.Initialise(state, impl->guest_is_32bit, &parent.impl_->segments);
    impl->callret->Attach(impl->thread);

    FATHOM_INFO("forked guest thread: rip=%#llx rsp=%#llx",
                static_cast<unsigned long long>(state.rip),
                static_cast<unsigned long long>(state.gregs[FEXCore::X86State::REG_RSP]));
    return std::unique_ptr<GuestThread> {new GuestThread {std::move(impl)}};
}

} // namespace fathom

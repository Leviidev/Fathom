// fex_engine.h -- the FEXCore embedding.
//
// This is the only file that knows FEXCore exists. It owns the context, the guest
// threads, the syscall handler FEXCore calls into, and the mechanism that unwinds out of
// the JIT when a guest thread exits.
//
// The split between the two classes here is the process model. FEXCore's *context* is the
// JIT and its code cache, and there is one of those. A *guest thread* is a register file,
// a stack and an unwind point, and there is one per thread of guest execution -- which,
// in Fathom, is also one per guest process, because processes are guest threads that do
// not share a file descriptor table.
#pragma once

#include "guest_memory.h"
#include "linux_syscalls.h"

#include <cstdint>
#include <memory>
#include <string>

namespace fathom {

struct EngineOptions {
    uint32_t max_inst_per_block {};  ///< 0 keeps FEXCore's own default.
    bool multiblock {true};
    bool tso_enabled {true};
    bool reduced_precision_x87 {false};
    bool disassemble {false};
    /// Reports no AVX through CPUID. glibc picks its string routines by IFUNC from what
    /// CPUID advertises, so this is the switch that decides whether it runs the AVX2
    /// strcmp or the SSE2 one -- and therefore whether a JIT bug in the wide paths is
    /// reachable at all.
    bool disable_avx {false};

    /// True when the guest is an i386 binary. Its pointers are 32 bits, so it cannot be
    /// mapped 1:1 -- `guest_memory_base` is where its address space really lives, and
    /// FEXCore adds it to every address the guest computes.
    bool guest_is_32bit {false};
    uint64_t guest_memory_base {0};
};

enum class RunOutcome {
    Exited,   ///< The guest called exit/exit_group.
    Halted,   ///< The guest executed HLT, or ran off the end of its code.
    Stopped,  ///< fathom_session_request_stop unwound it.
    Execed,   ///< The guest called execve; the caller runs the new image on a new thread.
    Faulted,
};

struct RunResult {
    RunOutcome outcome {RunOutcome::Faulted};
    int status {};
    uint64_t rip {};
    uint64_t rsp {};
    std::string message;
};

class FexEngine;

/// One thread of guest execution, with its own registers, call/return stack and unwind
/// point. Its syscalls are answered by the LinuxSyscalls it was created with, which is
/// what gives a forked child its own file descriptor table.
class GuestThread final : public GuestThreadControl {
public:
    ~GuestThread() override;

    GuestThread(const GuestThread&) = delete;
    GuestThread& operator=(const GuestThread&) = delete;

    /// Runs until this thread stops. Blocking, and valid only on the host thread that
    /// owns it -- FEXCore binds a guest thread to the host thread executing it.
    RunResult Run();

    uint64_t Rip() const;
    uint64_t Rsp() const;
    uint64_t Rax() const;

    /// Points this thread at a freshly loaded program image, which is what execve does:
    /// same thread, same pid, entirely different program.
    void ResetTo(uint64_t rip, uint64_t rsp);

    /// Unwinds out of the JIT so the process can be restarted on a freshly loaded image.
    /// execve cannot simply rewrite this thread's registers: the syscall that asked for it
    /// is still several JIT frames deep, and the only way out of there is the same unwind
    /// that exit uses.
    [[noreturn]] void ExecGuest() override;

    // GuestThreadControl
    void SetFsBase(uint64_t base) override;
    uint64_t GetFsBase() const override;
    void SetTlsDescriptor(int entry, uint32_t base, uint32_t limit) override;
    [[noreturn]] void ExitGuest(int status) override;

private:
    friend class FexEngine;
    class Impl;
    explicit GuestThread(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

class FexEngine {
public:
    static std::unique_ptr<FexEngine> Create(GuestAddressSpace& space, const EngineOptions& options,
                                             std::string& error);
    ~FexEngine();

    FexEngine(const FexEngine&) = delete;
    FexEngine& operator=(const FexEngine&) = delete;

    /// A program's first thread, entering at its entry point with a defined register file.
    std::unique_ptr<GuestThread> StartThread(uint64_t rip, uint64_t rsp, LinuxSyscalls& syscalls,
                                             std::string& error);

    /// A thread whose registers are a copy of `parent`'s, except that RAX is zero: that
    /// difference is the whole of what fork returns to a child.
    std::unique_ptr<GuestThread> ForkThread(const GuestThread& parent, LinuxSyscalls& syscalls,
                                            std::string& error);

    static const char* FexRevision();

private:
    class Impl;
    explicit FexEngine(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

} // namespace fathom

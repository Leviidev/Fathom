// fex_engine.h -- the FEXCore embedding.
//
// This is the only file that knows FEXCore exists. It owns the context, the guest
// thread, the syscall handler FEXCore calls into, and the mechanism that unwinds out of
// the JIT when the guest exits.
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
};

enum class RunOutcome {
    Exited,   ///< The guest called exit/exit_group.
    Halted,   ///< The guest executed HLT, or ran off the end of its code.
    Stopped,  ///< fathom_session_request_stop unwound it.
    Faulted,
};

struct RunResult {
    RunOutcome outcome {RunOutcome::Faulted};
    int status {};
    uint64_t rip {};
    uint64_t rsp {};
    std::string message;
};

class FexEngine : public GuestThreadControl {
public:
    static std::unique_ptr<FexEngine> Create(GuestAddressSpace& space, LinuxSyscalls& syscalls,
                                             const EngineOptions& options, std::string& error);
    ~FexEngine() override;

    FexEngine(const FexEngine&) = delete;
    FexEngine& operator=(const FexEngine&) = delete;

    /// Creates the guest thread at the program's entry point.
    bool Prepare(uint64_t rip, uint64_t rsp, std::string& error);

    /// Runs until the guest stops. Blocking, and only valid on the thread that called
    /// Prepare -- FEXCore binds a guest thread to the host thread executing it.
    RunResult Run();

    uint64_t Rip() const;
    uint64_t Rsp() const;

    // GuestThreadControl
    void SetFsBase(uint64_t base) override;
    uint64_t GetFsBase() const override;
    [[noreturn]] void ExitGuest(int status) override;

    static const char* FexRevision();

private:
    class Impl;
    explicit FexEngine(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

} // namespace fathom

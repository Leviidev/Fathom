// crash_handler.h -- breadcrumbs the crash handler reads after everything has gone wrong.
#pragma once

#include <csignal>
#include <cstdint>

namespace fathom {

/// Offered every fatal signal before the crash record is written. Returning true means
/// the fault was fixed up in `context` and execution should resume there.
using FaultRecovery = bool (*)(int signal, siginfo_t* info, void* context);

/// Installs the recovery hook. The engine uses this for guest alignment faults, which
/// are an expected part of running x86 code on ARM64 rather than a crash.
void SetFaultRecovery(FaultRecovery recovery);

/// Records the guest syscall about to be serviced. Cheap enough for the hot path
/// (three relaxed atomic stores) and it is what turns "the log stops here" into
/// "the log stops in openat".
void NoteSyscall(uint64_t number, uint64_t first_argument, uint64_t count);

/// Records where the guest was, as of the last syscall boundary.
void NoteGuestRip(uint64_t rip);

} // namespace fathom

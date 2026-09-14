// crash_handler.h -- breadcrumbs the crash handler reads after everything has gone wrong.
#pragma once

#include <cstdint>

namespace fathom {

/// Records the guest syscall about to be serviced. Cheap enough for the hot path
/// (three relaxed atomic stores) and it is what turns "the log stops here" into
/// "the log stops in openat".
void NoteSyscall(uint64_t number, uint64_t first_argument, uint64_t count);

/// Records where the guest was, as of the last syscall boundary.
void NoteGuestRip(uint64_t rip);

} // namespace fathom

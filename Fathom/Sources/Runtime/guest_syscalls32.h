// guest_syscalls32.h -- i386's syscall numbering, mapped onto x86-64's.
//
// The two architectures agree on almost nothing here. i386's write is 4, where x86-64's 4
// is stat; i386's exit is 1, where x86-64's 1 is write. A 32-bit guest's syscalls are
// therefore not merely a subset -- read as x86-64 they are a different program's
// behaviour entirely, and the first thing a 32-bit binary does gets silently misread.
//
// Translating the number keeps one implementation of each syscall rather than two. Where
// the *semantics* differ as well -- mmap2 counts its offset in pages, the 64-bit stat
// variants use a different structure -- that is handled at the call site, not here.
#pragma once

#include <cstdint>

namespace fathom {

/// The x86-64 number for an i386 syscall, -1 if there is no equivalent, or
/// kI386NeedsUnpacking for one whose arguments do not simply carry across.
int64_t X86_64SyscallForI386(uint64_t i386_number);

constexpr int64_t kI386NeedsUnpacking = -2;

/// i386 numbers whose arguments or results need reshaping as well as renumbering.
constexpr uint64_t kI386Mmap = 90;      ///< Takes a pointer to a packed argument struct.
constexpr uint64_t kI386Mmap2 = 192;    ///< Offset counted in 4096-byte pages, not bytes.
constexpr uint64_t kI386Stat64 = 195;
constexpr uint64_t kI386Lstat64 = 196;
constexpr uint64_t kI386Fstat64 = 197;
constexpr uint64_t kI386Fstatat64 = 300;
constexpr uint64_t kI386SetThreadArea = 243;
constexpr uint64_t kI386Llseek = 140;
constexpr uint64_t kI386Socketcall = 102; ///< One entry point for all sixteen socket calls.
/// True for the i386 syscalls that predate 64-bit time_t and still take a 32-bit one.
/// The _time64 variants map to the same x86-64 numbers but carry wider structures.
bool IsI386NarrowTime(uint64_t i386_number);

constexpr uint64_t kI386Ipc = 117;        ///< The same idea for System V semaphores and shared memory.

} // namespace fathom

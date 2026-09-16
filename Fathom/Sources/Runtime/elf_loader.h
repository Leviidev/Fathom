// elf_loader.h -- loads an x86-64 Linux ELF into the guest address space.
//
// Scope is deliberately the two shapes that can actually work on iOS today:
//
//   * ET_DYN with no PT_INTERP (a static-PIE binary) -- placed wherever the arena has
//     room. This is the shape Fathom runs best.
//   * ET_DYN with PT_INTERP (an ordinary dynamically linked binary) -- the interpreter
//     is loaded alongside it and given control, which needs a guest root filesystem
//     containing the loader and its libraries.
//
// ET_EXEC is parsed and attempted honestly, but a non-PIE Linux binary wants to live at
// its link address (classically 0x400000) and an iOS arm64 process reserves the first
// 4GB of its address space as __PAGEZERO. The attempt is made, and when the kernel
// refuses, the failure says exactly that instead of something vague.
#pragma once

#include "guest_memory.h"

#include <cstdint>
#include <string>
#include <vector>

namespace fathom {

enum class ProgramKind {
    Unknown,
    Static,     ///< ET_EXEC, no interpreter.
    StaticPie,  ///< ET_DYN, no interpreter.
    Dynamic,    ///< Has PT_INTERP.
};

struct ElfInspection {
    bool ok {};
    ProgramKind kind {ProgramKind::Unknown};
    bool loadable {};
    uint64_t entry {};
    uint64_t image_size {};
    uint64_t min_vaddr {};
    uint16_t phentsize {};
    uint16_t phnum {};
    uint64_t phoff {};
    /// True for an i386 binary. Such a guest's pointers are 32 bits, so its memory has to
    /// be placed where a 32-bit value can reach it and every address relocated to suit.
    bool is_32bit {};
    std::string machine;
    std::string interpreter;
    std::string error;
};

/// Reads headers only. Maps nothing, allocates no guest memory.
ElfInspection InspectElf(const std::string& path);

struct LoadedImage {
    uint64_t load_base {};   ///< Added to every p_vaddr. 0 for ET_EXEC.
    uint64_t entry {};       ///< Relocated entry point.
    uint64_t phdr_address {};///< Where the program headers ended up in guest memory.
    uint16_t phentsize {};
    uint16_t phnum {};
    uint64_t image_begin {};
    uint64_t image_end {};
};

/// Maps every PT_LOAD of `path` into `space`.
/// `preferred_base` is only a hint, and only consulted for ET_DYN images.
bool LoadElf(const std::string& path, GuestAddressSpace& space, uint64_t preferred_base,
             LoadedImage* out_image, std::string& error);

struct StackImage {
    uint64_t stack_base {};  ///< Lowest address of the stack allocation.
    uint64_t stack_size {};
    uint64_t rsp {};         ///< Initial RSP: points at argc, 16-byte aligned.
};

/// Builds the System V process-entry stack: argc, argv, envp, then the auxiliary
/// vector, then the strings they point at.
///
/// The auxv is not optional decoration -- a C runtime reads AT_RANDOM to seed its stack
/// guard and AT_PHDR/AT_PHNUM to find its own program headers, and crashes very early
/// and very confusingly without them.
bool BuildInitialStack(GuestAddressSpace& space, const LoadedImage& image,
                       const std::vector<std::string>& argv, const std::vector<std::string>& envp,
                       const std::string& exec_path, uint64_t interpreter_base, uint64_t stack_size,
                       StackImage* out_stack, std::string& error);

} // namespace fathom

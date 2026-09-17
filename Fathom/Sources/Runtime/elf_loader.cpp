#include "elf_loader.h"

#include "fathom_log.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fathom {
namespace {

// Darwin has no <elf.h>, and the guest's ELF is a fixed on-disk format anyway, so the
// pieces that matter are spelled out here rather than depending on a host header that
// describes the *host's* object format.
struct Elf64Ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/// A 32-bit ELF, which is a different shape rather than a smaller one: the fields are
/// narrower *and* the program header puts p_flags in a different place. Both are read
/// here and widened into the 64-bit structures above, so everything downstream -- segment
/// mapping, the interpreter, the initial stack -- works on one representation.
struct Elf32Ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};
static_assert(sizeof(Elf32Ehdr) == 52, "Elf32_Ehdr is 52 bytes");

struct Elf32Phdr {
    uint32_t p_type;
    uint32_t p_offset;   // Note the order: p_flags is last here, second in the 64-bit form.
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};
static_assert(sizeof(Elf32Phdr) == 32, "Elf32_Phdr is 32 bytes");

constexpr uint16_t kElfTypeExec = 2;
constexpr uint16_t kElfTypeDyn = 3;
constexpr uint16_t kElfMachineX8664 = 62;
constexpr uint16_t kElfMachineI386 = 3;
constexpr uint8_t kElfClass32 = 1;
constexpr uint8_t kElfClass64 = 2;

constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtInterp = 3;

constexpr uint32_t kPfExec = 1;
constexpr uint32_t kPfWrite = 2;
constexpr uint32_t kPfRead = 4;

// The guest's page size, which is x86-64's 4096 and has nothing to do with the host's.
constexpr uint64_t kGuestPageSize = 4096;

// Auxiliary vector tags. Only the ones a C runtime actually reads on x86-64 Linux.
constexpr uint64_t kAtNull = 0;
constexpr uint64_t kAtPhdr = 3;
constexpr uint64_t kAtPhent = 4;
constexpr uint64_t kAtPhnum = 5;
constexpr uint64_t kAtPagesz = 6;
constexpr uint64_t kAtBase = 7;
constexpr uint64_t kAtFlags = 8;
constexpr uint64_t kAtEntry = 9;
constexpr uint64_t kAtUid = 11;
constexpr uint64_t kAtEuid = 12;
constexpr uint64_t kAtGid = 13;
constexpr uint64_t kAtEgid = 14;
constexpr uint64_t kAtPlatform = 15;
constexpr uint64_t kAtHwcap = 16;
constexpr uint64_t kAtClktck = 17;
constexpr uint64_t kAtSecure = 23;
constexpr uint64_t kAtRandom = 25;
constexpr uint64_t kAtHwcap2 = 26;
constexpr uint64_t kAtExecfn = 31;

class FileHandle {
public:
    explicit FileHandle(const std::string& path)
        : fd_ {open(path.c_str(), O_RDONLY | O_CLOEXEC)} {}
    ~FileHandle() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    bool valid() const { return fd_ >= 0; }
    int get() const { return fd_; }

private:
    int fd_ {-1};
};

bool ReadExactly(int fd, void* buffer, size_t size, off_t offset) {
    auto* cursor = static_cast<uint8_t*>(buffer);
    size_t remaining = size;
    while (remaining > 0) {
        const ssize_t read_bytes = pread(fd, cursor, remaining, offset);
        if (read_bytes <= 0) {
            return false;
        }
        cursor += read_bytes;
        offset += read_bytes;
        remaining -= static_cast<size_t>(read_bytes);
    }
    return true;
}

bool ReadHeaders(const std::string& path, Elf64Ehdr* header, std::vector<Elf64Phdr>* headers,
                 std::string& error) {
    FileHandle file {path};
    if (!file.valid()) {
        error = std::string {"cannot open "} + path + ": " + std::strerror(errno);
        return false;
    }

    if (!ReadExactly(file.get(), header, sizeof(*header), 0)) {
        error = "file is too small to be an ELF executable";
        return false;
    }

    if (std::memcmp(header->e_ident, "\x7f" "ELF", 4) != 0) {
        error = "not an ELF file (bad magic)";
        return false;
    }
    const uint8_t elf_class = header->e_ident[4];
    if (elf_class != kElfClass64 && elf_class != kElfClass32) {
        error = "not a 32-bit or 64-bit ELF";
        return false;
    }
    if (header->e_ident[5] != 1) {
        error = "not a little-endian ELF";
        return false;
    }

    // A 32-bit header was just read into a 64-bit structure, so almost nothing past
    // e_version is where it appears to be. Re-read it properly and widen.
    if (elf_class == kElfClass32) {
        Elf32Ehdr narrow {};
        if (!ReadExactly(file.get(), &narrow, sizeof(narrow), 0)) {
            error = "file is too small to be a 32-bit ELF executable";
            return false;
        }
        if (narrow.e_machine != kElfMachineI386) {
            error = "wrong architecture: a 32-bit ELF that is not i386";
            return false;
        }
        std::memcpy(header->e_ident, narrow.e_ident, sizeof(header->e_ident));
        header->e_type = narrow.e_type;
        header->e_machine = narrow.e_machine;
        header->e_version = narrow.e_version;
        header->e_entry = narrow.e_entry;
        header->e_phoff = narrow.e_phoff;
        header->e_shoff = narrow.e_shoff;
        header->e_flags = narrow.e_flags;
        header->e_ehsize = narrow.e_ehsize;
        header->e_phentsize = narrow.e_phentsize;
        header->e_phnum = narrow.e_phnum;
    } else if (header->e_machine != kElfMachineX8664) {
        char message[128];
        std::snprintf(message, sizeof(message),
                      "wrong architecture: this binary targets ELF machine %u, and Fathom runs x86-64 (62)",
                      header->e_machine);
        error = message;
        return false;
    }
    if (header->e_type != kElfTypeExec && header->e_type != kElfTypeDyn) {
        error = "not an executable or shared object";
        return false;
    }
    const size_t expected_phentsize = elf_class == kElfClass32 ? sizeof(Elf32Phdr) : sizeof(Elf64Phdr);
    if (header->e_phentsize != expected_phentsize || header->e_phnum == 0) {
        error = "malformed program header table";
        return false;
    }

    if (elf_class == kElfClass32) {
        std::vector<Elf32Phdr> narrow(header->e_phnum);
        if (!ReadExactly(file.get(), narrow.data(), sizeof(Elf32Phdr) * header->e_phnum,
                         static_cast<off_t>(header->e_phoff))) {
            error = "truncated program header table";
            return false;
        }
        headers->clear();
        headers->reserve(narrow.size());
        for (const auto& entry : narrow) {
            headers->push_back(Elf64Phdr {entry.p_type, entry.p_flags, entry.p_offset, entry.p_vaddr,
                                          entry.p_paddr, entry.p_filesz, entry.p_memsz, entry.p_align});
        }
        return true;
    }

    headers->resize(header->e_phnum);
    if (!ReadExactly(file.get(), headers->data(), sizeof(Elf64Phdr) * header->e_phnum,
                     static_cast<off_t>(header->e_phoff))) {
        error = "truncated program header table";
        return false;
    }
    return true;
}

int ToGuestProtection(uint32_t p_flags) {
    int protection = 0;
    if ((p_flags & kPfRead) != 0) {
        protection |= kGuestProtRead;
    }
    if ((p_flags & kPfWrite) != 0) {
        protection |= kGuestProtWrite;
    }
    if ((p_flags & kPfExec) != 0) {
        protection |= kGuestProtExec;
    }
    return protection;
}

std::string ReadInterpreter(const std::string& path, const Elf64Phdr& segment) {
    if (segment.p_filesz == 0 || segment.p_filesz > 4096) {
        return {};
    }
    FileHandle file {path};
    if (!file.valid()) {
        return {};
    }
    std::string interpreter(segment.p_filesz, '\0');
    if (!ReadExactly(file.get(), interpreter.data(), interpreter.size(),
                     static_cast<off_t>(segment.p_offset))) {
        return {};
    }
    const auto terminator = interpreter.find('\0');
    if (terminator != std::string::npos) {
        interpreter.resize(terminator);
    }
    return interpreter;
}

} // namespace

ElfInspection InspectElf(const std::string& path) {
    ElfInspection result;

    Elf64Ehdr header {};
    std::vector<Elf64Phdr> segments;
    if (!ReadHeaders(path, &header, &segments, result.error)) {
        return result;
    }

    uint64_t lowest = UINT64_MAX;
    uint64_t highest = 0;
    for (const auto& segment : segments) {
        if (segment.p_type == kPtInterp) {
            result.interpreter = ReadInterpreter(path, segment);
        }
        if (segment.p_type != kPtLoad || segment.p_memsz == 0) {
            continue;
        }
        lowest = std::min(lowest, segment.p_vaddr);
        highest = std::max(highest, segment.p_vaddr + segment.p_memsz);
    }
    if (lowest == UINT64_MAX) {
        result.error = "no loadable segments";
        return result;
    }

    result.ok = true;
    result.is_32bit = header.e_ident[4] == kElfClass32;
    result.machine = result.is_32bit ? "i386" : "x86-64";
    result.entry = header.e_entry;
    result.min_vaddr = lowest;
    result.image_size = highest - (lowest & ~(kGuestPageSize - 1));
    result.phoff = header.e_phoff;
    result.phentsize = header.e_phentsize;
    result.phnum = header.e_phnum;

    if (!result.interpreter.empty()) {
        result.kind = ProgramKind::Dynamic;
    } else if (header.e_type == kElfTypeDyn) {
        result.kind = ProgramKind::StaticPie;
    } else {
        result.kind = ProgramKind::Static;
    }

    switch (result.kind) {
    case ProgramKind::StaticPie:
        result.loadable = true;
        break;
    case ProgramKind::Dynamic:
        result.loadable = true;
        result.error = "dynamically linked: the guest root filesystem must provide " +
                       result.interpreter + " and the libraries this program links against";
        break;
    case ProgramKind::Static:
        // Reported as loadable so the attempt is still made -- fathom_probe_device
        // measures what this device really allows rather than assuming.
        result.loadable = true;
        result.error = "non-PIE: wants a fixed load address, which iOS usually reserves";
        break;
    default:
        break;
    }
    return result;
}

bool LoadElf(const std::string& path, GuestAddressSpace& space, uint64_t preferred_base,
             uint64_t guest_base, LoadedImage* out_image, std::string& error) {
    Elf64Ehdr header {};
    std::vector<Elf64Phdr> segments;
    if (!ReadHeaders(path, &header, &segments, error)) {
        return false;
    }

    uint64_t lowest = UINT64_MAX;
    uint64_t highest = 0;
    for (const auto& segment : segments) {
        if (segment.p_type != kPtLoad || segment.p_memsz == 0) {
            continue;
        }
        lowest = std::min(lowest, segment.p_vaddr);
        highest = std::max(highest, segment.p_vaddr + segment.p_memsz);
    }
    if (lowest == UINT64_MAX) {
        error = "no loadable segments";
        return false;
    }

    const uint64_t page_size = space.HostPageSize();
    const uint64_t image_begin = lowest & ~(page_size - 1);
    const uint64_t image_end = (highest + page_size - 1) & ~(page_size - 1);
    const uint64_t span = image_end - image_begin;

    uint64_t load_base = 0;
    if (header.e_type == kElfTypeDyn) {
        // PIE: the whole image is relocatable, so let the arena choose. The segments are
        // committed as one span rather than individually, because consecutive ELF
        // segments are 4KB-aligned and would otherwise collide inside a 16KB host page.
        const uint64_t placed = space.Allocate(span, preferred_base, kGuestProtRead | kGuestProtWrite);
        if (placed == 0) {
            error = "guest address space could not fit the program image";
            return false;
        }
        load_base = placed - image_begin;
    } else if (guest_base != 0) {
        // ET_EXEC inside a relocated guest, which is the ordinary case for i386: the file
        // insists on 0x08048000 or similar, and that address is perfectly available --
        // inside the arena, where the guest's address space starts at zero. No host
        // mapping at a fixed low address is needed, or possible.
        if (!space.CommitFixed(image_begin + guest_base, span, kGuestProtRead | kGuestProtWrite)) {
            error = "guest address space could not hold the program at its fixed address";
            return false;
        }
        load_base = guest_base;
    } else {
        // ET_EXEC: the addresses in the file are the addresses it must run at.
        void* fixed = mmap(reinterpret_cast<void*>(image_begin), span, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (fixed == MAP_FAILED || reinterpret_cast<uint64_t>(fixed) != image_begin) {
            if (fixed != MAP_FAILED) {
                munmap(fixed, span);
            }
            char message[320];
            std::snprintf(message, sizeof(message),
                          "this binary is not position-independent and must load at %#llx, which this "
                          "device will not map (iOS reserves the low 4GB of every process). Rebuild it "
                          "with -static-pie, or use a position-independent build.",
                          static_cast<unsigned long long>(image_begin));
            error = message;
            return false;
        }
        space.AdoptExternalMapping(image_begin, span, kGuestProtRead | kGuestProtWrite);
    }

    FileHandle file {path};
    if (!file.valid()) {
        error = std::string {"cannot open "} + path + ": " + std::strerror(errno);
        return false;
    }

    for (const auto& segment : segments) {
        if (segment.p_type != kPtLoad || segment.p_memsz == 0) {
            continue;
        }
        auto* destination = reinterpret_cast<uint8_t*>(load_base + segment.p_vaddr);
        std::memset(destination, 0, segment.p_memsz);
        if (segment.p_filesz > 0 &&
            !ReadExactly(file.get(), destination, segment.p_filesz, static_cast<off_t>(segment.p_offset))) {
            error = "truncated program image: a PT_LOAD segment runs past the end of the file";
            return false;
        }
        FATHOM_DEBUG("segment %#llx..%#llx flags=%c%c%c",
                     static_cast<unsigned long long>(load_base + segment.p_vaddr),
                     static_cast<unsigned long long>(load_base + segment.p_vaddr + segment.p_memsz),
                     (segment.p_flags & kPfRead) != 0 ? 'r' : '-',
                     (segment.p_flags & kPfWrite) != 0 ? 'w' : '-',
                     (segment.p_flags & kPfExec) != 0 ? 'x' : '-');
    }

    // Guest protections are applied only after every segment's bytes are in place: a
    // read-only segment still has to be written once, here, to get its contents.
    for (const auto& segment : segments) {
        if (segment.p_type != kPtLoad || segment.p_memsz == 0) {
            continue;
        }
        space.Protect(load_base + segment.p_vaddr, segment.p_memsz, ToGuestProtection(segment.p_flags));
    }

    // What the program is about to be told about itself, checked against what is actually
    // there. A loader reads its own program headers through AT_PHDR and its own variables
    // out of zero-initialised data; if either is not what it should be, everything it
    // computes afterwards is nonsense and the failure surfaces somewhere unrecognisable.
    if (getenv("FATHOM_VERIFY_IMAGES") != nullptr) {
        for (const auto& segment : segments) {
            if (segment.p_type != kPtLoad || segment.p_memsz <= segment.p_filesz) {
                continue;
            }
            const auto* zero_from =
                reinterpret_cast<const uint8_t*>(load_base + segment.p_vaddr + segment.p_filesz);
            const uint64_t zero_bytes = segment.p_memsz - segment.p_filesz;
            uint64_t nonzero = 0;
            for (uint64_t index = 0; index < zero_bytes; ++index) {
                nonzero += zero_from[index] != 0 ? 1 : 0;
            }
            if (nonzero != 0) {
                FATHOM_ERROR("%s: %llu of %llu bytes that should be zero are not, at %#llx",
                             path.c_str(), static_cast<unsigned long long>(nonzero),
                             static_cast<unsigned long long>(zero_bytes),
                             static_cast<unsigned long long>(load_base + segment.p_vaddr +
                                                             segment.p_filesz));
            }
        }
    }

    out_image->load_base = load_base;
    out_image->entry = load_base + header.e_entry;
    out_image->phentsize = header.e_phentsize;
    out_image->phnum = header.e_phnum;
    out_image->image_begin = load_base + image_begin;
    out_image->image_end = load_base + image_end;

    // AT_PHDR must point at the program headers *as mapped*. They are almost always
    // covered by the first PT_LOAD, so their file offset is also their image offset.
    out_image->phdr_address = 0;
    for (const auto& segment : segments) {
        if (segment.p_type != kPtLoad) {
            continue;
        }
        if (header.e_phoff >= segment.p_offset &&
            header.e_phoff + static_cast<uint64_t>(header.e_phentsize) * header.e_phnum <=
                segment.p_offset + segment.p_filesz) {
            out_image->phdr_address = load_base + segment.p_vaddr + (header.e_phoff - segment.p_offset);
            break;
        }
    }

    FATHOM_INFO("loaded %s: base=%#llx entry=%#llx phdr=%#llx span=%llu KB", path.c_str(),
                static_cast<unsigned long long>(load_base),
                static_cast<unsigned long long>(out_image->entry),
                static_cast<unsigned long long>(out_image->phdr_address),
                static_cast<unsigned long long>(span / 1024));
    return true;
}

bool BuildInitialStack(GuestAddressSpace& space, uint64_t guest_base, const LoadedImage& image,
                       const std::vector<std::string>& argv, const std::vector<std::string>& envp,
                       const std::string& exec_path, uint64_t interpreter_base, uint64_t stack_size,
                       StackImage* out_stack, std::string& error) {
    // A guard below it, which Linux always has and this did not. The arena hands out
    // whatever is next, so a stack could sit immediately above a library's data with
    // nothing in between: a program that runs off the bottom of its stack then writes
    // into that library instead of faulting, and what follows is the library reading its
    // own variables as nonsense, a long way from the overflow. Reserved as part of the
    // same allocation and then released, so nothing can be placed there either.
    const uint64_t guard = space.HostPageSize();
    const uint64_t reserved = space.Allocate(stack_size + guard, 0,
                                             kGuestProtRead | kGuestProtWrite);
    if (reserved == 0) {
        error = "could not allocate the guest stack";
        return false;
    }
    const uint64_t base = reserved + guard;
    // Taken out of the guest's reach in both accountings: the address space is told it
    // permits nothing, so a syscall handed a pointer into it refuses, and the host mapping
    // is made unreadable, so guest code that walks into it faults there instead of
    // quietly writing over whatever the arena placed below.
    space.Protect(reserved, guard, 0);
    mprotect(reinterpret_cast<void*>(reserved), guard, PROT_NONE);

    const uint64_t top = base + stack_size;

    // Strings live at the very top, below them the pointer arrays that reference them.
    uint64_t cursor = top;
    const auto push_bytes = [&cursor](const void* data, size_t size) -> uint64_t {
        cursor -= size;
        cursor &= ~static_cast<uint64_t>(15);
        std::memcpy(reinterpret_cast<void*>(cursor), data, size);
        return cursor;
    };
    const auto push_string = [&push_bytes](const std::string& value) -> uint64_t {
        return push_bytes(value.c_str(), value.size() + 1);
    };

    // 16 bytes of entropy for AT_RANDOM. A C runtime copies these into its stack
    // canary, so they have to be real memory the guest can read, not a null pointer.
    uint8_t random_bytes[16];
    arc4random_buf(random_bytes, sizeof(random_bytes));
    const uint64_t random_address = push_bytes(random_bytes, sizeof(random_bytes));

    // The guest's own name for the machine it thinks it is on.
    const uint64_t platform_address = push_string(guest_base != 0 ? "i686" : "x86_64");
    const uint64_t execfn_address = push_string(exec_path);

    std::vector<uint64_t> env_addresses;
    env_addresses.reserve(envp.size());
    for (auto entry = envp.rbegin(); entry != envp.rend(); ++entry) {
        env_addresses.push_back(push_string(*entry));
    }
    std::reverse(env_addresses.begin(), env_addresses.end());

    std::vector<uint64_t> arg_addresses;
    arg_addresses.reserve(argv.size());
    for (auto entry = argv.rbegin(); entry != argv.rend(); ++entry) {
        arg_addresses.push_back(push_string(*entry));
    }
    std::reverse(arg_addresses.begin(), arg_addresses.end());

    const std::vector<std::pair<uint64_t, uint64_t>> auxv {
        {kAtPhdr, image.phdr_address},
        {kAtPhent, image.phentsize},
        {kAtPhnum, image.phnum},
        // 4096, not the host's 16384: the guest's own notion of a page is baked into the
        // ELF's segment alignment and into every mmap length its libc rounds up.
        {kAtPagesz, kGuestPageSize},
        {kAtBase, interpreter_base},
        {kAtFlags, 0},
        {kAtEntry, image.entry},
        {kAtUid, 1000},
        {kAtEuid, 1000},
        {kAtGid, 1000},
        {kAtEgid, 1000},
        {kAtPlatform, platform_address},
        // Left at zero on purpose: a guest libc that wants x86 feature bits reads CPUID,
        // which FEXCore emulates properly, rather than trusting this.
        {kAtHwcap, 0},
        {kAtClktck, 100},
        {kAtSecure, 0},
        {kAtRandom, random_address},
        {kAtHwcap2, 0},
        {kAtExecfn, execfn_address},
        {kAtNull, 0},
    };

    // A 32-bit process's stack is built out of 4-byte words, not 8. Everything about the
    // layout is otherwise the same -- argc, then argv, then envp, then the auxiliary
    // vector -- but writing 64-bit words into it puts every entry at twice its offset and
    // the guest reads its own arguments as garbage.
    const bool narrow = guest_base != 0;
    const size_t word_size = narrow ? 4 : 8;

    const size_t word_count = 1                        // argc
                              + arg_addresses.size() + 1 // argv + NULL
                              + env_addresses.size() + 1 // envp + NULL
                              + auxv.size() * 2;

    uint64_t rsp = cursor - word_count * word_size;
    // The ABI is specific here: at the process entry point RSP is 16-byte aligned and
    // argc sits at [RSP]. That is different from the alignment rule at a *function* entry
    // (where RSP+8 is aligned because a return address was pushed), and conflating the two
    // leaves the guest running with a permanently misaligned stack.
    rsp &= ~static_cast<uint64_t>(15);
    if (rsp < base) {
        error = "guest stack is too small for the program's arguments and environment";
        return false;
    }

    // Every pointer stored here is one the guest will dereference, so it is written in
    // the guest's numbering rather than the host's.
    uint8_t* word = reinterpret_cast<uint8_t*>(rsp);
    const auto put = [&word, word_size](uint64_t value) {
        if (word_size == 4) {
            const auto narrowed = static_cast<uint32_t>(value);
            std::memcpy(word, &narrowed, 4);
        } else {
            std::memcpy(word, &value, 8);
        }
        word += word_size;
    };

    put(arg_addresses.size());
    for (const auto address : arg_addresses) {
        put(address - guest_base);
    }
    put(0);
    for (const auto address : env_addresses) {
        put(address - guest_base);
    }
    put(0);
    for (const auto& [key, value] : auxv) {
        put(key);
        // Only the three that point at something built on this stack need converting.
        // AT_PHDR, AT_BASE and AT_ENTRY came from the loaded image and are already in the
        // guest's numbering; converting them twice would subtract the base twice.
        const bool from_this_stack = key == kAtRandom || key == kAtPlatform || key == kAtExecfn;
        put(from_this_stack && value != 0 ? value - guest_base : value);
    }

    out_stack->stack_base = base;
    out_stack->stack_size = stack_size;
    out_stack->rsp = rsp - guest_base;
    if (getenv("FATHOM_LOG_ARGUMENTS") != nullptr) {
        for (const auto& argument : argv) {
            FATHOM_INFO("argv: %s", argument.c_str());
        }
        for (const auto& variable : envp) {
            FATHOM_INFO("envp: %s", variable.c_str());
        }
    }
    FATHOM_INFO("auxv: phdr=%#llx phent=%llu phnum=%llu base=%#llx entry=%#llx",
                static_cast<unsigned long long>(image.phdr_address),
                static_cast<unsigned long long>(image.phentsize),
                static_cast<unsigned long long>(image.phnum),
                static_cast<unsigned long long>(interpreter_base),
                static_cast<unsigned long long>(image.entry));
    FATHOM_INFO("guest stack: %#llx..%#llx, rsp=%#llx, %zu argv, %zu envp",
                static_cast<unsigned long long>(base), static_cast<unsigned long long>(top),
                static_cast<unsigned long long>(rsp), argv.size(), envp.size());
    return true;
}

} // namespace fathom

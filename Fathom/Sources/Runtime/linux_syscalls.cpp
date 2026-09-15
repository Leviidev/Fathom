#include "linux_syscalls.h"

#include "crash_handler.h"
#include "fathom_log.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

namespace fathom {
namespace {

// ---------------------------------------------------------------------------
// The guest's ABI constants. These are x86-64 Linux's values, which are not the
// host's -- O_CREAT alone is 0x40 on Linux and 0x200 on Darwin, so passing a guest
// flag word to a host call unchanged silently means something else entirely.
// ---------------------------------------------------------------------------

namespace guest {
constexpr int kOAccMode = 0x3;
constexpr int kOCreat = 0x40;
constexpr int kOExcl = 0x80;
constexpr int kOTrunc = 0x200;
constexpr int kOAppend = 0x400;
constexpr int kONonBlock = 0x800;
constexpr int kODirectory = 0x10000;
constexpr int kOCloExec = 0x80000;

constexpr int kAtFdCwd = -100;
constexpr int kAtSymlinkNoFollow = 0x100;

constexpr int kProtRead = 1;
constexpr int kProtWrite = 2;
constexpr int kProtExec = 4;

constexpr int kMapShared = 0x01;
constexpr int kMapFixed = 0x10;
constexpr int kMapAnonymous = 0x20;

constexpr int kClockRealtime = 0;
constexpr int kClockMonotonic = 1;
constexpr int kClockProcessCputime = 2;
constexpr int kClockThreadCputime = 3;
constexpr int kClockMonotonicRaw = 4;
constexpr int kClockRealtimeCoarse = 5;
constexpr int kClockMonotonicCoarse = 6;
constexpr int kClockBoottime = 7;

constexpr uint64_t kArchSetGs = 0x1001;
constexpr uint64_t kArchSetFs = 0x1002;
constexpr uint64_t kArchGetFs = 0x1003;
constexpr uint64_t kArchGetGs = 0x1004;

constexpr uint64_t kTcgets = 0x5401;
constexpr uint64_t kTcsets = 0x5402;
constexpr uint64_t kTcsetsw = 0x5403;
constexpr uint64_t kTcsetsf = 0x5404;

// Linux termios lflag bits, read back to notice the guest leaving canonical mode.
constexpr uint32_t kIcanon = 0x0002;
constexpr uint64_t kTiocgwinsz = 0x5413;

// Linux framebuffer device. The oldest and simplest way to put pixels on a Linux screen:
// ask for the geometry, mmap the memory, write pixels.
constexpr uint64_t kFbioGetVarScreenInfo = 0x4600;
constexpr uint64_t kFbioPutVarScreenInfo = 0x4601;
constexpr uint64_t kFbioGetFixScreenInfo = 0x4602;
constexpr uint64_t kFbioPanDisplay = 0x4606;
constexpr uint64_t kFbioBlank = 0x4611;

constexpr uint64_t kPageSize = 4096;
} // namespace guest

// The display Fathom offers a guest. Not a real panel resolution: a size that is cheap to
// copy every frame and still looks sharp once scaled to a phone screen.
constexpr uint32_t kDisplayWidth = 480;
constexpr uint32_t kDisplayHeight = 800;
constexpr uint32_t kDisplayBpp = 32;

/// x86-64 Linux's fb_var_screeninfo, written field by field at the offsets the guest
/// reads. 160 bytes; the trailing timing fields are all zero, which a framebuffer
/// consumer ignores.
void WriteVarScreenInfo(uint8_t* out, uint32_t width, uint32_t height, uint32_t bpp) {
    std::memset(out, 0, 160);
    auto put = [out](size_t offset, uint32_t value) {
        std::memcpy(out + offset, &value, sizeof(value));
    };
    put(0, width);       // xres
    put(4, height);      // yres
    put(8, width);       // xres_virtual
    put(12, height);     // yres_virtual
    put(24, bpp);        // bits_per_pixel

    // Channel layout, as three fb_bitfield {offset, length, msb_right} triples followed
    // by the alpha one. This says BGRA in memory order on a little-endian machine, which
    // is what both Core Graphics and every framebuffer program treat as the normal case.
    auto channel = [&put](size_t base, uint32_t offset, uint32_t length) {
        put(base, offset);
        put(base + 4, length);
        put(base + 8, 0);
    };
    channel(32, 16, 8);  // red
    channel(44, 8, 8);   // green
    channel(56, 0, 8);   // blue
    channel(68, 24, 8);  // transp
}

/// x86-64 Linux's fb_fix_screeninfo, 80 bytes.
void WriteFixScreenInfo(uint8_t* out, uint64_t address, uint32_t stride, uint32_t size) {
    std::memset(out, 0, 80);
    std::strncpy(reinterpret_cast<char*>(out), "fathom", 15);
    std::memcpy(out + 16, &address, sizeof(address));   // smem_start
    std::memcpy(out + 24, &size, sizeof(size));         // smem_len
    const uint32_t type = 0;                            // FB_TYPE_PACKED_PIXELS
    std::memcpy(out + 28, &type, sizeof(type));
    const uint32_t visual = 2;                          // FB_VISUAL_TRUECOLOR
    std::memcpy(out + 36, &visual, sizeof(visual));
    std::memcpy(out + 48, &stride, sizeof(stride));     // line_length
}

// x86-64 Linux syscall numbers, in the order they are handled below.
enum : uint64_t {
    kSysRead = 0,
    kSysWrite = 1,
    kSysOpen = 2,
    kSysClose = 3,
    kSysStat = 4,
    kSysFstat = 5,
    kSysLstat = 6,
    kSysPoll = 7,
    kSysLseek = 8,
    kSysMmap = 9,
    kSysMprotect = 10,
    kSysMunmap = 11,
    kSysBrk = 12,
    kSysRtSigaction = 13,
    kSysRtSigprocmask = 14,
    kSysRtSigreturn = 15,
    kSysIoctl = 16,
    kSysPread64 = 17,
    kSysPwrite64 = 18,
    kSysReadv = 19,
    kSysWritev = 20,
    kSysAccess = 21,
    kSysSchedYield = 24,
    kSysMremap = 25,
    kSysMsync = 26,
    kSysMadvise = 28,
    kSysDup = 32,
    kSysDup2 = 33,
    kSysNanosleep = 35,
    kSysGetpid = 39,
    kSysClone = 56,
    kSysFork = 57,
    kSysExecve = 59,
    kSysExit = 60,
    kSysWait4 = 61,
    kSysKill = 62,
    kSysUname = 63,
    kSysFcntl = 72,
    kSysFsync = 74,
    kSysFtruncate = 77,
    kSysGetdents = 78,
    kSysGetcwd = 79,
    kSysChdir = 80,
    kSysRename = 82,
    kSysMkdir = 83,
    kSysRmdir = 84,
    kSysCreat = 85,
    kSysUnlink = 87,
    kSysReadlink = 89,
    kSysChmod = 90,
    kSysUmask = 95,
    kSysGettimeofday = 96,
    kSysGetrlimit = 97,
    kSysSysinfo = 99,
    kSysGetuid = 102,
    kSysGetgid = 104,
    kSysSetuid = 105,
    kSysGeteuid = 107,
    kSysGetegid = 108,
    kSysGetppid = 110,
    kSysGetpgrp = 111,
    kSysSigaltstack = 131,
    kSysStatfs = 137,
    kSysFstatfs = 138,
    kSysSchedGetaffinity = 204,
    kSysArchPrctl = 158,
    kSysGettid = 186,
    kSysTime = 201,
    kSysFutex = 202,
    kSysGetdents64 = 217,
    kSysSetTidAddress = 218,
    kSysClockGettime = 228,
    kSysClockGetres = 229,
    kSysClockNanosleep = 230,
    kSysExitGroup = 231,
    kSysTgkill = 234,
    kSysOpenat = 257,
    kSysMkdirat = 258,
    kSysNewfstatat = 262,
    kSysUnlinkat = 263,
    kSysRenameat = 264,
    kSysFaccessat = 269,
    kSysReadlinkat = 267,
    kSysSetRobustList = 273,
    kSysGetRobustList = 274,
    kSysEpollCreate1 = 291,
    kSysPipe2 = 293,
    kSysPrlimit64 = 302,
    kSysGetrandom = 318,
    kSysMemfdCreate = 319,
    kSysStatx = 332,
    kSysRseq = 334,
    kSysFaccessat2 = 439,
    kSysClone3 = 435,
};

/// Darwin's errno numbering diverges from Linux's above 34 (EAGAIN is 35 here and 11
/// there), so every failure is mapped rather than negated as-is.
int64_t ToLinuxErrno(int host_errno) {
    switch (host_errno) {
    case EPERM: return 1;
    case ENOENT: return 2;
    case ESRCH: return 3;
    case EINTR: return 4;
    case EIO: return 5;
    case ENXIO: return 6;
    case E2BIG: return 7;
    case ENOEXEC: return 8;
    case EBADF: return 9;
    case ECHILD: return 10;
    case EDEADLK: return 35;
    case ENOMEM: return 12;
    case EACCES: return 13;
    case EFAULT: return 14;
    case EBUSY: return 16;
    case EEXIST: return 17;
    case EXDEV: return 18;
    case ENODEV: return 19;
    case ENOTDIR: return 20;
    case EISDIR: return 21;
    case EINVAL: return 22;
    case ENFILE: return 23;
    case EMFILE: return 24;
    case ENOTTY: return 25;
    case ETXTBSY: return 26;
    case EFBIG: return 27;
    case ENOSPC: return 28;
    case ESPIPE: return 29;
    case EROFS: return 30;
    case EMLINK: return 31;
    case EPIPE: return 32;
    case EDOM: return 33;
    case ERANGE: return 34;
    case EAGAIN: return 11;
    case ENAMETOOLONG: return 36;
    case ENOLCK: return 37;
    case ENOSYS: return 38;
    case ENOTEMPTY: return 39;
    case ELOOP: return 40;
    case EOVERFLOW: return 75;
    case ENOTSUP: return 95;
    case ETIMEDOUT: return 110;
    default: return 22; // EINVAL
    }
}

uint64_t Fail(int host_errno) {
    return static_cast<uint64_t>(-ToLinuxErrno(host_errno));
}

uint64_t FailLinux(int linux_errno) {
    return static_cast<uint64_t>(-static_cast<int64_t>(linux_errno));
}

int ToHostOpenFlags(int guest_flags) {
    int host = guest_flags & guest::kOAccMode;
    if ((guest_flags & guest::kOCreat) != 0) host |= O_CREAT;
    if ((guest_flags & guest::kOExcl) != 0) host |= O_EXCL;
    if ((guest_flags & guest::kOTrunc) != 0) host |= O_TRUNC;
    if ((guest_flags & guest::kOAppend) != 0) host |= O_APPEND;
    if ((guest_flags & guest::kONonBlock) != 0) host |= O_NONBLOCK;
    if ((guest_flags & guest::kODirectory) != 0) host |= O_DIRECTORY;
    if ((guest_flags & guest::kOCloExec) != 0) host |= O_CLOEXEC;
    return host;
}

// x86-64 Linux's struct stat, written at the exact offsets the guest reads.
struct LinuxStat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t pad0;
    uint64_t st_rdev;
    int64_t st_size;
    int64_t st_blksize;
    int64_t st_blocks;
    uint64_t st_atime_sec;
    uint64_t st_atime_nsec;
    uint64_t st_mtime_sec;
    uint64_t st_mtime_nsec;
    uint64_t st_ctime_sec;
    uint64_t st_ctime_nsec;
    int64_t unused[3];
};
static_assert(sizeof(LinuxStat) == 144, "x86-64 Linux struct stat is 144 bytes");

void TranslateStat(const struct stat& host, LinuxStat* out) {
    std::memset(out, 0, sizeof(*out));
    out->st_dev = static_cast<uint64_t>(host.st_dev);
    out->st_ino = host.st_ino;
    out->st_nlink = host.st_nlink;
    // The mode bits that matter (S_IFMT kinds and the permission bits) share values
    // between Darwin and Linux, so this one field genuinely does carry across.
    out->st_mode = host.st_mode;
    out->st_uid = host.st_uid;
    out->st_gid = host.st_gid;
    out->st_rdev = static_cast<uint64_t>(host.st_rdev);
    out->st_size = host.st_size;
    out->st_blksize = host.st_blksize;
    out->st_blocks = host.st_blocks;
    out->st_atime_sec = static_cast<uint64_t>(host.st_atimespec.tv_sec);
    out->st_atime_nsec = static_cast<uint64_t>(host.st_atimespec.tv_nsec);
    out->st_mtime_sec = static_cast<uint64_t>(host.st_mtimespec.tv_sec);
    out->st_mtime_nsec = static_cast<uint64_t>(host.st_mtimespec.tv_nsec);
    out->st_ctime_sec = static_cast<uint64_t>(host.st_ctimespec.tv_sec);
    out->st_ctime_nsec = static_cast<uint64_t>(host.st_ctimespec.tv_nsec);
}

struct LinuxIovec {
    uint64_t base;
    uint64_t length;
};

struct LinuxTimespec {
    int64_t seconds;
    int64_t nanoseconds;
};

// Linux's timeval carries a 64-bit microseconds field; Darwin's is 32 bits plus
// padding. Same total size, different meaning, so it is written out by hand.
struct LinuxTimeval {
    int64_t seconds;
    int64_t microseconds;
};

clockid_t ToHostClock(int guest_clock, bool* supported) {
    *supported = true;
    switch (guest_clock) {
    case guest::kClockRealtime:
    case guest::kClockRealtimeCoarse:
        return CLOCK_REALTIME;
    case guest::kClockMonotonic:
    case guest::kClockMonotonicCoarse:
        return CLOCK_MONOTONIC;
    case guest::kClockMonotonicRaw:
        return CLOCK_MONOTONIC_RAW;
    case guest::kClockBoottime:
        return CLOCK_MONOTONIC;
    case guest::kClockProcessCputime:
        return CLOCK_PROCESS_CPUTIME_ID;
    case guest::kClockThreadCputime:
        return CLOCK_THREAD_CPUTIME_ID;
    default:
        *supported = false;
        return CLOCK_REALTIME;
    }
}

const char* SyscallName(uint64_t number) {
    switch (number) {
    case kSysRead: return "read";
    case kSysWrite: return "write";
    case kSysOpen: return "open";
    case kSysClose: return "close";
    case kSysStat: return "stat";
    case kSysFstat: return "fstat";
    case kSysLstat: return "lstat";
    case kSysLseek: return "lseek";
    case kSysMmap: return "mmap";
    case kSysMprotect: return "mprotect";
    case kSysMunmap: return "munmap";
    case kSysBrk: return "brk";
    case kSysRtSigaction: return "rt_sigaction";
    case kSysRtSigprocmask: return "rt_sigprocmask";
    case kSysIoctl: return "ioctl";
    case kSysPread64: return "pread64";
    case kSysReadv: return "readv";
    case kSysWritev: return "writev";
    case kSysAccess: return "access";
    case kSysSchedYield: return "sched_yield";
    case kSysMremap: return "mremap";
    case kSysMadvise: return "madvise";
    case kSysGetpid: return "getpid";
    case kSysClone: return "clone";
    case kSysExit: return "exit";
    case kSysUname: return "uname";
    case kSysFcntl: return "fcntl";
    case kSysGetdents64: return "getdents64";
    case kSysGetcwd: return "getcwd";
    case kSysChdir: return "chdir";
    case kSysReadlink: return "readlink";
    case kSysGettimeofday: return "gettimeofday";
    case kSysGetrlimit: return "getrlimit";
    case kSysGetuid: return "getuid";
    case kSysGeteuid: return "geteuid";
    case kSysArchPrctl: return "arch_prctl";
    case kSysGettid: return "gettid";
    case kSysFutex: return "futex";
    case kSysSetTidAddress: return "set_tid_address";
    case kSysClockGettime: return "clock_gettime";
    case kSysExitGroup: return "exit_group";
    case kSysOpenat: return "openat";
    case kSysNewfstatat: return "newfstatat";
    case kSysReadlinkat: return "readlinkat";
    case kSysSetRobustList: return "set_robust_list";
    case kSysPrlimit64: return "prlimit64";
    case kSysGetrandom: return "getrandom";
    case kSysStatx: return "statx";
    case kSysRseq: return "rseq";
    default: return "?";
    }
}

} // namespace

LinuxSyscalls::LinuxSyscalls(GuestAddressSpace& space, GuestThreadControl& control, SyscallConfig config)
    : space_ {space}
    , control_ {control}
    , config_ {std::move(config)} {
    if (!config_.work_dir.empty()) {
        cwd_ = NormaliseGuestPath(config_.work_dir);
    }
}

LinuxSyscalls::~LinuxSyscalls() {
    CloseAll();
}

void LinuxSyscalls::CloseAll() {
    std::scoped_lock lock {mutex_};
    for (auto& [fd, file] : files_) {
        if (file.directory != nullptr) {
            closedir(static_cast<DIR*>(file.directory)); // also closes host_fd
            continue;
        }
        if (file.host_fd >= 0) {
            close(file.host_fd);
        }
    }
    files_.clear();
}

void LinuxSyscalls::SetOutputCallback(OutputCallback callback, void* context) {
    std::scoped_lock lock {mutex_};
    output_ = callback;
    output_context_ = context;
}

void LinuxSyscalls::RequestStop() {
    stop_requested_.store(true, std::memory_order_relaxed);
    // A guest parked in read() is not at a syscall boundary and would otherwise wait for
    // a keystroke that is never coming.
    input_ready_.notify_all();
}

void LinuxSyscalls::SendInput(const char* bytes, size_t length) {
    if (bytes == nullptr || length == 0) {
        return;
    }
    {
        std::scoped_lock lock {input_mutex_};
        input_.insert(input_.end(), bytes, bytes + length);
    }
    input_ready_.notify_all();
}

void LinuxSyscalls::InitialiseHeap(uint64_t base, uint64_t reserved) {
    heap_base_ = base;
    heap_break_ = base;
    heap_limit_ = base + reserved;
    FATHOM_INFO("guest heap: %#llx..%#llx (%llu MB)", static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(heap_limit_),
                static_cast<unsigned long long>(reserved >> 20));
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

std::string LinuxSyscalls::NormaliseGuestPath(const std::string& path) const {
    std::string absolute = path;
    if (absolute.empty()) {
        absolute = cwd_;
    } else if (absolute.front() != '/') {
        absolute = cwd_ + (cwd_.back() == '/' ? "" : "/") + absolute;
    }

    std::vector<std::string> parts;
    size_t index = 0;
    while (index < absolute.size()) {
        while (index < absolute.size() && absolute[index] == '/') {
            ++index;
        }
        const size_t start = index;
        while (index < absolute.size() && absolute[index] != '/') {
            ++index;
        }
        if (start == index) {
            continue;
        }
        const std::string part = absolute.substr(start, index - start);
        if (part == ".") {
            continue;
        }
        if (part == "..") {
            // Popping an empty stack is how a guest would try to escape its root; at "/"
            // Linux itself treats ".." as "/", so doing nothing is both safe and correct.
            if (!parts.empty()) {
                parts.pop_back();
            }
            continue;
        }
        parts.push_back(part);
    }

    std::string normalised;
    for (const auto& part : parts) {
        normalised += "/";
        normalised += part;
    }
    return normalised.empty() ? "/" : normalised;
}

std::string LinuxSyscalls::ResolveGuestPath(const std::string& path) const {
    const std::string guest_path = NormaliseGuestPath(path);
    if (config_.guest_root.empty()) {
        return guest_path;
    }
    if (guest_path == "/") {
        return config_.guest_root;
    }
    return config_.guest_root + guest_path;
}

std::string LinuxSyscalls::ResolveAt(int dirfd, const char* path, std::string* guest_path_out) {
    std::string request = path == nullptr ? std::string {} : std::string {path};
    if (!request.empty() && request.front() != '/' && dirfd != guest::kAtFdCwd) {
        std::scoped_lock lock {mutex_};
        const auto entry = files_.find(dirfd);
        if (entry != files_.end()) {
            request = entry->second.guest_path + "/" + request;
        }
    }
    const std::string guest_path = NormaliseGuestPath(request);
    if (guest_path_out != nullptr) {
        *guest_path_out = guest_path;
    }
    return ResolveGuestPath(guest_path);
}

// ---------------------------------------------------------------------------
// Guest memory access
// ---------------------------------------------------------------------------

void* LinuxSyscalls::GuestPointer(uint64_t address, uint64_t size, bool writable) const {
    if (address == 0 || size == 0) {
        return nullptr;
    }
    const int required = kGuestProtRead | (writable ? kGuestProtWrite : 0);
    if (!space_.Validate(address, size, required)) {
        return nullptr;
    }
    return reinterpret_cast<void*>(address);
}

bool LinuxSyscalls::ReadGuestString(uint64_t address, std::string* out, size_t limit) const {
    if (address == 0) {
        return false;
    }
    // Walked a byte at a time with a validity check per page: a guest string has no
    // length, so the only safe way to find its end is to never read past a page the
    // guest does not own.
    std::string value;
    value.reserve(64);
    for (size_t offset = 0; offset < limit; ++offset) {
        const uint64_t byte_address = address + offset;
        if ((offset == 0) || (byte_address % guest::kPageSize) == 0) {
            if (!space_.Validate(byte_address, 1, kGuestProtRead)) {
                return false;
            }
        }
        const char byte = *reinterpret_cast<const char*>(byte_address);
        if (byte == '\0') {
            *out = std::move(value);
            return true;
        }
        value.push_back(byte);
    }
    return false;
}

// ---------------------------------------------------------------------------
// File descriptors
// ---------------------------------------------------------------------------

LinuxSyscalls::OpenFile* LinuxSyscalls::FindFile(int fd) {
    const auto entry = files_.find(fd);
    return entry == files_.end() ? nullptr : &entry->second;
}

int LinuxSyscalls::RegisterFile(int host_fd, std::string guest_path) {
    // Guest fds are host fds. open() never returns 0/1/2 here (those stay held by the
    // app itself), so the guest's stdio numbers can never collide with a real file.
    files_[host_fd] = OpenFile {host_fd, std::move(guest_path), nullptr};
    return host_fd;
}

// ---------------------------------------------------------------------------
// Syscall implementations
// ---------------------------------------------------------------------------

uint64_t LinuxSyscalls::DoOpenAt(int dirfd, uint64_t path_address, int flags, int mode) {
    std::string path;
    if (!ReadGuestString(path_address, &path)) {
        return FailLinux(14); // EFAULT
    }

    std::string guest_path;
    const std::string host_path = ResolveAt(dirfd, path.c_str(), &guest_path);

    // The display is a device, not a file: it is answered here rather than looked for in
    // the guest root, and its fd is backed by no host file at all.
    if (guest_path == "/dev/fb0" || guest_path == "/dev/graphics/fb0") {
        if (!EnsureFramebuffer()) {
            return FailLinux(12); // ENOMEM
        }
        std::scoped_lock lock {mutex_};
        // Numbered well above anything open() will hand out, so it cannot collide with a
        // real descriptor.
        int fd = 900;
        while (files_.count(fd) != 0) {
            ++fd;
        }
        files_[fd] = OpenFile {-1, guest_path, nullptr, true};
        FATHOM_INFO("guest opened the display as fd %d", fd);
        return static_cast<uint64_t>(fd);
    }

    const int host_fd = open(host_path.c_str(), ToHostOpenFlags(flags), static_cast<mode_t>(mode));
    if (host_fd < 0) {
        if (config_.trace) {
            FATHOM_DEBUG("openat(%s) -> %s", guest_path.c_str(), std::strerror(errno));
        }
        return Fail(errno);
    }

    std::scoped_lock lock {mutex_};
    return static_cast<uint64_t>(RegisterFile(host_fd, guest_path));
}

uint64_t LinuxSyscalls::DoWrite(int fd, uint64_t buffer, uint64_t count) {
    const void* data = GuestPointer(buffer, count, false);
    if (data == nullptr) {
        return count == 0 ? 0 : FailLinux(14);
    }

    if (fd == 1 || fd == 2) {
        OutputCallback callback = nullptr;
        void* context = nullptr;
        {
            std::scoped_lock lock {mutex_};
            callback = output_;
            context = output_context_;
        }
        if (callback != nullptr) {
            callback(context, fd, static_cast<const char*>(data), count);
        }
        return count;
    }

    std::scoped_lock lock {mutex_};
    auto* file = FindFile(fd);
    if (file == nullptr) {
        return FailLinux(9); // EBADF
    }
    const ssize_t written = write(file->host_fd, data, count);
    return written < 0 ? Fail(errno) : static_cast<uint64_t>(written);
}

uint64_t LinuxSyscalls::DoRead(int fd, uint64_t buffer, uint64_t count) {
    void* data = GuestPointer(buffer, count, true);
    if (data == nullptr) {
        return count == 0 ? 0 : FailLinux(14);
    }
    if (fd == 0) {
        std::unique_lock lock {input_mutex_};
        while (input_.empty()) {
            if (stop_requested_.load(std::memory_order_relaxed)) {
                // Unlocked by hand: ExitGuest unwinds by long jump and no destructor
                // between here and the run loop will ever run.
                lock.unlock();
                exit_status_ = -1;
                control_.ExitGuest(-1);
            }
            if (nonblocking_stdin_.load(std::memory_order_relaxed)) {
                return FailLinux(11); // EAGAIN
            }
            // Woken by SendInput; the timeout only exists so a stop request is noticed
            // even if no key ever arrives.
            input_ready_.wait_for(lock, std::chrono::milliseconds(100));
        }

        const auto available = std::min<uint64_t>(count, input_.size());
        auto* out = static_cast<char*>(data);
        for (uint64_t index = 0; index < available; ++index) {
            out[index] = input_.front();
            input_.pop_front();
        }
        return available;
    }

    std::scoped_lock lock {mutex_};
    auto* file = FindFile(fd);
    if (file == nullptr) {
        return FailLinux(9);
    }
    const ssize_t bytes = read(file->host_fd, data, count);
    return bytes < 0 ? Fail(errno) : static_cast<uint64_t>(bytes);
}

uint64_t LinuxSyscalls::DoWritev(int fd, uint64_t iov, uint64_t count) {
    const auto* vectors = static_cast<const LinuxIovec*>(GuestPointer(iov, count * sizeof(LinuxIovec), false));
    if (vectors == nullptr) {
        return count == 0 ? 0 : FailLinux(14);
    }
    uint64_t total = 0;
    for (uint64_t index = 0; index < count; ++index) {
        if (vectors[index].length == 0) {
            continue;
        }
        const uint64_t written = DoWrite(fd, vectors[index].base, vectors[index].length);
        if (static_cast<int64_t>(written) < 0) {
            return total > 0 ? total : written;
        }
        total += written;
        if (written < vectors[index].length) {
            break;
        }
    }
    return total;
}

uint64_t LinuxSyscalls::DoReadv(int fd, uint64_t iov, uint64_t count) {
    const auto* vectors = static_cast<const LinuxIovec*>(GuestPointer(iov, count * sizeof(LinuxIovec), false));
    if (vectors == nullptr) {
        return count == 0 ? 0 : FailLinux(14);
    }
    uint64_t total = 0;
    for (uint64_t index = 0; index < count; ++index) {
        if (vectors[index].length == 0) {
            continue;
        }
        const uint64_t bytes = DoRead(fd, vectors[index].base, vectors[index].length);
        if (static_cast<int64_t>(bytes) < 0) {
            return total > 0 ? total : bytes;
        }
        total += bytes;
        if (bytes < vectors[index].length) {
            break;
        }
    }
    return total;
}

uint64_t LinuxSyscalls::DoStatAt(int dirfd, uint64_t path_address, uint64_t stat_address, int flags) {
    auto* out = static_cast<LinuxStat*>(GuestPointer(stat_address, sizeof(LinuxStat), true));
    if (out == nullptr) {
        return FailLinux(14);
    }
    std::string path;
    if (!ReadGuestString(path_address, &path)) {
        return FailLinux(14);
    }

    const std::string host_path = ResolveAt(dirfd, path.c_str(), nullptr);
    struct stat host {};
    const int result = (flags & guest::kAtSymlinkNoFollow) != 0 ? lstat(host_path.c_str(), &host)
                                                                : stat(host_path.c_str(), &host);
    if (result != 0) {
        return Fail(errno);
    }
    TranslateStat(host, out);
    return 0;
}

uint64_t LinuxSyscalls::DoFstat(int fd, uint64_t stat_address) {
    auto* out = static_cast<LinuxStat*>(GuestPointer(stat_address, sizeof(LinuxStat), true));
    if (out == nullptr) {
        return FailLinux(14);
    }

    struct stat host {};
    if (fd >= 0 && fd <= 2) {
        // The guest's stdio is the app's console view, and a character device is the
        // closest honest description of it.
        std::memset(&host, 0, sizeof(host));
        host.st_mode = S_IFCHR | 0620;
        host.st_nlink = 1;
        host.st_blksize = 1024;
        TranslateStat(host, out);
        return 0;
    }

    std::scoped_lock lock {mutex_};
    auto* file = FindFile(fd);
    if (file == nullptr) {
        return FailLinux(9);
    }
    if (fstat(file->host_fd, &host) != 0) {
        return Fail(errno);
    }
    TranslateStat(host, out);
    return 0;
}

uint64_t LinuxSyscalls::DoGetdents64(int fd, uint64_t buffer, uint64_t size) {
    auto* out = static_cast<uint8_t*>(GuestPointer(buffer, size, true));
    if (out == nullptr) {
        return FailLinux(14);
    }

    std::scoped_lock lock {mutex_};
    auto* file = FindFile(fd);
    if (file == nullptr) {
        return FailLinux(9);
    }
    if (file->directory == nullptr) {
        // fdopendir takes ownership of the descriptor, so the OpenFile stops closing it
        // separately -- closedir does both.
        DIR* directory = fdopendir(file->host_fd);
        if (directory == nullptr) {
            return Fail(errno);
        }
        file->directory = directory;
    }

    uint64_t offset = 0;
    auto* directory = static_cast<DIR*>(file->directory);
    while (true) {
        const long position = telldir(directory);
        errno = 0;
        struct dirent* entry = readdir(directory);
        if (entry == nullptr) {
            if (errno != 0) {
                return Fail(errno);
            }
            break;
        }

        const size_t name_length = std::strlen(entry->d_name);
        // Linux's dirent64: u64 d_ino, s64 d_off, u16 d_reclen, u8 d_type, then the name.
        const size_t record_size = (8 + 8 + 2 + 1 + name_length + 1 + 7) & ~static_cast<size_t>(7);
        if (offset + record_size > size) {
            seekdir(directory, position); // Re-deliver this entry on the next call.
            break;
        }

        auto* record = out + offset;
        std::memset(record, 0, record_size);
        *reinterpret_cast<uint64_t*>(record) = entry->d_ino;
        *reinterpret_cast<int64_t*>(record + 8) = static_cast<int64_t>(telldir(directory));
        *reinterpret_cast<uint16_t*>(record + 16) = static_cast<uint16_t>(record_size);
        record[18] = entry->d_type; // DT_* values match between Darwin and Linux.
        std::memcpy(record + 19, entry->d_name, name_length + 1);
        offset += record_size;
    }
    return offset;
}

uint64_t LinuxSyscalls::DoMmap(uint64_t address, uint64_t length, int protection, int flags, int fd,
                               int64_t offset) {
    if (length == 0) {
        return FailLinux(22);
    }

    int guest_protection = 0;
    if ((protection & guest::kProtRead) != 0) guest_protection |= kGuestProtRead;
    if ((protection & guest::kProtWrite) != 0) guest_protection |= kGuestProtWrite;
    if ((protection & guest::kProtExec) != 0) guest_protection |= kGuestProtExec;
    if (guest_protection == 0) {
        // A PROT_NONE guard mapping still has to occupy its address range.
        guest_protection = kGuestProtRead;
    }

    const bool anonymous = (flags & guest::kMapAnonymous) != 0;
    const bool fixed = (flags & guest::kMapFixed) != 0;

    uint64_t placed = 0;
    if (fixed && address != 0) {
        // The guest insists on this address. Inside the arena that is satisfiable; the
        // range may already be committed, in which case this is a re-protect.
        if (!space_.Contains(address, length)) {
            return FailLinux(12); // ENOMEM
        }
        if (!space_.CommitFixed(address, length, guest_protection)) {
            return FailLinux(12);
        }
        placed = address;
    } else {
        // Writable regardless of what the guest asked for: file-backed contents have to
        // be written in below, and the real protection is applied afterwards.
        placed = space_.Allocate(length, address, guest_protection | kGuestProtWrite);
        if (placed == 0) {
            return FailLinux(12);
        }
    }

    if (!anonymous) {
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(fd);
        if (file == nullptr) {
            space_.Release(placed, length);
            return FailLinux(9);
        }
        if (file->is_framebuffer) {
            // Hand back the framebuffer itself rather than a copy: the whole point is
            // that what the guest writes here is what ends up on screen.
            space_.Release(placed, length);
            const auto display = Display();
            if (display.address == 0) {
                return FailLinux(19);
            }
            FATHOM_INFO("guest mapped the display at %#llx",
                        static_cast<unsigned long long>(display.address));
            return display.address;
        }
        // A real mmap shares pages with the page cache; this copies instead. For the one
        // case that matters here -- a dynamic loader mapping a library read-only or
        // private -- a copy is indistinguishable to the guest.
        if ((flags & guest::kMapShared) != 0) {
            FATHOM_WARN("MAP_SHARED file mapping is emulated as a private copy (fd %d)", fd);
        }
        uint64_t done = 0;
        while (done < length) {
            const ssize_t bytes = pread(file->host_fd, reinterpret_cast<void*>(placed + done),
                                        length - done, static_cast<off_t>(offset + static_cast<int64_t>(done)));
            if (bytes <= 0) {
                break; // Short file: the remainder stays zero, exactly as Linux leaves it.
            }
            done += static_cast<uint64_t>(bytes);
        }
    }

    if ((guest_protection & kGuestProtWrite) == 0) {
        space_.Protect(placed, length, guest_protection);
    }
    return placed;
}

uint64_t LinuxSyscalls::DoBrk(uint64_t requested) {
    if (heap_base_ == 0) {
        return 0;
    }
    if (requested == 0) {
        return heap_break_;
    }
    if (requested < heap_base_ || requested > heap_limit_) {
        // Linux answers an unsatisfiable brk with the current break rather than an error.
        return heap_break_;
    }
    heap_break_ = requested;
    return heap_break_;
}

bool LinuxSyscalls::EnsureFramebuffer() {
    std::scoped_lock lock {framebuffer_mutex_};
    if (framebuffer_.address != 0) {
        return true;
    }

    const uint32_t stride = kDisplayWidth * (kDisplayBpp / 8);
    const uint64_t size = static_cast<uint64_t>(stride) * kDisplayHeight;
    const uint64_t address = space_.Allocate(size, 0, kGuestProtRead | kGuestProtWrite);
    if (address == 0) {
        FATHOM_ERROR("could not allocate a %ux%u framebuffer", kDisplayWidth, kDisplayHeight);
        return false;
    }
    std::memset(reinterpret_cast<void*>(address), 0, size);

    framebuffer_ = Framebuffer {address, kDisplayWidth, kDisplayHeight, stride, kDisplayBpp};
    FATHOM_INFO("display: %ux%u at %u bpp, %llu KB at %#llx", kDisplayWidth, kDisplayHeight,
                kDisplayBpp, static_cast<unsigned long long>(size / 1024),
                static_cast<unsigned long long>(address));
    return true;
}

LinuxSyscalls::Framebuffer LinuxSyscalls::Display() const {
    std::scoped_lock lock {framebuffer_mutex_};
    return framebuffer_;
}

uint64_t LinuxSyscalls::DoFramebufferIoctl(uint64_t request, uint64_t argument) {
    const auto display = Display();
    if (display.address == 0) {
        return FailLinux(19); // ENODEV
    }

    switch (request) {
    case guest::kFbioGetVarScreenInfo: {
        auto* out = static_cast<uint8_t*>(GuestPointer(argument, 160, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        WriteVarScreenInfo(out, display.width, display.height, display.bits_per_pixel);
        return 0;
    }
    case guest::kFbioGetFixScreenInfo: {
        auto* out = static_cast<uint8_t*>(GuestPointer(argument, 80, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        WriteFixScreenInfo(out, display.address, display.stride, display.stride * display.height);
        return 0;
    }
    case guest::kFbioPutVarScreenInfo:
        // The mode is fixed. Accepted rather than refused, because a program that cannot
        // set its preferred mode usually carries on with whatever it was given, while one
        // that gets an error often gives up entirely.
        return 0;
    case guest::kFbioPanDisplay:
        // There is only one buffer, so panning is where a frame ends -- the one moment
        // the guest tells us it has finished drawing.
        frame_presentations_.fetch_add(1, std::memory_order_relaxed);
        return 0;
    case guest::kFbioBlank:
        return 0;
    default:
        return FailLinux(25); // ENOTTY
    }
}

uint64_t LinuxSyscalls::DoUname(uint64_t address) {
    // Linux's utsname is six fixed 65-byte fields back to back.
    constexpr size_t kField = 65;
    auto* out = static_cast<char*>(GuestPointer(address, kField * 6, true));
    if (out == nullptr) {
        return FailLinux(14);
    }
    std::memset(out, 0, kField * 6);
    const char* fields[6] = {"Linux", "fathom", "6.6.0-fathom", "#1 SMP Fathom", "x86_64", "(none)"};
    for (size_t index = 0; index < 6; ++index) {
        std::strncpy(out + index * kField, fields[index], kField - 1);
    }
    return 0;
}

uint64_t LinuxSyscalls::DoClockGettime(int clock, uint64_t address) {
    auto* out = static_cast<LinuxTimespec*>(GuestPointer(address, sizeof(LinuxTimespec), true));
    if (out == nullptr) {
        return FailLinux(14);
    }
    bool supported = false;
    const clockid_t host_clock = ToHostClock(clock, &supported);
    if (!supported) {
        return FailLinux(22);
    }
    struct timespec host {};
    if (clock_gettime(host_clock, &host) != 0) {
        return Fail(errno);
    }
    out->seconds = host.tv_sec;
    out->nanoseconds = host.tv_nsec;
    return 0;
}

uint64_t LinuxSyscalls::DoReadlinkAt(int dirfd, uint64_t path_address, uint64_t buffer, uint64_t size) {
    std::string path;
    if (!ReadGuestString(path_address, &path)) {
        return FailLinux(14);
    }
    auto* out = static_cast<char*>(GuestPointer(buffer, size, true));
    if (out == nullptr) {
        return FailLinux(14);
    }

    std::string guest_path;
    const std::string host_path = ResolveAt(dirfd, path.c_str(), &guest_path);

    // /proc/self/exe is how a program finds its own binary, and enough real programs
    // depend on it that answering it is worth the special case.
    if (guest_path == "/proc/self/exe" || guest_path == "/proc/curproc/file") {
        const std::string answer = config_.work_dir;
        const size_t copied = std::min(static_cast<size_t>(size), answer.size());
        std::memcpy(out, answer.data(), copied);
        return copied;
    }

    const ssize_t length = readlink(host_path.c_str(), out, size);
    return length < 0 ? Fail(errno) : static_cast<uint64_t>(length);
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

uint64_t LinuxSyscalls::Handle(uint64_t number, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                               uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    syscall_count_.fetch_add(1, std::memory_order_relaxed);

    if (stop_requested_.load(std::memory_order_relaxed)) {
        // Every syscall is a safe point to unwind from, which is what makes "stop" feel
        // immediate for anything that talks to the outside world at all.
        exit_status_ = -1;
        control_.ExitGuest(-1);
    }

    const auto count = syscall_count_.load(std::memory_order_relaxed);
    NoteSyscall(number, arg1, count);

    if (config_.trace) {
        FATHOM_INFO("syscall %llu %s(%#llx, %#llx, %#llx)", static_cast<unsigned long long>(number),
                    SyscallName(number), static_cast<unsigned long long>(arg1),
                    static_cast<unsigned long long>(arg2), static_cast<unsigned long long>(arg3));
    }

    const auto result = Dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6);

    if (config_.trace) {
        // The return value is the half that actually explains a stall: a syscall that
        // was reached and refused looks identical to one that was never reached unless
        // the answer is logged too.
        const auto signed_result = static_cast<int64_t>(result);
        if (signed_result < 0 && signed_result > -4096) {
            FATHOM_INFO("  -> error %lld", static_cast<long long>(-signed_result));
        } else {
            FATHOM_INFO("  -> %#llx", static_cast<unsigned long long>(result));
        }
    }
    return result;
}

uint64_t LinuxSyscalls::Dispatch(uint64_t number, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    switch (number) {
    case kSysRead:
        return DoRead(static_cast<int>(arg1), arg2, arg3);
    case kSysWrite:
        return DoWrite(static_cast<int>(arg1), arg2, arg3);
    case kSysOpen:
        return DoOpenAt(guest::kAtFdCwd, arg1, static_cast<int>(arg2), static_cast<int>(arg3));
    case kSysOpenat:
        return DoOpenAt(static_cast<int>(arg1), arg2, static_cast<int>(arg3), static_cast<int>(arg4));
    case kSysCreat:
        return DoOpenAt(guest::kAtFdCwd, arg1, guest::kOCreat | guest::kOTrunc | 1, static_cast<int>(arg2));

    case kSysClose: {
        const int fd = static_cast<int>(arg1);
        if (fd >= 0 && fd <= 2) {
            return 0; // The guest closing its own stdio must not close the app's.
        }
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(fd);
        if (file == nullptr) {
            return FailLinux(9);
        }
        if (file->directory != nullptr) {
            closedir(static_cast<DIR*>(file->directory));
        } else {
            close(file->host_fd);
        }
        files_.erase(fd);
        return 0;
    }

    case kSysStat:
        return DoStatAt(guest::kAtFdCwd, arg1, arg2, 0);
    case kSysLstat:
        return DoStatAt(guest::kAtFdCwd, arg1, arg2, guest::kAtSymlinkNoFollow);
    case kSysNewfstatat:
        return DoStatAt(static_cast<int>(arg1), arg2, arg3, static_cast<int>(arg4));
    case kSysFstat:
        return DoFstat(static_cast<int>(arg1), arg2);

    case kSysLseek: {
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        const off_t position = lseek(file->host_fd, static_cast<off_t>(arg2), static_cast<int>(arg3));
        return position < 0 ? Fail(errno) : static_cast<uint64_t>(position);
    }

    case kSysPread64: {
        void* data = GuestPointer(arg2, arg3, true);
        if (data == nullptr) {
            return arg3 == 0 ? 0 : FailLinux(14);
        }
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        const ssize_t bytes = pread(file->host_fd, data, arg3, static_cast<off_t>(arg4));
        return bytes < 0 ? Fail(errno) : static_cast<uint64_t>(bytes);
    }

    case kSysReadv:
        return DoReadv(static_cast<int>(arg1), arg2, arg3);
    case kSysWritev:
        return DoWritev(static_cast<int>(arg1), arg2, arg3);

    case kSysMmap:
        return DoMmap(arg1, arg2, static_cast<int>(arg3), static_cast<int>(arg4),
                      static_cast<int>(arg5), static_cast<int64_t>(arg6));

    case kSysMunmap:
        return space_.Release(arg1, arg2) ? 0 : FailLinux(22);

    case kSysMprotect: {
        int guest_protection = 0;
        if ((arg3 & guest::kProtRead) != 0) guest_protection |= kGuestProtRead;
        if ((arg3 & guest::kProtWrite) != 0) guest_protection |= kGuestProtWrite;
        if ((arg3 & guest::kProtExec) != 0) guest_protection |= kGuestProtExec;
        return space_.Protect(arg1, arg2, guest_protection) ? 0 : FailLinux(22);
    }

    case kSysMremap: {
        const uint64_t old_address = arg1;
        const uint64_t old_size = arg2;
        const uint64_t new_size = arg3;
        if (new_size <= old_size) {
            return old_address;
        }
        const uint64_t placed = space_.Allocate(new_size, 0, kGuestProtRead | kGuestProtWrite);
        if (placed == 0) {
            return FailLinux(12);
        }
        std::memcpy(reinterpret_cast<void*>(placed), reinterpret_cast<const void*>(old_address), old_size);
        space_.Release(old_address, old_size);
        return placed;
    }

    case kSysBrk:
        return DoBrk(arg1);

    case kSysMadvise:
    case kSysMsync:
    case kSysFsync:
        return 0;

    case kSysIoctl: {
        const int fd = static_cast<int>(arg1);
        bool is_display = false;
        {
            std::scoped_lock lock {mutex_};
            auto* file = FindFile(fd);
            is_display = file != nullptr && file->is_framebuffer;
        }
        if (is_display) {
            return DoFramebufferIoctl(arg2, arg3);
        }
        if (fd >= 0 && fd <= 2 && arg2 == guest::kTcgets) {
            // Claiming the console is a terminal makes the guest's libc line-buffer its
            // output, so the console view fills in as the program runs instead of only
            // at exit. Everything else about it is honest; this one is a choice.
            auto* termios_out = static_cast<uint8_t*>(GuestPointer(arg3, 36, true));
            if (termios_out == nullptr) {
                return FailLinux(14);
            }
            std::memset(termios_out, 0, 36);
            *reinterpret_cast<uint32_t*>(termios_out + 0) = 0x2502;  // ICRNL | IXON | ...
            *reinterpret_cast<uint32_t*>(termios_out + 4) = 0x5;     // OPOST | ONLCR
            *reinterpret_cast<uint32_t*>(termios_out + 8) = 0xbf;    // B38400 | CS8 | CREAD
            *reinterpret_cast<uint32_t*>(termios_out + 12) = 0x8a3b; // ISIG | ICANON | ECHO ...
            return 0;
        }
        if (fd >= 0 && fd <= 2 &&
            (arg2 == guest::kTcsets || arg2 == guest::kTcsetsw || arg2 == guest::kTcsetsf)) {
            // The guest is configuring the terminal. The only part that matters here is
            // ICANON: with it cleared the program wants individual keypresses rather than
            // whole lines, which is what every full-screen terminal program does on
            // startup -- and what tells the UI to offer a keypad.
            const auto* termios_in = static_cast<const uint8_t*>(GuestPointer(arg3, 36, false));
            if (termios_in == nullptr) {
                return FailLinux(14);
            }
            const uint32_t lflag = *reinterpret_cast<const uint32_t*>(termios_in + 12);
            const bool raw = (lflag & guest::kIcanon) == 0;
            if (raw != raw_mode_.exchange(raw, std::memory_order_relaxed)) {
                FATHOM_INFO("guest terminal mode: %s", raw ? "raw (wants individual keys)" : "canonical");
            }
            return 0;
        }
        if (fd >= 0 && fd <= 2 && arg2 == guest::kTiocgwinsz) {
            auto* window = static_cast<uint16_t*>(GuestPointer(arg3, 8, true));
            if (window == nullptr) {
                return FailLinux(14);
            }
            window[0] = 24;  // rows
            window[1] = 80;  // columns
            window[2] = 0;
            window[3] = 0;
            return 0;
        }
        return FailLinux(25); // ENOTTY
    }

    case kSysAccess:
    case kSysFaccessat:
    case kSysFaccessat2: {
        const bool is_at = number != kSysAccess;
        const int dirfd = is_at ? static_cast<int>(arg1) : guest::kAtFdCwd;
        const uint64_t path_address = is_at ? arg2 : arg1;
        const int mode = static_cast<int>(is_at ? arg3 : arg2);
        std::string path;
        if (!ReadGuestString(path_address, &path)) {
            return FailLinux(14);
        }
        const std::string host_path = ResolveAt(dirfd, path.c_str(), nullptr);
        return access(host_path.c_str(), mode) == 0 ? 0 : Fail(errno);
    }

    case kSysReadlink:
        return DoReadlinkAt(guest::kAtFdCwd, arg1, arg2, arg3);
    case kSysReadlinkat:
        return DoReadlinkAt(static_cast<int>(arg1), arg2, arg3, arg4);

    case kSysGetdents:
    case kSysGetdents64:
        return DoGetdents64(static_cast<int>(arg1), arg2, arg3);

    case kSysGetcwd: {
        auto* out = static_cast<char*>(GuestPointer(arg1, arg2, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::scoped_lock lock {mutex_};
        if (cwd_.size() + 1 > arg2) {
            return FailLinux(34); // ERANGE
        }
        std::memcpy(out, cwd_.c_str(), cwd_.size() + 1);
        return cwd_.size() + 1;
    }

    case kSysChdir: {
        std::string path;
        if (!ReadGuestString(arg1, &path)) {
            return FailLinux(14);
        }
        const std::string guest_path = NormaliseGuestPath(path);
        struct stat host {};
        if (stat(ResolveGuestPath(guest_path).c_str(), &host) != 0) {
            return Fail(errno);
        }
        if (!S_ISDIR(host.st_mode)) {
            return FailLinux(20); // ENOTDIR
        }
        std::scoped_lock lock {mutex_};
        cwd_ = guest_path;
        return 0;
    }

    case kSysMkdir:
    case kSysMkdirat: {
        const bool is_at = number == kSysMkdirat;
        std::string path;
        if (!ReadGuestString(is_at ? arg2 : arg1, &path)) {
            return FailLinux(14);
        }
        const std::string host_path = ResolveAt(is_at ? static_cast<int>(arg1) : guest::kAtFdCwd,
                                                path.c_str(), nullptr);
        const auto mode = static_cast<mode_t>(is_at ? arg3 : arg2);
        return mkdir(host_path.c_str(), mode) == 0 ? 0 : Fail(errno);
    }

    case kSysUnlink:
    case kSysUnlinkat: {
        const bool is_at = number == kSysUnlinkat;
        std::string path;
        if (!ReadGuestString(is_at ? arg2 : arg1, &path)) {
            return FailLinux(14);
        }
        const std::string host_path = ResolveAt(is_at ? static_cast<int>(arg1) : guest::kAtFdCwd,
                                                path.c_str(), nullptr);
        const bool remove_directory = is_at && (arg3 & 0x200) != 0; // AT_REMOVEDIR
        const int result = remove_directory ? rmdir(host_path.c_str()) : unlink(host_path.c_str());
        return result == 0 ? 0 : Fail(errno);
    }

    case kSysRmdir: {
        std::string path;
        if (!ReadGuestString(arg1, &path)) {
            return FailLinux(14);
        }
        return rmdir(ResolveGuestPath(path).c_str()) == 0 ? 0 : Fail(errno);
    }

    case kSysFtruncate: {
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        return ftruncate(file->host_fd, static_cast<off_t>(arg2)) == 0 ? 0 : Fail(errno);
    }

    case kSysFcntl: {
        constexpr int kGuestFGetfd = 1;
        constexpr int kGuestFSetfd = 2;
        constexpr int kGuestFGetfl = 3;
        constexpr int kGuestFSetfl = 4;
        const int command = static_cast<int>(arg2);
        if (command == kGuestFSetfl && static_cast<int>(arg1) == 0) {
            const bool nonblocking = (arg3 & guest::kONonBlock) != 0;
            nonblocking_stdin_.store(nonblocking, std::memory_order_relaxed);
            return 0;
        }
        if (command == kGuestFGetfd || command == kGuestFSetfd) {
            return 0;
        }
        if (command == kGuestFGetfl) {
            return 2; // O_RDWR, which is a safe answer for anything already open.
        }
        return 0;
    }

    case kSysDup:
    case kSysDup2: {
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        const int duplicated = dup(file->host_fd);
        if (duplicated < 0) {
            return Fail(errno);
        }
        return static_cast<uint64_t>(RegisterFile(duplicated, file->guest_path));
    }

    case kSysUname:
        return DoUname(arg1);

    case kSysArchPrctl: {
        switch (arg1) {
        case guest::kArchSetFs:
            control_.SetFsBase(arg2);
            return 0;
        case guest::kArchGetFs: {
            auto* out = static_cast<uint64_t*>(GuestPointer(arg2, sizeof(uint64_t), true));
            if (out == nullptr) {
                return FailLinux(14);
            }
            *out = control_.GetFsBase();
            return 0;
        }
        case guest::kArchSetGs:
        case guest::kArchGetGs:
            // GS is not wired through; nothing in a normal Linux userspace program uses
            // it, and silently accepting a write would be worse than refusing it.
            return FailLinux(22);
        default:
            return FailLinux(22);
        }
    }

    case kSysClockGettime:
        return DoClockGettime(static_cast<int>(arg1), arg2);

    case kSysClockGetres: {
        auto* out = static_cast<LinuxTimespec*>(GuestPointer(arg2, sizeof(LinuxTimespec), true));
        if (out == nullptr) {
            return 0;
        }
        out->seconds = 0;
        out->nanoseconds = 1;
        return 0;
    }

    case kSysGettimeofday: {
        auto* out = static_cast<LinuxTimeval*>(GuestPointer(arg1, sizeof(LinuxTimeval), true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        struct timeval host {};
        gettimeofday(&host, nullptr);
        out->seconds = host.tv_sec;
        out->microseconds = host.tv_usec;
        return 0;
    }

    case kSysTime: {
        const auto now = static_cast<uint64_t>(::time(nullptr));
        if (arg1 != 0) {
            auto* out = static_cast<uint64_t*>(GuestPointer(arg1, sizeof(uint64_t), true));
            if (out != nullptr) {
                *out = now;
            }
        }
        return now;
    }

    case kSysNanosleep:
    case kSysClockNanosleep: {
        const uint64_t request_address = number == kSysNanosleep ? arg1 : arg3;
        const auto* request = static_cast<const LinuxTimespec*>(
            GuestPointer(request_address, sizeof(LinuxTimespec), false));
        if (request == nullptr) {
            return FailLinux(14);
        }
        struct timespec host {request->seconds, request->nanoseconds};
        nanosleep(&host, nullptr);
        return 0;
    }

    case kSysSchedYield:
        sched_yield();
        return 0;

    case kSysGetrandom: {
        void* out = GuestPointer(arg1, arg2, true);
        if (out == nullptr) {
            return arg2 == 0 ? 0 : FailLinux(14);
        }
        arc4random_buf(out, arg2);
        return arg2;
    }

    case kSysGetpid:
    case kSysGettid:
        return 1000;
    case kSysGetppid:
    case kSysGetpgrp:
        return 1;
    case kSysGetuid:
    case kSysGeteuid:
    case kSysGetgid:
    case kSysGetegid:
        return 1000;
    case kSysUmask:
        return 0022;

    case kSysSetTidAddress:
        clear_child_tid_ = arg1;
        return 1000;

    case kSysSetRobustList:
    case kSysGetRobustList:
        return 0;

    case kSysRtSigaction:
    case kSysRtSigprocmask:
    case kSysSigaltstack:
        // Accepted and ignored. Guest signal delivery is not implemented, so a program
        // that installs a handler simply never has it called -- which is materially
        // better than refusing the call and sending its libc down an error path.
        return 0;

    case kSysGetrlimit:
    case kSysPrlimit64: {
        const uint64_t out_address = number == kSysGetrlimit ? arg2 : arg4;
        if (out_address == 0) {
            return 0;
        }
        auto* out = static_cast<uint64_t*>(GuestPointer(out_address, sizeof(uint64_t) * 2, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        const uint64_t resource = number == kSysGetrlimit ? arg1 : arg2;
        constexpr uint64_t kRlimitStack = 3;
        constexpr uint64_t kRlimitNofile = 7;
        if (resource == kRlimitStack) {
            out[0] = 8ULL * 1024 * 1024;
            out[1] = ~0ULL;
        } else if (resource == kRlimitNofile) {
            out[0] = 1024;
            out[1] = 4096;
        } else {
            out[0] = ~0ULL;
            out[1] = ~0ULL;
        }
        return 0;
    }

    case kSysSchedGetaffinity: {
        void* out = GuestPointer(arg3, arg2, true);
        if (out == nullptr || arg2 < 8) {
            return FailLinux(14);
        }
        std::memset(out, 0, arg2);
        *static_cast<uint8_t*>(out) = 0x1; // One CPU, matching the single guest thread.
        return 8;
    }

    case kSysFutex: {
        constexpr int kFutexWait = 0;
        constexpr int kFutexWake = 1;
        const int operation = static_cast<int>(arg2) & 0x7f;
        if (operation == kFutexWake) {
            return 0; // Nothing is ever waiting: the guest runs on one thread.
        }
        if (operation == kFutexWait) {
            const auto* value = static_cast<const uint32_t*>(GuestPointer(arg1, sizeof(uint32_t), false));
            if (value == nullptr) {
                return FailLinux(14);
            }
            if (*value != static_cast<uint32_t>(arg3)) {
                return FailLinux(11); // EAGAIN: the value moved, which is the common case.
            }
            // A genuine wait with one thread would be a deadlock. Reporting a spurious
            // wakeup sends the guest back around its own condition check, which is the
            // one answer that cannot corrupt its state.
            sched_yield();
            return 0;
        }
        return 0;
    }

    case kSysExit:
    case kSysExitGroup:
        exit_status_ = static_cast<int>(arg1);
        FATHOM_INFO("guest exited with status %d after %llu syscalls", exit_status_,
                    static_cast<unsigned long long>(syscall_count_.load(std::memory_order_relaxed)));
        control_.ExitGuest(exit_status_);

    case kSysClone:
    case kSysClone3:
    case kSysFork:
        FATHOM_WARN("guest tried to create a thread or process; Fathom runs a single guest thread");
        return FailLinux(38); // ENOSYS

    case kSysExecve:
        return FailLinux(38);

    case kSysKill:
    case kSysTgkill:
        return 0;

    case kSysRseq:
        // Refusing this is correct and expected: glibc treats ENOSYS as "no restartable
        // sequences" and carries on.
        return FailLinux(38);

    case kSysStatx: {
        // Answered through fstatat and reshaped, rather than left unimplemented: a
        // recent glibc reaches for statx first and only falls back if it returns ENOSYS.
        return FailLinux(38);
    }

    case kSysSysinfo:
    case kSysStatfs:
    case kSysFstatfs:
    case kSysPoll:
    case kSysEpollCreate1:
    case kSysPipe2:
    case kSysMemfdCreate:
        return FailLinux(38);

    default:
        FATHOM_WARN("unimplemented syscall %llu (%s)", static_cast<unsigned long long>(number),
                    SyscallName(number));
        return FailLinux(38); // ENOSYS
    }
}

} // namespace fathom

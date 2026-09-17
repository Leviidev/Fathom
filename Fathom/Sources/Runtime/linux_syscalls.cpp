#include "linux_syscalls.h"

#include "guest_net.h"
#include "guest_syscalls32.h"
#include "guest_path.h"

#include <poll.h>

#include "crash_handler.h"
#include "fathom_log.h"

#include <algorithm>
#include <set>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <thread>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/param.h>
#include <sys/mount.h>
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

/// clone(2) sharing the address space is a thread, not a process.
constexpr uint64_t kCloneVm = 0x00000100;
constexpr uint64_t kCloneThread = 0x00010000;

constexpr int kOAccMode = 0x3;
constexpr int kOCreat = 0x40;
constexpr int kOExcl = 0x80;
constexpr int kOTrunc = 0x200;
constexpr int kOAppend = 0x400;
constexpr int kONonBlock = 0x800;
constexpr int kODirectory = 0x10000;
/// fstatat with an empty path means "the descriptor itself". Modern glibc implements
/// plain fstat() this way, so without it every fstat stats the working directory --
/// which hands back one identical st_dev/st_ino for every open file, and a dynamic
/// loader uses exactly those two fields to decide whether it has already loaded a
/// library. Every library then looks like the same library.
constexpr int kAtEmptyPath = 0x1000;
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
    kSysMincore = 27,
    kSysMadvise = 28,
    kSysDup = 32,
    kSysDup2 = 33,
    kSysNanosleep = 35,
    kSysGetpid = 39,
    kSysClone = 56,
    kSysFork = 57,
    kSysVfork = 58,
    kSysExecve = 59,
    kSysExit = 60,
    kSysWait4 = 61,
    kSysFlock = 73,
    kSysFchdir = 81,
    kSysGetxattr = 191,
    kSysLgetxattr = 192,
    kSysFgetxattr = 193,
    kSysListxattr = 194,
    kSysLlistxattr = 195,
    kSysFlistxattr = 196,
    kSysChown = 92,
    kSysFchown = 93,
    kSysFchownat = 260,
    kSysLchown = 94,
    kSysRenameat2 = 316,
    kSysMount = 165,
    kSysUmount2 = 166,
    kSysSymlink = 88,
    kSysSymlinkat = 266,
    kSysLink = 86,
    kSysLinkat = 265,
    kSysFchmod = 91,
    kSysFchmodat = 268,
    kSysUtimensat = 280,
    kSysSelect = 23,
    kSysPselect6 = 270,
    kSysSocket = 41,
    kSysConnect = 42,
    kSysAccept = 43,
    kSysSendto = 44,
    kSysRecvfrom = 45,
    kSysSendmsg = 46,
    kSysRecvmsg = 47,
    kSysShutdown = 48,
    kSysBind = 49,
    kSysListen = 50,
    kSysGetsockname = 51,
    kSysGetpeername = 52,
    kSysSocketpair = 53,
    kSysSetsockopt = 54,
    kSysGetsockopt = 55,
    kSysAccept4 = 288,
    kSysPipe = 22,
    kSysDup3 = 292,
    kSysKill = 62,
    kSysUname = 63,
    kSysFcntl = 72,
    kSysFsync = 74,
    kSysFdatasync = 75,
    kSysMlock = 149,
    kSysMunlock = 150,
    kSysMlockall = 151,
    kSysMunlockall = 152,
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
    kSysSetgid = 106,
    kSysGeteuid = 107,
    kSysGetegid = 108,
    kSysGetppid = 110,
    kSysGetpgrp = 111,
    kSysSigaltstack = 131,
    kSysStatfs = 137,
    kSysFstatfs = 138,
    kSysGetpriority = 140,
    kSysSetpriority = 141,
    kSysSchedSetparam = 142,
    kSysSchedGetparam = 143,
    kSysSchedSetscheduler = 144,
    kSysSchedGetscheduler = 145,
    kSysSchedGetPriorityMax = 146,
    kSysSchedGetPriorityMin = 147,
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
    kSysPrctl = 157,
    kSysSemget = 64,
    kSysGetgroups = 115,
    kSysSetgroups = 116,
    kSysWaitid = 247,
    kSysSchedSetaffinity = 203,
    kSysRecvmmsg = 299,
    kSysSendmmsg = 307,
    kSysGetitimer = 36,
    kSysSetitimer = 38,
    kSysSetpgid = 109,
    kSysGetpgid = 121,
    kSysSetsid = 112,
    kSysGetsid = 124,
    kSysSetresuid = 117,
    kSysGetresuid = 118,
    kSysSetresgid = 119,
    kSysGetresgid = 120,
    kSysSemop = 65,
    kSysSemctl = 66,
    kSysMknod = 133,
    kSysMknodat = 259,
    kSysShmget = 29,
    kSysShmat = 30,
    kSysShmctl = 31,
    kSysShmdt = 67,
    kSysEpollCreate = 213,
    kSysEpollWait = 232,
    kSysEpollCtl = 233,
    kSysEpollPwait = 281,
    kSysTimerfdCreate = 283,
    kSysEventfd = 284,
    kSysTimerfdSettime = 286,
    kSysTimerfdGettime = 287,
    kSysEventfd2 = 290,
    kSysEpollCreate1 = 291,
    kSysPipe2 = 293,
    kSysPrlimit64 = 302,
    kSysFallocate = 285,
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
    case ENOMSG: return 42;
    case EIDRM: return 43;
    case ENOSTR: return 60;
    case ENODATA: return 61;
    case ETIME: return 62;
    case ENOLINK: return 67;
    case EPROTO: return 71;
    case EMULTIHOP: return 72;
    case EBADMSG: return 74;
    case EILSEQ: return 84;
    case ENOTSOCK: return 88;
    case EDESTADDRREQ: return 89;
    case EMSGSIZE: return 90;
    case EPROTOTYPE: return 91;
    case ENOPROTOOPT: return 92;
    case EPROTONOSUPPORT: return 93;
    case ESOCKTNOSUPPORT: return 94;
    case ENOTSUP: return 95;
    case EPFNOSUPPORT: return 96;
    case EAFNOSUPPORT: return 97;
    case EADDRINUSE: return 98;
    case EADDRNOTAVAIL: return 99;
    case ENETDOWN: return 100;
    case ENETUNREACH: return 101;
    case ENETRESET: return 102;
    case ECONNABORTED: return 103;
    case ECONNRESET: return 104;
    case ENOBUFS: return 105;
    case EISCONN: return 106;
    case ENOTCONN: return 107;
    case ESHUTDOWN: return 108;
    case ETOOMANYREFS: return 109;
    case ETIMEDOUT: return 110;
    case ECONNREFUSED: return 111;
    case EHOSTDOWN: return 112;
    case EHOSTUNREACH: return 113;
    case EALREADY: return 114;
    // The one that matters most of all. A non-blocking connect reports EINPROGRESS, and a
    // caller checks for exactly that value before waiting for the connection to complete.
    // Reported as anything else -- and the default below used to make it EINVAL -- the
    // caller concludes the address was bad and gives up, which a program describes to its
    // user as having no network at all.
    case EINPROGRESS: return 115;
    case ESTALE: return 116;
    case EDQUOT: return 122;
    case ECANCELED: return 125;
    default:
        // Worth saying out loud: a wrong errno sends a guest down a path meant for a
        // different failure, and that is far harder to recognise than a missing syscall.
        FATHOM_WARN("no Linux errno for host errno %d (%s); reporting EINVAL", host_errno,
                    std::strerror(host_errno));
        return 22; // EINVAL
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

// i386's struct stat64. Not a narrowed struct stat: the fields are in a different order,
// st_ino appears twice (once truncated at the front, once whole at the end), and the
// whole thing is 96 bytes rather than 144. Writing the x86-64 layout here overruns the
// guest's buffer by 48 bytes, which a stack-allocated one answers with "stack smashing
// detected" some functions later.
#pragma pack(push, 1)
struct LinuxStat32 {
    uint64_t st_dev;
    uint8_t pad0[4];
    uint32_t broken_st_ino;  ///< Truncated to 32 bits, kept for pre-LFS callers.
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint8_t pad3[4];
    int64_t st_size;
    uint32_t st_blksize;
    uint64_t st_blocks;
    uint32_t st_atime_sec;
    uint32_t st_atime_nsec;
    uint32_t st_mtime_sec;
    uint32_t st_mtime_nsec;
    uint32_t st_ctime_sec;
    uint32_t st_ctime_nsec;
    uint64_t st_ino;
};
#pragma pack(pop)
static_assert(sizeof(LinuxStat32) == 96, "i386 Linux struct stat64 is 96 bytes");

void TranslateStat32(const struct stat& host, LinuxStat32* out) {
    std::memset(out, 0, sizeof(*out));
    out->st_dev = static_cast<uint64_t>(host.st_dev);
    out->st_ino = host.st_ino;
    out->broken_st_ino = static_cast<uint32_t>(host.st_ino);
    out->st_mode = host.st_mode;
    out->st_nlink = host.st_nlink;
    out->st_uid = host.st_uid;
    out->st_gid = host.st_gid;
    out->st_rdev = static_cast<uint64_t>(host.st_rdev);
    out->st_size = host.st_size;
    out->st_blksize = static_cast<uint32_t>(host.st_blksize);
    out->st_blocks = static_cast<uint64_t>(host.st_blocks);
    out->st_atime_sec = static_cast<uint32_t>(host.st_atimespec.tv_sec);
    out->st_atime_nsec = static_cast<uint32_t>(host.st_atimespec.tv_nsec);
    out->st_mtime_sec = static_cast<uint32_t>(host.st_mtimespec.tv_sec);
    out->st_mtime_nsec = static_cast<uint32_t>(host.st_mtimespec.tv_nsec);
    out->st_ctime_sec = static_cast<uint32_t>(host.st_ctimespec.tv_sec);
    out->st_ctime_nsec = static_cast<uint32_t>(host.st_ctimespec.tv_nsec);
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
    case kSysPoll: return "poll";
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
    case kSysFork: return "fork";
    case kSysVfork: return "vfork";
    case kSysExecve: return "execve";
    case kSysWait4: return "wait4";
    case kSysSocket: return "socket";
    case kSysConnect: return "connect";
    case kSysAccept: return "accept";
    case kSysAccept4: return "accept4";
    case kSysSendto: return "sendto";
    case kSysRecvfrom: return "recvfrom";
    case kSysSendmsg: return "sendmsg";
    case kSysRecvmsg: return "recvmsg";
    case kSysShutdown: return "shutdown";
    case kSysBind: return "bind";
    case kSysListen: return "listen";
    case kSysGetsockname: return "getsockname";
    case kSysGetpeername: return "getpeername";
    case kSysSocketpair: return "socketpair";
    case kSysSetsockopt: return "setsockopt";
    case kSysGetsockopt: return "getsockopt";
    case kSysSelect: return "select";
    case kSysPselect6: return "pselect6";
    case kSysRename: return "rename";
    case kSysRenameat: return "renameat";
    case kSysRenameat2: return "renameat2";
    case kSysSymlink: return "symlink";
    case kSysSymlinkat: return "symlinkat";
    case kSysLink: return "link";
    case kSysLinkat: return "linkat";
    case kSysChmod: return "chmod";
    case kSysFchmod: return "fchmod";
    case kSysFchmodat: return "fchmodat";
    case kSysUtimensat: return "utimensat";
    case kSysGetxattr: return "getxattr";
    case kSysLgetxattr: return "lgetxattr";
    case kSysFgetxattr: return "fgetxattr";
    case kSysListxattr: return "listxattr";
    case kSysLlistxattr: return "llistxattr";
    case kSysFlistxattr: return "flistxattr";
    case kSysFchdir: return "fchdir";
    case kSysChown: return "chown";
    case kSysFchown: return "fchown";
    case kSysFchownat: return "fchownat";
    case kSysLchown: return "lchown";
    case kSysFlock: return "flock";
    case kSysStatfs: return "statfs";
    case kSysFstatfs: return "fstatfs";
    case kSysPipe: return "pipe";
    case kSysPipe2: return "pipe2";
    case kSysPrctl: return "prctl";
    case kSysSemget: return "semget";
    case kSysGetgroups: return "getgroups";
    case kSysSetgroups: return "setgroups";
    case kSysWaitid: return "waitid";
    case kSysGetpriority: return "getpriority";
    case kSysSetpriority: return "setpriority";
    case kSysSchedSetparam: return "sched_setparam";
    case kSysSchedGetparam: return "sched_getparam";
    case kSysSchedSetscheduler: return "sched_setscheduler";
    case kSysSchedGetscheduler: return "sched_getscheduler";
    case kSysSchedGetPriorityMax: return "sched_get_priority_max";
    case kSysSchedGetPriorityMin: return "sched_get_priority_min";
    case kSysFaccessat2: return "faccessat2";
    case kSysSchedSetaffinity: return "sched_setaffinity";
    case kSysRecvmmsg: return "recvmmsg";
    case kSysSendmmsg: return "sendmmsg";
    case kSysGetitimer: return "getitimer";
    case kSysSetitimer: return "setitimer";
    case kSysSetpgid: return "setpgid";
    case kSysGetpgid: return "getpgid";
    case kSysSetsid: return "setsid";
    case kSysGetsid: return "getsid";
    case kSysSetresuid: return "setresuid";
    case kSysGetresuid: return "getresuid";
    case kSysSetresgid: return "setresgid";
    case kSysGetresgid: return "getresgid";
    case kSysSemop: return "semop";
    case kSysSemctl: return "semctl";
    case kSysMknod: return "mknod";
    case kSysMknodat: return "mknodat";
    case kSysEpollCreate: return "epoll_create";
    case kSysEpollCreate1: return "epoll_create1";
    case kSysEpollCtl: return "epoll_ctl";
    case kSysEpollWait: return "epoll_wait";
    case kSysEpollPwait: return "epoll_pwait";
    case kSysShmget: return "shmget";
    case kSysShmat: return "shmat";
    case kSysShmctl: return "shmctl";
    case kSysShmdt: return "shmdt";
    case kSysTimerfdCreate: return "timerfd_create";
    case kSysTimerfdSettime: return "timerfd_settime";
    case kSysTimerfdGettime: return "timerfd_gettime";
    case kSysEventfd: return "eventfd";
    case kSysEventfd2: return "eventfd2";
    case kSysDup3: return "dup3";
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
    case kSysSetuid: return "setuid";
    case kSysSetgid: return "setgid";
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
    case kSysFallocate: return "fallocate";
    case kSysMemfdCreate: return "memfd_create";
    case kSysPwrite64: return "pwrite64";
    case kSysGetrandom: return "getrandom";
    case kSysStatx: return "statx";
    case kSysRseq: return "rseq";
    default: return "?";
    }
}

/// Every guest thread waiting on a futex waits here.
///
/// One queue rather than one per address: a wake notifies everybody and each waiter
/// re-checks the word it was told to watch, which futex semantics explicitly allow. It
/// costs a few spurious wake-ups under contention and saves keeping a hash table of
/// queues alive across forks and execs.
struct FutexQueueState {
    std::mutex mutex;
    std::condition_variable changed;
    uint64_t generation {};
};

/// One queue per address, near enough.
///
/// A single queue for the whole session is correct -- a futex waiter must re-check its own
/// word on waking -- and it is also unusable at scale: every wake anywhere wakes every
/// waiter everywhere, each of them re-checks, finds nothing and waits again. With Steam's
/// client and its web helper that is forty threads woken for each of thousands of wakes a
/// second, and none of them makes progress. Bucketing by address means a wake reaches the
/// handful of threads actually waiting on that word. Two addresses can share a bucket,
/// which costs a spurious wake and nothing else.
constexpr size_t kFutexBuckets = 1024;

FutexQueueState& FutexQueue(uint64_t address = 0) {
    static FutexQueueState queues[kFutexBuckets];
    // The low two bits are always zero -- a futex word is four bytes and aligned -- and
    // neighbouring words belong to different locks, so the next bits are what to spread on.
    return queues[(address >> 2) % kFutexBuckets];
}

} // namespace

void LinuxSyscalls::WakeFutex(uint64_t host_address) {
    auto& queue = FutexQueue(host_address);
    {
        std::scoped_lock lock {queue.mutex};
        ++queue.generation;
    }
    queue.changed.notify_all();
}

void LinuxSyscalls::ReleaseThreadId() {
    if (clear_child_tid_ == 0) {
        return;
    }
    // What the kernel does for CLONE_CHILD_CLEARTID, and what pthread_join waits for.
    auto* slot = static_cast<uint32_t*>(GuestPointer(clear_child_tid_, sizeof(uint32_t), true));
    const uint64_t address = ToHost(clear_child_tid_);
    clear_child_tid_ = 0;
    if (slot != nullptr) {
        *slot = 0;
    }
    WakeFutex(address);
}

LinuxSyscalls::LinuxSyscalls(GuestAddressSpace& space, GuestThreadControl& control,
                             GuestConsole& console, SyscallConfig config)
    : space_ {space}
    , control_ {control}
    , console_ {console}
    , config_ {std::move(config)}
    , shared_ {std::make_shared<ProcessFiles>()}
    , process_stopping_ {std::make_shared<std::atomic<bool>>(false)} {
    if (!config_.work_dir.empty()) {
        shared_->cwd = NormaliseGuestPath(config_.work_dir);
    }
    // stdin, stdout and stderr are entries like any other, so that a shell can point them
    // at a pipe or a file and everything downstream keeps working by number alone.
    for (int stream = 0; stream <= 2; ++stream) {
        OpenFile console;
        console.console_stream = stream;
        console.guest_path = "/dev/console";
        shared_->files[stream] = console;
    }
}

LinuxSyscalls::~LinuxSyscalls() {
    // Only the last thread holding the table closes what is in it. A thread going away
    // is not a process going away, and its siblings still need their descriptors.
    if (shared_.use_count() == 1) {
        CloseAll();
    }
}

void LinuxSyscalls::CloseAll() {
    std::scoped_lock lock {shared_->mutex};
    for (auto& [fd, file] : shared_->files) {
        if (file.directory != nullptr) {
            closedir(static_cast<DIR*>(file.directory)); // also closes host_fd
            continue;
        }
        if (file.host_fd >= 0) {
            close(file.host_fd);
        }
    }
    shared_->files.clear();
}

void LinuxSyscalls::SetProcess(int pid, int ppid, ProcessHost* host) {
    pid_ = pid;
    ppid_ = ppid;
    host_ = host;
    // One process, traced. A whole session's trace is unreadable and slow enough to change
    // what it is measuring; a single process that will not finish starting is usually the
    // only thing worth watching.
    if (const char* wanted = getenv("FATHOM_TRACE_PID")) {
        config_.trace = std::atoi(wanted) == pid;
    }
}

void LinuxSyscalls::CloneInto(LinuxSyscalls& child) const {
    std::scoped_lock lock {shared_->mutex};
    // Every descriptor is dup'd rather than shared outright: the child must be able to
    // close one, or point it somewhere else for a redirection, without the parent's
    // table changing underneath it. dup keeps the underlying file description shared,
    // which is exactly what fork promises.
    for (const auto& [fd, file] : shared_->files) {
        OpenFile inherited;
        inherited.guest_path = file.guest_path;
        // Carried across, and not obvious: without it a child's fd 1 is neither the
        // console nor a file, so the first thing it prints fails and it exits reporting
        // a write error instead of doing its job.
        inherited.console_stream = file.console_stream;
        inherited.is_framebuffer = file.is_framebuffer;
        inherited.event = file.event;
        inherited.epoll = file.epoll;
        inherited.is_timer = file.is_timer;
        inherited.close_on_exec = file.close_on_exec;
        inherited.timer_interval_ns = file.timer_interval_ns;
        inherited.timer_value_ns = file.timer_value_ns;

        if (file.host_fd >= 0) {
            inherited.host_fd = dup(file.host_fd);
            if (inherited.host_fd < 0) {
                // Said out loud, because a child quietly missing a descriptor its parent
                // gave it is invisible until something much later fails: Steam passes the
                // socket its web helper answers on this way, and a helper that never
                // answers is a Steam that never draws.
                FATHOM_WARN("fork: pid %d could not inherit fd %d (%s): %s", child.pid_, fd,
                            file.guest_path.c_str(), std::strerror(errno));
                continue;
            }
        }
        child.shared_->files[fd] = std::move(inherited);
    }
    child.shared_->cwd = shared_->cwd;
    child.shared_->heap_base = shared_->heap_base;
    child.shared_->heap_limit = shared_->heap_limit;
    child.shared_->heap_break = shared_->heap_break;
    // The child's address space *is* the parent's until it execs, so what the parent
    // mapped the child has mapped too. Without this the list starts empty, and the first
    // thing that goes wrong is a fork inside a fork: the grandchild's snapshot covers none
    // of those regions, so whatever it writes there is never put back and the child it was
    // forked from carries on with a heap somebody else has been scribbling in.
    child.shared_->mappings = shared_->mappings;
    child.shared_->image_data = shared_->image_data;
    child.config_.work_dir = config_.work_dir;
    // A fork is running the same program as its parent until it execs, so it answers
    // /proc/self/exe the same way -- which is how busybox re-runs itself as an applet.
    child.program_path_ = program_path_;
    child.command_line_ = command_line_;
    child.thread_name_ = thread_name_;
}

std::string LinuxSyscalls::DescribeFd(int fd) const {
    if (fd == 0) {
        return "the console";
    }
    std::scoped_lock lock {shared_->mutex};
    const auto found = shared_->files.find(fd);
    return found == shared_->files.end() ? std::string {} : found->second.guest_path;
}

uint64_t LinuxSyscalls::HeapBreak() const {
    return shared_->heap_break;
}

void LinuxSyscalls::ShareInto(LinuxSyscalls& thread) const {
    thread.shared_ = shared_;
    thread.process_stopping_ = process_stopping_;
    thread.config_.work_dir = config_.work_dir;
    thread.command_line_ = command_line_;
    thread.thread_name_ = thread_name_;
    thread.program_path_ = program_path_;
}

void LinuxSyscalls::AdoptImage(uint64_t heap_base, uint64_t heap_reserved, const std::string& path) {
    // A new program starts with all three of i386's thread-local slots free. Carrying the
    // count across an exec means a process that has exec'd a few times is told there are
    // none left, and its loader gives up with "cannot set up thread-local storage".
    next_tls_entry_ = 12;
    // Tracing one program rather than all of them. A full trace of a session that runs a
    // hundred processes is unreadable and slow enough to change what it is measuring; the
    // interesting one is usually a single program that will not start.
    if (const char* wanted = getenv("FATHOM_TRACE_PROGRAM")) {
        config_.trace = path.find(wanted) != std::string::npos;
    }
    InitialiseHeap(heap_base, heap_reserved);
    config_.work_dir = path;
    program_path_ = path;
    // An exec replaces the whole address space, so nothing the old program mapped is
    // this process's any more. Keeping the list would make a later fork snapshot and
    // then restore regions that have since been released and handed to somebody else --
    // which corrupts whichever process is now living there.
    std::scoped_lock lock {shared_->mutex};
    shared_->mappings.clear();
    shared_->image_data.clear();
    // The descriptors the old program asked to have closed here. Until now this layer
    // kept every one, which is not what the guest asked for and is not harmless: the
    // program on the far side of a pipe waits for every copy of the writing end to go.
    std::vector<int> closing;
    for (const auto& [fd, file] : shared_->files) {
        if (file.close_on_exec) {
            closing.push_back(fd);
        }
    }
    for (const int fd : closing) {
        CloseFd(fd);
    }
}

void LinuxSyscalls::InitialiseHeap(uint64_t base, uint64_t reserved) {
    shared_->heap_base = base;
    shared_->heap_break = base;
    shared_->heap_limit = base + reserved;
    FATHOM_INFO("guest heap: %#llx..%#llx (%llu MB)", static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(shared_->heap_limit),
                static_cast<unsigned long long>(reserved >> 20));
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

std::string LinuxSyscalls::NormaliseGuestPath(const std::string& path) const {
    // /proc/self/exe is the program's own binary, and programs do more with it than read
    // the link: Steam's launcher execs it to restart itself. Substituted here so that
    // open, exec and stat all agree about what it means.
    //
    // readlink is deliberately not routed through this -- see DoReadlinkAt. Answering it
    // from here would make the program's own binary look like a symlink pointing at
    // itself, and a program that verifies its own installation reports the file as
    // corrupt and reinstalls, for ever.
    if (!program_path_.empty() && IsProcSelfExe(path)) {
        return program_path_;
    }

    std::string absolute = path;
    if (absolute.empty()) {
        absolute = shared_->cwd;
    } else if (absolute.front() != '/') {
        absolute = shared_->cwd + (shared_->cwd.back() == '/' ? "" : "/") + absolute;
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

std::string LinuxSyscalls::ResolveGuestPath(const std::string& path, bool follow_final) const {
    // An empty path is ENOENT on Linux for every syscall that takes one (the AT_EMPTY_PATH
    // callers check for it before they get here). Normalising it to "/" instead hands the
    // caller the root directory, and a program that unlinks an uninitialised buffer is told
    // it may not delete a directory rather than that there is nothing there.
    if (path.empty()) {
        return {};
    }
    const std::string guest_path = NormaliseGuestPath(path);

    // The character devices every Unix program assumes exist. A minirootfs ships no /dev
    // at all -- it is built for a container runtime that mounts one -- so without this
    // the first thing a shell does with /dev/null fails, and a great many programs treat
    // that as fatal. The host has real ones, and they behave identically.
    if (guest_path == "/dev/null" || guest_path == "/dev/zero" || guest_path == "/dev/full" ||
        guest_path == "/dev/random" || guest_path == "/dev/urandom" || guest_path == "/dev/tty") {
        return guest_path;
    }

    if (config_.guest_root.empty()) {
        return guest_path;
    }
    // Not a plain concatenation: a symlink inside the root may point at an absolute
    // path, which means absolute *in the guest*, and the host would resolve it against
    // its own root and find nothing.
    return ResolveGuestPathOnHost(config_.guest_root, guest_path, follow_final);
}

std::string LinuxSyscalls::ResolveAt(int dirfd, const char* path, std::string* guest_path_out,
                                     bool follow_final) {
    std::string request = path == nullptr ? std::string {} : std::string {path};
    if (!request.empty() && request.front() != '/' && dirfd != guest::kAtFdCwd) {
        std::scoped_lock lock {shared_->mutex};
        const auto entry = shared_->files.find(dirfd);
        if (entry != shared_->files.end()) {
            request = entry->second.guest_path + "/" + request;
        }
    }
    if (request.empty()) {
        if (guest_path_out != nullptr) {
            guest_path_out->clear();
        }
        return {};
    }
    const std::string guest_path = NormaliseGuestPath(request);
    if (guest_path_out != nullptr) {
        *guest_path_out = guest_path;
    }
    return ResolveGuestPath(guest_path, follow_final);
}

// ---------------------------------------------------------------------------
// Guest memory access
// ---------------------------------------------------------------------------

void* LinuxSyscalls::GuestPointer(uint64_t address, uint64_t size, bool writable) const {
    if (address == 0 || size == 0) {
        return nullptr;
    }
    // The guest's number, not the host's. Identical for a 64-bit guest; for a 32-bit one
    // the arena lives high in the host's address space and this is where that is undone.
    address = ToHost(address);
    // Committed is the test, not writable. The guest's pages are 4KB and the host's are
    // 16KB, so the protection recorded for a host page is the union of up to four guest
    // pages' -- an approximation, and too coarse to refuse a syscall on. A guest that
    // passes a pointer into a page it has legitimately made writable can have that page
    // recorded read-only because a neighbour is, and the syscall comes back EFAULT for no
    // reason the guest can see. Whether the memory exists at all is the thing this can
    // answer accurately, and it is what catches a genuinely wild pointer.
    (void)writable;
    if (!space_.Validate(address, size, kGuestProtRead)) {
        return nullptr;
    }
    return reinterpret_cast<void*>(address);
}

bool LinuxSyscalls::ReadGuestStringArray(uint64_t address, std::vector<std::string>* out) const {
    out->clear();
    if (address == 0) {
        return true;  // A null argv is empty, not an error.
    }
    const size_t slot_size = config_.guest_is_32bit ? 4 : 8;
    for (size_t index = 0; index < 4096; ++index) {
        const auto* slot = static_cast<const unsigned char*>(
            GuestPointer(address + index * slot_size, slot_size, false));
        if (slot == nullptr) {
            return false;
        }
        uint64_t entry_address = 0;
        std::memcpy(&entry_address, slot, slot_size);
        if (entry_address == 0) {
            return true;
        }
        std::string entry;
        if (!ReadGuestString(entry_address, &entry)) {
            return false;
        }
        out->push_back(std::move(entry));
    }
    return true;
}

bool LinuxSyscalls::ReadGuestString(uint64_t address, std::string* out, size_t limit) const {
    if (address == 0) {
        return false;
    }
    // Walked a byte at a time with a validity check per page: a guest string has no
    // length, so the only safe way to find its end is to never read past a page the
    // guest does not own.
    // Guest numbering, like every other pointer a syscall is handed. GuestPointer does
    // this for fixed-size buffers; a string has to do it itself because it walks.
    const uint64_t host_address = ToHost(address);
    std::string value;
    value.reserve(64);
    for (size_t offset = 0; offset < limit; ++offset) {
        const uint64_t byte_address = host_address + offset;
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
    const auto entry = shared_->files.find(fd);
    return entry == shared_->files.end() ? nullptr : &entry->second;
}

std::vector<std::pair<uint64_t, uint64_t>> LinuxSyscalls::Mappings() const {
    std::scoped_lock lock {shared_->mutex};
    return shared_->mappings;
}

std::vector<std::pair<uint64_t, uint64_t>> LinuxSyscalls::ImageData(bool c_library_only) const {
    std::scoped_lock lock {shared_->mutex};
    std::vector<std::pair<uint64_t, uint64_t>> regions;
    regions.reserve(shared_->image_data.size());
    for (const auto& region : shared_->image_data) {
        if (!c_library_only || region.is_c_library) {
            regions.emplace_back(region.begin, region.size);
        }
    }
    return regions;
}

int LinuxSyscalls::AllocateFd() {
    int fd = 0;
    while (shared_->files.count(fd) != 0) {
        ++fd;
    }
    return fd;
}

int LinuxSyscalls::RegisterFile(int host_fd, std::string guest_path, bool close_on_exec) {
    // Guest descriptors are their own numbering, not the host's. They have to be, because
    // a guest expects the lowest free number back and expects to be able to move one onto
    // fd 1 -- and fd 1 on the host belongs to this app.
    const int fd = AllocateFd();
    OpenFile file;
    file.host_fd = host_fd;
    file.guest_path = std::move(guest_path);
    file.close_on_exec = close_on_exec;
    shared_->files[fd] = std::move(file);
    return fd;
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
        std::scoped_lock lock {shared_->mutex};
        const int fd = AllocateFd();
        OpenFile display;
        display.guest_path = guest_path;
        display.is_framebuffer = true;
        shared_->files[fd] = std::move(display);
        FATHOM_INFO("guest opened the display as fd %d", fd);
        return static_cast<uint64_t>(fd);
    }

    // A few /proc files are answered by this layer rather than by the guest root. They
    // are backed by a real unlinked temporary file so that the descriptor behaves like
    // any other -- seekable, statable, readable in whatever sized pieces the caller wants.
    std::string synthesised;
    if (ProcFileContents(guest_path, &synthesised)) {
        char pattern[] = "/tmp/fathom-proc-XXXXXX";
        const int backing = mkstemp(pattern);
        if (backing < 0) {
            return Fail(errno);
        }
        unlink(pattern);
        if (!synthesised.empty()) {
            (void)!write(backing, synthesised.data(), synthesised.size());
        }
        lseek(backing, 0, SEEK_SET);
        std::scoped_lock lock {shared_->mutex};
        return static_cast<uint64_t>(
            RegisterFile(backing, guest_path, (flags & guest::kOCloExec) != 0));
    }

    // /proc/self/fd, which Chromium reads to decide which descriptors to keep across an
    // exec. There is no /proc here to hold it, so one is made: a directory of links named
    // for this process's open descriptors, which readdir walks like any other. It is
    // removed when the descriptor onto it is closed.
    {
        const std::string self = "/proc/self/fd";
        const std::string mine = "/proc/" + std::to_string(pid_) + "/fd";
        if (guest_path == self || guest_path == mine) {
            const char* temporary = getenv("TMPDIR");
            std::string pattern = (temporary == nullptr ? "/tmp/" : std::string {temporary} + "/") +
                                  "fathom-fds-XXXXXX";
            std::vector<char> directory {pattern.begin(), pattern.end()};
            directory.push_back('\0');
            if (mkdtemp(directory.data()) == nullptr) {
                return Fail(errno);
            }
            const std::string made {directory.data()};
            {
                std::scoped_lock lock {shared_->mutex};
                for (const auto& [number, file] : shared_->files) {
                    const std::string link = made + "/" + std::to_string(number);
                    const std::string target =
                        file.guest_path.empty() ? std::string {"/"} : file.guest_path;
                    (void)symlink(target.c_str(), link.c_str());
                }
            }
            const int directory_fd = open(made.c_str(), O_RDONLY | O_DIRECTORY);
            if (directory_fd < 0) {
                rmdir(made.c_str());
                return Fail(errno);
            }
            std::scoped_lock lock {shared_->mutex};
            const int fd = RegisterFile(directory_fd, guest_path);
            shared_->files[fd].scratch_directory = made;
            return static_cast<uint64_t>(fd);
        }
    }

    // Shared memory, said out loud. There are a handful of these in a session and they are
    // how separate programs find each other's memory -- Steam's client and its web helper
    // share one -- so an open that does not happen is worth seeing.
    if (guest_path.rfind("/dev/shm/", 0) == 0) {
        FATHOM_INFO("[pid %d] opening %s", pid_, guest_path.c_str());
    }
    const int host_fd = open(host_path.c_str(), ToHostOpenFlags(flags), static_cast<mode_t>(mode));
    if (host_fd < 0) {
        if (config_.trace) {
            FATHOM_DEBUG("openat(%s) -> %s", guest_path.c_str(), std::strerror(errno));
        }
        return Fail(errno);
    }

    std::scoped_lock lock {shared_->mutex};
    return static_cast<uint64_t>(
        RegisterFile(host_fd, guest_path, (flags & guest::kOCloExec) != 0));
}

uint64_t LinuxSyscalls::DoWrite(int fd, uint64_t buffer, uint64_t count) {
    const void* data = GuestPointer(buffer, count, false);
    if (data == nullptr) {
        return count == 0 ? 0 : FailLinux(14);
    }

    int host_fd = -1;
    {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(fd);
        if (file == nullptr) {
            return FailLinux(9); // EBADF
        }
        if (file->event != nullptr) {
            return DoEventfdWrite(*file, buffer);
        }
        if (file->console_stream >= 0) {
            console_.Write(file->console_stream, static_cast<const char*>(data), count);
            return count;
        }
        host_fd = file->host_fd;
    }
    const ssize_t written = write(host_fd, data, count);
    return written < 0 ? Fail(errno) : static_cast<uint64_t>(written);
}

uint64_t LinuxSyscalls::DoRead(int fd, uint64_t buffer, uint64_t count) {
    void* data = GuestPointer(buffer, count, true);
    if (data == nullptr) {
        return count == 0 ? 0 : FailLinux(14);
    }
    bool from_console = false;
    int host_fd = -1;
    {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(fd);
        if (file == nullptr) {
            return FailLinux(9); // EBADF
        }
        if (file->event != nullptr) {
            return DoEventfdRead(*file, buffer);
        }
        if (file->is_timer) {
            return DoTimerfdRead(*file, buffer);
        }
        from_console = file->console_stream >= 0;
        host_fd = file->host_fd;
    }
    if (from_console) {
        const int64_t read_bytes = console_.ReadInput(static_cast<char*>(data), count);
        if (read_bytes < 0) {
            return FailLinux(11); // EAGAIN
        }
        if (read_bytes == 0 && console_.StopRequested()) {
            exit_status_ = -1;
            control_.ExitGuest(-1);
        }
        return static_cast<uint64_t>(read_bytes);
    }

    // The descriptor's number is taken above and the table's lock dropped before the read
    // itself, which is the whole point: a read blocks, and the table belongs to every
    // thread of the process. Holding it here stops all of them -- including the one that
    // was going to write the bytes this read is waiting for, because it needs the table
    // to find its own end of the pipe. Two threads of a program passing messages to each
    // other is not an unusual thing to do; Chromium does it during startup, and the whole
    // process would stop dead the first time it did.
    const auto waiting = EnterBlockingWait();
    const ssize_t bytes = read(host_fd, data, count);
    return bytes < 0 ? Fail(errno) : static_cast<uint64_t>(bytes);
}

namespace {

/// x86-64 Linux struct pollfd: 4 bytes of fd, then two 2-byte masks.
struct LinuxPollfd {
    int32_t fd;
    int16_t events;
    int16_t revents;
};
static_assert(sizeof(LinuxPollfd) == 8, "guest pollfd must be 8 bytes");

constexpr int16_t kPollIn = 0x001;
constexpr int16_t kPollOut = 0x004;
constexpr int16_t kPollErr = 0x008;
constexpr int16_t kPollHup = 0x010;
constexpr int16_t kPollNval = 0x020;

} // namespace

/// poll, which busybox's line editor depends on: after reading an ESC it polls stdin with
/// a short timeout to decide whether an arrow key followed or the user really pressed
/// escape. Returning ENOSYS here left the shell redrawing its prompt instead of reading.
/// select, which apk's downloader uses in place of poll. The descriptor sets are bitmaps
/// of *guest* descriptors, so every bit has to be mapped to the host's numbering and back
/// again -- a host fd_set built from guest numbers would watch whatever this app happens
/// to have open at those indices.
uint64_t LinuxSyscalls::DoSelect(int count, uint64_t read_address, uint64_t write_address,
                                 uint64_t except_address, int64_t timeout_us) {
    constexpr int kMaxFds = 1024;
    if (count < 0 || count > kMaxFds) {
        return FailLinux(22); // EINVAL
    }
    const uint64_t set_bytes = ((static_cast<uint64_t>(count) + 63) / 64) * 8;

    const auto load = [&](uint64_t address, std::vector<uint64_t>* out) -> bool {
        out->assign((set_bytes + 7) / 8, 0);
        if (address == 0 || set_bytes == 0) {
            return true;
        }
        const void* bits = GuestPointer(address, set_bytes, true);
        if (bits == nullptr) {
            return false;
        }
        std::memcpy(out->data(), bits, set_bytes);
        return true;
    };
    const auto store = [&](uint64_t address, const std::vector<uint64_t>& bits) {
        if (address == 0 || set_bytes == 0) {
            return;
        }
        void* out = GuestPointer(address, set_bytes, true);
        if (out != nullptr) {
            std::memcpy(out, bits.data(), set_bytes);
        }
    };
    const auto is_set = [](const std::vector<uint64_t>& bits, int fd) {
        return (bits[static_cast<size_t>(fd) / 64] >> (static_cast<size_t>(fd) % 64) & 1) != 0;
    };

    std::vector<uint64_t> want_read;
    std::vector<uint64_t> want_write;
    std::vector<uint64_t> want_except;
    if (!load(read_address, &want_read) || !load(write_address, &want_write) ||
        !load(except_address, &want_except)) {
        return FailLinux(14);
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(timeout_us < 0 ? 0 : timeout_us);

    for (;;) {
        if (ShouldStop()) {
            exit_status_ = -1;
            control_.ExitGuest(-1);
        }

        std::vector<uint64_t> ready_read(want_read.size(), 0);
        std::vector<uint64_t> ready_write(want_write.size(), 0);
        uint64_t ready = 0;

        for (int fd = 0; fd < count; ++fd) {
            const bool wants_read = is_set(want_read, fd);
            const bool wants_write = is_set(want_write, fd);
            if (!wants_read && !wants_write) {
                continue;
            }

            bool readable = false;
            bool writable = false;
            int console_stream = -1;
            int host_fd = -1;
            {
                std::scoped_lock lock {shared_->mutex};
                auto* file = FindFile(fd);
                if (file == nullptr) {
                    return FailLinux(9); // EBADF
                }
                console_stream = file->console_stream;
                host_fd = file->host_fd;
            }

            if (console_stream == 0) {
                readable = console_.InputAvailable();
            } else if (console_stream > 0) {
                writable = true;  // The console never blocks a write.
            } else if (host_fd >= 0) {
                struct pollfd probe {};
                probe.fd = host_fd;
                probe.events = static_cast<short>((wants_read ? POLLIN : 0) | (wants_write ? POLLOUT : 0));
                if (poll(&probe, 1, 0) > 0) {
                    readable = (probe.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
                    writable = (probe.revents & POLLOUT) != 0;
                }
            }

            if (wants_read && readable) {
                ready_read[static_cast<size_t>(fd) / 64] |= 1ULL << (static_cast<size_t>(fd) % 64);
                ++ready;
            }
            if (wants_write && writable) {
                ready_write[static_cast<size_t>(fd) / 64] |= 1ULL << (static_cast<size_t>(fd) % 64);
                ++ready;
            }
        }

        if (ready > 0 || timeout_us == 0) {
            store(read_address, ready_read);
            store(write_address, ready_write);
            store(except_address, std::vector<uint64_t>(want_except.size(), 0));
            return ready;
        }
        if (timeout_us > 0 && std::chrono::steady_clock::now() >= deadline) {
            store(read_address, std::vector<uint64_t>(want_read.size(), 0));
            store(write_address, std::vector<uint64_t>(want_write.size(), 0));
            store(except_address, std::vector<uint64_t>(want_except.size(), 0));
            return 0;
        }
        console_.WaitForInput(5);
    }
}

uint64_t LinuxSyscalls::DoPoll(uint64_t fds_address, uint64_t count, int timeout_ms) {
    const auto waiting = EnterBlockingWait();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms < 0 ? 0 : timeout_ms);

    // poll(NULL, 0, ms) is just a sleep, and some programs use it as one.
    if (count == 0) {
        if (timeout_ms > 0) {
            console_.WaitForInput(timeout_ms);
        }
        return 0;
    }

    auto* fds = static_cast<LinuxPollfd*>(GuestPointer(fds_address, count * sizeof(LinuxPollfd), true));
    if (fds == nullptr) {
        return FailLinux(14);
    }

    // Short enough that a stop request is still noticed promptly, long enough that waiting
    // costs nothing.
    constexpr int kSliceMilliseconds = 50;
    std::vector<struct pollfd> host_fds;
    std::vector<LinuxPollfd*> host_owners;

    for (;;) {
        if (ShouldStop()) {
            exit_status_ = -1;
            control_.ExitGuest(-1);
        }

        host_fds.clear();
        host_owners.clear();
        bool watches_console = false;

        uint64_t ready = 0;
        for (uint64_t index = 0; index < count; ++index) {
            auto& entry = fds[index];
            entry.revents = 0;
            if (entry.fd < 0) {
                continue;  // Negative fds are ignored, not errors.
            }

            if (entry.fd == 0) {
                watches_console = true;
                if ((entry.events & kPollIn) != 0 && console_.InputAvailable()) {
                    entry.revents |= kPollIn;
                }
            } else if (entry.fd == 1 || entry.fd == 2) {
                // The console never blocks a write.
                if ((entry.events & kPollOut) != 0) {
                    entry.revents |= kPollOut;
                }
            } else {
                int host_fd = -1;
                {
                    std::scoped_lock lock {shared_->mutex};
                    auto* file = FindFile(entry.fd);
                    if (file != nullptr) {
                        host_fd = file->host_fd;
                    }
                }
                if (host_fd < 0) {
                    entry.revents |= kPollNval;
                } else {
                    host_fds.push_back({host_fd, static_cast<short>(entry.events), 0});
                    host_owners.push_back(&entry);
                }
            }

            if (entry.revents != 0) {
                ++ready;
            }
        }

        // One host poll for all of them, and -- when nothing else needs watching -- with a
        // real timeout rather than zero. Polling each descriptor with a zero timeout and
        // then sleeping turns a guest that is waiting quietly for a socket into a process
        // burning a whole core, which is what an X client waiting for its server did.
        if (!host_fds.empty()) {
            const bool can_block = !watches_console && ready == 0 && timeout_ms != 0;
            int slice = 0;
            if (can_block) {
                slice = kSliceMilliseconds;
                if (timeout_ms > 0) {
                    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                               deadline - std::chrono::steady_clock::now())
                                               .count();
                    slice = static_cast<int>(std::clamp<int64_t>(remaining, 0, kSliceMilliseconds));
                }
            }
            const int answered = poll(host_fds.data(), static_cast<nfds_t>(host_fds.size()), slice);
            if (answered > 0) {
                for (size_t index = 0; index < host_fds.size(); ++index) {
                    if (host_fds[index].revents != 0) {
                        host_owners[index]->revents = static_cast<int16_t>(host_fds[index].revents);
                        ++ready;
                    }
                }
            }
        }

        if (ready > 0 || timeout_ms == 0) {
            return ready;
        }
        if (timeout_ms > 0 && std::chrono::steady_clock::now() >= deadline) {
            return 0;
        }

        // Only reached when the console is part of the set, or there is nothing to poll at
        // all: the host poll above has already done the waiting otherwise.
        if (watches_console || host_fds.empty()) {
            console_.WaitForInput(kSliceMilliseconds);
        }
    }
}

namespace {

/// Linux and Darwin agree on MSG_OOB, MSG_PEEK and MSG_DONTROUTE and then part company:
/// MSG_WAITALL is 0x100 on Linux and 0x40 on Darwin, and MSG_DONTWAIT is 0x40 on Linux
/// and 0x80 on Darwin -- so passing Linux's MSG_DONTWAIT straight through asks Darwin to
/// block until the whole buffer is full, which is the opposite of what was meant.
int HostMessageFlags(int guest_flags) {
    constexpr int kGuestMsgWaitall = 0x100;
    constexpr int kGuestMsgDontwait = 0x40;
    constexpr int kGuestMsgNosignal = 0x4000;

    int host_flags = guest_flags & (MSG_OOB | MSG_PEEK | MSG_DONTROUTE);
    if ((guest_flags & kGuestMsgWaitall) != 0) {
        host_flags |= MSG_WAITALL;
    }
    if ((guest_flags & kGuestMsgDontwait) != 0) {
        host_flags |= MSG_DONTWAIT;
    }
    // MSG_NOSIGNAL has no Darwin equivalent; SO_NOSIGPIPE is set on the socket instead.
    (void)kGuestMsgNosignal;
    return host_flags;
}

} // namespace

/// sendmsg and recvmsg, which musl's DNS resolver uses rather than recvfrom -- leaving
/// them unimplemented had it spin on ENOSYS several hundred thousand times per lookup.
///
/// The two systems lay struct msghdr out differently: Linux has a 4-byte pad after
/// msg_namelen and 64-bit msg_iovlen and msg_controllen, where Darwin has neither pad nor
/// the wider fields. The fields are therefore read out of the guest by offset rather than
/// cast across. struct iovec happens to match on both, so the guest's array is handed
/// over as-is once its buffers have been checked.
uint64_t LinuxSyscalls::DoMessage(int fd, uint64_t header_address, int flags, bool sending) {
    {
        // A netlink socket here is a pipe with nothing on the other end. recvmsg on a pipe
        // is an error the guest has no reason to see; "nothing yet" is the truth.
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(fd);
        if (file != nullptr && file->is_netlink) {
            return sending ? FailLinux(11) : FailLinux(11); // EAGAIN either way.
        }
    }
    const int host_fd = HostFdFor(fd);
    if (host_fd < 0) {
        return FailLinux(9);
    }

    // struct msghdr is pointers and size_ts throughout, so an i386 guest's is exactly half
    // the width of this process's -- 28 bytes against 56, with every field at a different
    // offset. Read at the wrong width, msg_controllen picks up half a pointer and comes
    // out as a nonsense length, and the call is refused with EINVAL. That is what an X
    // server's first read from a new client looks like when it goes wrong.
    const bool narrow = config_.guest_is_32bit;
    const size_t width = narrow ? 4 : 8;
    const size_t name_offset = 0;
    const size_t name_length_offset = width;
    const size_t iov_offset = narrow ? 8 : 16;
    const size_t iov_count_offset = narrow ? 12 : 24;
    const size_t control_offset = narrow ? 16 : 32;
    const size_t control_length_offset = narrow ? 20 : 40;
    const size_t flags_offset = narrow ? 24 : 48;
    const uint64_t header_size = narrow ? 28 : 56;

    auto* header = static_cast<uint8_t*>(GuestPointer(header_address, header_size, true));
    if (header == nullptr) {
        return FailLinux(14);
    }

    uint64_t name_address = 0;
    uint32_t name_length = 0;
    uint64_t iov_address = 0;
    uint64_t iov_count = 0;
    uint64_t control_address = 0;
    uint64_t control_length = 0;
    std::memcpy(&name_address, header + name_offset, width);
    std::memcpy(&name_length, header + name_length_offset, 4);
    std::memcpy(&iov_address, header + iov_offset, width);
    std::memcpy(&iov_count, header + iov_count_offset, width);
    std::memcpy(&control_address, header + control_offset, width);
    std::memcpy(&control_length, header + control_length_offset, width);

    if (iov_count > 1024) {
        return FailLinux(22); // EINVAL
    }
    // Built rather than cast: the guest's iovec is its own width, and its bases are guest
    // addresses that have to be turned into host ones before the kernel sees them.
    std::vector<std::pair<uint64_t, uint64_t>> guest_vectors;
    if (!ReadGuestIovec(iov_address, iov_count, &guest_vectors)) {
        return FailLinux(14);
    }
    std::vector<iovec> vectors;
    vectors.reserve(guest_vectors.size());
    for (const auto& [base, length] : guest_vectors) {
        void* data = length == 0 ? nullptr : GuestPointer(base, length, !sending);
        if (data == nullptr && length != 0) {
            return FailLinux(14);
        }
        vectors.push_back({data, static_cast<size_t>(length)});
    }
    sockaddr_storage address {};
    msghdr host_header {};
    host_header.msg_iov = vectors.empty() ? nullptr : vectors.data();
    host_header.msg_iovlen = static_cast<int>(vectors.size());

    // Ancillary data. The only kind that carries meaning across is SCM_RIGHTS -- an array
    // of open file descriptors sent over a unix socket -- and it has to be translated in
    // both directions, because a descriptor number belongs to the process holding it.
    // Steam's client and its web helper pass descriptors to each other constantly; with
    // them dropped, the receiver gets a message referring to a descriptor it never got.
    //
    // struct cmsghdr is a length, a level and a type: twelve bytes on i386 where the
    // length is a 32-bit size_t, sixteen here. Darwin numbers SOL_SOCKET 0xFFFF where
    // Linux numbers it 1.
    constexpr uint32_t kGuestSolSocket = 1;
    constexpr uint32_t kScmRights = 1;
    const size_t guest_cmsg_header = narrow ? 12 : 16;
    std::vector<unsigned char> host_control;

    if (sending && control_address != 0 && control_length >= guest_cmsg_header) {
        const auto* control = static_cast<const unsigned char*>(
            GuestPointer(control_address, control_length, false));
        if (control == nullptr) {
            return FailLinux(14);
        }
        std::vector<int> host_fds;
        uint64_t at = 0;
        while (at + guest_cmsg_header <= control_length) {
            uint64_t length = 0;
            uint32_t level = 0;
            uint32_t type = 0;
            std::memcpy(&length, control + at, width);
            std::memcpy(&level, control + at + width, 4);
            std::memcpy(&type, control + at + width + 4, 4);
            if (length < guest_cmsg_header || at + length > control_length) {
                break;
            }
            if (level == kGuestSolSocket && type == kScmRights) {
                const uint64_t count = (length - guest_cmsg_header) / sizeof(int32_t);
                for (uint64_t index = 0; index < count; ++index) {
                    int32_t guest_fd = 0;
                    std::memcpy(&guest_fd, control + at + guest_cmsg_header + index * 4, 4);
                    const int translated = HostFdFor(guest_fd);
                    if (translated >= 0) {
                        host_fds.push_back(translated);
                    }
                }
            }
            // Each entry is padded out to the architecture's word size.
            at += (length + width - 1) & ~(width - 1);
        }
        if (!host_fds.empty()) {
            host_control.resize(CMSG_SPACE(host_fds.size() * sizeof(int)));
            auto* cmsg = reinterpret_cast<cmsghdr*>(host_control.data());
            cmsg->cmsg_len = CMSG_LEN(host_fds.size() * sizeof(int));
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            std::memcpy(CMSG_DATA(cmsg), host_fds.data(), host_fds.size() * sizeof(int));
        }
    }

    if (sending) {
        if (name_address != 0 && name_length != 0) {
            const void* guest_name = GuestPointer(name_address, name_length, false);
            if (guest_name != nullptr) {
                const socklen_t length = ToHostSocketAddress(guest_name, name_length, &address);
                if (length != 0) {
                    host_header.msg_name = &address;
                    host_header.msg_namelen = length;
                }
            }
        }
        if (!host_control.empty()) {
            host_header.msg_control = host_control.data();
            host_header.msg_controllen = static_cast<socklen_t>(host_control.size());
        }
        const ssize_t sent = sendmsg(host_fd, &host_header, HostMessageFlags(flags));
        return sent < 0 ? Fail(errno) : static_cast<uint64_t>(sent);
    }

    if (name_address != 0 && name_length != 0) {
        host_header.msg_name = &address;
        host_header.msg_namelen = sizeof(address);
    }
    // Room for whatever descriptors arrive; the guest's own buffer is a different shape
    // and gets written afterwards.
    std::vector<unsigned char> received_control;
    if (control_address != 0 && control_length >= guest_cmsg_header) {
        received_control.resize(CMSG_SPACE(sizeof(int) * 64));
        host_header.msg_control = received_control.data();
        host_header.msg_controllen = static_cast<socklen_t>(received_control.size());
    }
    const ssize_t received = recvmsg(host_fd, &host_header, HostMessageFlags(flags));
    if (received < 0) {
        return Fail(errno);
    }

    uint64_t control_written = 0;
    if (!received_control.empty() && host_header.msg_controllen > 0) {
        std::vector<int32_t> guest_fds;
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&host_header); cmsg != nullptr;
             cmsg = CMSG_NXTHDR(&host_header, cmsg)) {
            if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
                continue;
            }
            const size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            const int* arriving = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
            std::scoped_lock lock {shared_->mutex};
            for (size_t index = 0; index < count; ++index) {
                guest_fds.push_back(static_cast<int32_t>(RegisterFile(arriving[index], "socket:[fd]")));
            }
        }
        if (!guest_fds.empty()) {
            const uint64_t needed = guest_cmsg_header + guest_fds.size() * sizeof(int32_t);
            auto* out_control = static_cast<unsigned char*>(
                GuestPointer(control_address, std::min(needed, control_length), true));
            if (out_control != nullptr && needed <= control_length) {
                const uint64_t length = needed;
                const uint32_t level = kGuestSolSocket;
                const uint32_t type = kScmRights;
                std::memcpy(out_control, &length, width);
                std::memcpy(out_control + width, &level, 4);
                std::memcpy(out_control + width + 4, &type, 4);
                std::memcpy(out_control + guest_cmsg_header, guest_fds.data(),
                            guest_fds.size() * sizeof(int32_t));
                control_written = needed;
            }
        }
    }
    std::memcpy(header + control_length_offset, &control_written, width);
    if (host_header.msg_name != nullptr && host_header.msg_namelen != 0) {
        void* guest_name = GuestPointer(name_address, name_length, true);
        if (guest_name != nullptr) {
            const socklen_t written = ToGuestSocketAddress(&address, guest_name, name_length);
            std::memcpy(header + name_length_offset, &written, 4);
        }
    }
    const int32_t out_flags = host_header.msg_flags;
    std::memcpy(header + flags_offset, &out_flags, 4);
    return static_cast<uint64_t>(received);
}

int LinuxSyscalls::HostFdFor(int guest_fd) {
    std::scoped_lock lock {shared_->mutex};
    auto* file = FindFile(guest_fd);
    return file == nullptr ? -1 : file->host_fd;
}

bool LinuxSyscalls::IsConsole(int fd) {
    std::scoped_lock lock {shared_->mutex};
    auto* file = FindFile(fd);
    return file != nullptr && file->console_stream >= 0;
}

/// Puts a copy of `file` on descriptor `target`. The caller holds the lock.
int LinuxSyscalls::DuplicateTo(const OpenFile& file, int target) {
    OpenFile copy;
    copy.guest_path = file.guest_path;
    copy.console_stream = file.console_stream;
    copy.is_framebuffer = file.is_framebuffer;
    if (file.host_fd >= 0) {
        copy.host_fd = dup(file.host_fd);
        if (copy.host_fd < 0) {
            return -1;
        }
    }
    shared_->files[target] = std::move(copy);
    return target;
}

/// Closes one descriptor. The caller holds the lock.
void LinuxSyscalls::CloseFd(int fd) {
    auto entry = shared_->files.find(fd);
    if (entry == shared_->files.end()) {
        return;
    }
    if (entry->second.directory != nullptr) {
        closedir(static_cast<DIR*>(entry->second.directory)); // also closes host_fd
    } else if (entry->second.host_fd >= 0) {
        close(entry->second.host_fd);
    }
    if (entry->second.netlink_peer >= 0) {
        close(entry->second.netlink_peer);
    }
    if (!entry->second.scratch_directory.empty()) {
        const std::string directory = entry->second.scratch_directory;
        DIR* listing = opendir(directory.c_str());
        if (listing != nullptr) {
            while (auto* item = readdir(listing)) {
                if (std::strcmp(item->d_name, ".") == 0 || std::strcmp(item->d_name, "..") == 0) {
                    continue;
                }
                unlink((directory + "/" + item->d_name).c_str());
            }
            closedir(listing);
        }
        rmdir(directory.c_str());
    }
    shared_->files.erase(entry);
}

bool LinuxSyscalls::ReadGuestIovec(uint64_t address, uint64_t count,
                                   std::vector<std::pair<uint64_t, uint64_t>>* out) const {
    out->clear();
    if (count == 0) {
        return true;
    }
    // struct iovec is two pointer-sized words, so an i386 guest's is half the width of
    // this process's. Reading it as the native struct would take every second field as a
    // base and fail on the first write to stderr.
    const size_t width = config_.guest_is_32bit ? 4 : 8;
    const auto* raw = static_cast<const unsigned char*>(GuestPointer(address, count * width * 2, false));
    if (raw == nullptr) {
        return false;
    }
    out->reserve(count);
    for (uint64_t index = 0; index < count; ++index) {
        uint64_t base = 0;
        uint64_t length = 0;
        std::memcpy(&base, raw + index * width * 2, width);
        std::memcpy(&length, raw + index * width * 2 + width, width);
        out->emplace_back(base, length);
    }
    return true;
}

uint64_t LinuxSyscalls::DoWritev(int fd, uint64_t iov, uint64_t count) {
    std::vector<std::pair<uint64_t, uint64_t>> vectors;
    if (!ReadGuestIovec(iov, count, &vectors)) {
        return count == 0 ? 0 : FailLinux(14);
    }
    uint64_t total = 0;
    for (const auto& [base, length] : vectors) {
        if (length == 0) {
            continue;
        }
        const uint64_t written = DoWrite(fd, base, length);
        if (static_cast<int64_t>(written) < 0) {
            return total > 0 ? total : written;
        }
        total += written;
        if (written < length) {
            break;
        }
    }
    return total;
}

uint64_t LinuxSyscalls::DoReadv(int fd, uint64_t iov, uint64_t count) {
    std::vector<std::pair<uint64_t, uint64_t>> vectors;
    if (!ReadGuestIovec(iov, count, &vectors)) {
        return count == 0 ? 0 : FailLinux(14);
    }
    uint64_t total = 0;
    for (const auto& [base, length] : vectors) {
        if (length == 0) {
            continue;
        }
        const uint64_t bytes = DoRead(fd, base, length);
        if (static_cast<int64_t>(bytes) < 0) {
            return total > 0 ? total : bytes;
        }
        total += bytes;
        if (bytes < length) {
            break;
        }
    }
    return total;
}

uint64_t LinuxSyscalls::WriteGuestStat(uint64_t address, const struct stat& host) {
    const uint64_t size = config_.guest_is_32bit ? sizeof(LinuxStat32) : sizeof(LinuxStat);
    void* out = GuestPointer(address, size, true);
    if (out == nullptr) {
        return FailLinux(14);
    }
    if (config_.guest_is_32bit) {
        TranslateStat32(host, static_cast<LinuxStat32*>(out));
    } else {
        TranslateStat(host, static_cast<LinuxStat*>(out));
    }
    return 0;
}

uint64_t LinuxSyscalls::DoStatAt(int dirfd, uint64_t path_address, uint64_t stat_address, int flags) {
    const uint64_t stat_size = config_.guest_is_32bit ? sizeof(LinuxStat32) : sizeof(LinuxStat);
    if (GuestPointer(stat_address, stat_size, true) == nullptr) {
        return FailLinux(14);
    }
    std::string path;
    if (!ReadGuestString(path_address, &path)) {
        return FailLinux(14);
    }

    struct stat host {};
    int result = 0;
    if (path.empty() && (flags & guest::kAtEmptyPath) != 0) {
        if (dirfd == guest::kAtFdCwd) {
            result = stat(ResolveGuestPath(shared_->cwd).c_str(), &host);
        } else {
            const int host_fd = HostFdFor(dirfd);
            if (host_fd < 0) {
                // The console, which has no host descriptor behind it.
                return DoFstat(dirfd, stat_address);
            }
            result = fstat(host_fd, &host);
        }
    } else {
        const bool follow = (flags & guest::kAtSymlinkNoFollow) == 0;
        std::string guest_path;
        const std::string host_path = ResolveAt(dirfd, path.c_str(), &guest_path, follow);
        // The /proc entries this layer makes up have no file behind them, and a program
        // that stats before it opens -- which is most of them -- is told they are not
        // there. Answering for them here is what makes them exist.
        std::string contents;
        if (guest_path == "/proc/self/fd" || guest_path == "/proc/" + std::to_string(pid_) + "/fd") {
            host = {};
            host.st_mode = S_IFDIR | 0500;
            host.st_nlink = 2;
            host.st_size = 512;
            result = 0;
        } else if (guest_path.rfind("/proc/", 0) == 0 && ProcFileContents(guest_path, &contents)) {
            host = {};
            host.st_mode = S_IFREG | 0444;
            host.st_nlink = 1;
            host.st_size = static_cast<off_t>(contents.size());
            result = 0;
        } else {
            result = follow ? stat(host_path.c_str(), &host) : lstat(host_path.c_str(), &host);
        }
    }
    if (result != 0) {
        return Fail(errno);
    }
    return WriteGuestStat(stat_address, host);
}

uint64_t LinuxSyscalls::DoFstat(int fd, uint64_t stat_address) {
    struct stat host {};
    if (IsConsole(fd)) {
        // The guest's stdio is the app's console view, and a character device is the
        // closest honest description of it.
        std::memset(&host, 0, sizeof(host));
        host.st_mode = S_IFCHR | 0620;
        host.st_nlink = 1;
        host.st_blksize = 1024;
        return WriteGuestStat(stat_address, host);
    }

    {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(fd);
        if (file == nullptr) {
            return FailLinux(9);
        }
        if (fstat(file->host_fd, &host) != 0) {
            return Fail(errno);
        }
    }
    return WriteGuestStat(stat_address, host);
}

uint64_t LinuxSyscalls::DoGetdents64(int fd, uint64_t buffer, uint64_t size) {
    auto* out = static_cast<uint8_t*>(GuestPointer(buffer, size, true));
    if (out == nullptr) {
        return FailLinux(14);
    }

    std::scoped_lock lock {shared_->mutex};
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
    // Everything below -- the arena, shared_->mappings, the framebuffer -- is in host addresses.
    // The guest's hint comes in guest-numbered and the result goes back out the same way;
    // for a 1:1 (64-bit) guest both conversions are the identity.
    if (address != 0) {
        address = ToHost(address);
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
        // The contents about to be written here are not what was here before, and this
        // range was never released -- a loader maps a library's whole span and then maps
        // each of its segments over the top. Any code compiled from the old bytes has to
        // go, or the new library runs as the old one.
        //
        // Only for a mapping the guest can execute, though. Throwing compiled code away
        // stops every thread in the process: FEXCore's invalidation lock gives writers
        // priority, so one of these blocks every thread that is running compiled code
        // until it is done. A loader places a library's data and bss this way too, and
        // Chromium's allocator places a hundred megabytes of heap this way -- none of
        // which any block was ever compiled from. Code arriving at an address always
        // arrives executable, either here or through an mprotect, and both invalidate.
        if ((guest_protection & kGuestProtExec) != 0) {
            space_.NotifyContentsReplaced(placed, placed + length);
        }
    } else {
        // Writable regardless of what the guest asked for: file-backed contents have to
        // be written in below, and the real protection is applied afterwards.
        placed = space_.Allocate(length, address, guest_protection | kGuestProtWrite);
        if (placed == 0) {
            return FailLinux(12);
        }
    }

    // A library's data and bss: a file mapping with write permission, or an anonymous one
    // placed at a fixed address, which is how a loader lays a library's bss over the span
    // it reserved for it. Recorded so that a fork can hold it for the parent.
    if ((guest_protection & kGuestProtWrite) != 0 && (fixed || !anonymous)) {
        std::scoped_lock lock {shared_->mutex};
        // Whether this belongs to the C library is worth knowing on its own: it is the
        // only part a fork's child is guaranteed to rewrite, and the only part small
        // enough to be worth holding for a parent whose other threads are still running.
        // An anonymous mapping placed at a fixed address is a library's bss, and it
        // belongs to whichever library was mapped just below it.
        bool is_c_library = false;
        if (!anonymous) {
            auto* mapped_file = FindFile(fd);
            if (mapped_file != nullptr) {
                const auto& path = mapped_file->guest_path;
                const auto name = path.find_last_of('/');
                const std::string base = name == std::string::npos ? path : path.substr(name + 1);
                is_c_library = base.rfind("libc.so", 0) == 0 || base.rfind("libc-", 0) == 0 ||
                               base.rfind("libpthread", 0) == 0 || base.rfind("ld-", 0) == 0 ||
                               base.rfind("ld-linux", 0) == 0;
            }
        } else if (!shared_->image_data.empty()) {
            const auto& previous = shared_->image_data.back();
            is_c_library = previous.is_c_library && previous.begin + previous.size <= placed &&
                           placed - (previous.begin + previous.size) < 0x10000;
        }
        shared_->image_data.push_back({placed, length, is_c_library});
    }

    if (anonymous) {
        // Linux guarantees anonymous pages read as zero, and a dynamic loader depends on
        // it completely: it maps a library's whole span from the file and then maps .bss
        // anonymously on top. Skip this and .bss keeps the file bytes that happened to
        // lie underneath, so a pointer that should be NULL holds whatever was there --
        // which is how a library crashes on an address out of its own file offsets.
        //
        // Freshly reserved arena pages are already zero, but the arena is reused as
        // processes come and go, so the zeroing has to be unconditional.
        std::memset(reinterpret_cast<void*>(placed), 0, length);
    }

    if (!anonymous) {
        std::scoped_lock lock {shared_->mutex};
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
            return ToGuest(display.address);
        }
        // MAP_SHARED means the guest's writes must be visible in the file, and to
        // everything else that mapped it. That is not something a copy can imitate, and
        // it is exactly what an X server's framebuffer and X11's shared-memory images
        // rely on. Mapped for real, over the arena pages the allocation just handed out.
        //
        // The one thing that cannot be honoured is an offset the host's larger pages
        // cannot express; that falls through to the copy below, which is still right for
        // a reader and only wrong for a writer.
        const uint64_t host_page = space_.HostPageSize();
        if ((flags & guest::kMapShared) != 0 && (static_cast<uint64_t>(offset) % host_page) == 0) {
            uint64_t rounded = (length + host_page - 1) & ~(host_page - 1);

            // Never past the end of the file. The host's pages are four times the guest's,
            // so rounding a small mapping up can reach well beyond what the file actually
            // has -- and a page of a file-backed mapping with no file behind it does not
            // read as zero, it raises SIGBUS. The remainder stays as the arena's own
            // anonymous memory, which reads as zero the way Linux's partial last page does.
            struct stat info {};
            if (fstat(file->host_fd, &info) == 0) {
                const uint64_t size_on_disk = static_cast<uint64_t>(info.st_size);
                const uint64_t after_offset = size_on_disk > static_cast<uint64_t>(offset)
                                                  ? size_on_disk - static_cast<uint64_t>(offset)
                                                  : 0;
                rounded = std::min(rounded, (after_offset + host_page - 1) & ~(host_page - 1));
            }

            int host_protection = PROT_READ;
            if ((protection & guest::kProtWrite) != 0) {
                host_protection |= PROT_WRITE;
            }
            void* mapped = rounded == 0
                               ? MAP_FAILED
                               : mmap(reinterpret_cast<void*>(placed), rounded, host_protection,
                                      MAP_FIXED | MAP_SHARED, file->host_fd,
                                      static_cast<off_t>(offset));
            if (mapped != MAP_FAILED) {
                // The table's lock is already held by the block this sits in.
                shared_->mappings.emplace_back(placed, length);
                return ToGuest(placed);
            }
            FATHOM_WARN("shared mapping of %s failed (%s); falling back to a private copy",
                        file->guest_path.c_str(), std::strerror(errno));
        }
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

    if (!anonymous && (protection & guest::kProtExec) != 0) {
        // Where a shared library's code actually landed. Without this, a guest address in
        // a crash report or a JIT trace cannot be attributed to any file at all: the
        // loader maps its libraries itself, so nothing else in this process knows.
        std::scoped_lock lock {shared_->mutex};
        if (auto* file = FindFile(fd)) {
            FATHOM_INFO("mapped %s code at %#llx..%#llx", file->guest_path.c_str(),
                        static_cast<unsigned long long>(ToGuest(placed)),
                        static_cast<unsigned long long>(ToGuest(placed) + length));
        }
    }
    if ((guest_protection & kGuestProtWrite) == 0) {
        space_.Protect(placed, length, guest_protection);
    }
    {
        std::scoped_lock lock {shared_->mutex};
        shared_->mappings.emplace_back(placed, length);
    }
    return ToGuest(placed);
}

uint64_t LinuxSyscalls::DoBrk(uint64_t requested) {
    if (shared_->heap_base == 0) {
        return 0;
    }
    if (requested == 0) {
        return shared_->heap_break;
    }
    if (requested < shared_->heap_base || requested > shared_->heap_limit) {
        // Linux answers an unsatisfiable brk with the current break rather than an error.
        return shared_->heap_break;
    }
    if (requested > shared_->heap_break) {
        // Linux gives zeroed pages when the break grows, and malloc relies on it: the
        // first thing it does with fresh heap is read a chunk header out of it. This
        // arena is reserved once and handed round, so the bytes above the break are
        // whatever the last process to own them left there -- a forked child that
        // allocated before exec'ing, most often. Left dirty, the parent's next malloc
        // reads that as a chunk header and glibc aborts with an assertion about the top
        // chunk, a long way from anything that looks related.
        std::memset(reinterpret_cast<void*>(ToHost(shared_->heap_break)), 0,
                    requested - shared_->heap_break);
    }
    shared_->heap_break = requested;
    return shared_->heap_break;
}

bool LinuxSyscalls::EnsureFramebuffer() {
    if (console_.Display().address != 0) {
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

    console_.SetFramebuffer(Framebuffer {address, kDisplayWidth, kDisplayHeight, stride, kDisplayBpp});
    FATHOM_INFO("display: %ux%u at %u bpp, %llu KB at %#llx", kDisplayWidth, kDisplayHeight,
                kDisplayBpp, static_cast<unsigned long long>(size / 1024),
                static_cast<unsigned long long>(address));
    return true;
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
        console_.NotePresentation();
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

bool LinuxSyscalls::ReadGuestTimespec(uint64_t address, int64_t* seconds,
                                      int64_t* nanoseconds) const {
    const size_t width = TimeWidth();
    const auto* raw = static_cast<const unsigned char*>(GuestPointer(address, width * 2, false));
    if (raw == nullptr) {
        return false;
    }
    *seconds = 0;
    *nanoseconds = 0;
    std::memcpy(seconds, raw, width);
    std::memcpy(nanoseconds, raw + width, width);
    return true;
}

bool LinuxSyscalls::WriteGuestTimespec(uint64_t address, int64_t seconds,
                                       int64_t nanoseconds) const {
    const size_t width = TimeWidth();
    auto* raw = static_cast<unsigned char*>(GuestPointer(address, width * 2, true));
    if (raw == nullptr) {
        return false;
    }
    std::memcpy(raw, &seconds, width);
    std::memcpy(raw + width, &nanoseconds, width);
    return true;
}

uint64_t LinuxSyscalls::DoClockGettime(int clock, uint64_t address) {
    bool supported = false;
    const clockid_t host_clock = ToHostClock(clock, &supported);
    if (!supported) {
        return FailLinux(22);
    }
    struct timespec host {};
    if (clock_gettime(host_clock, &host) != 0) {
        return Fail(errno);
    }
    return WriteGuestTimespec(address, host.tv_sec, host.tv_nsec) ? 0 : FailLinux(14);
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

    // Only the literal /proc/self/exe is a link to the program. Testing the *resolved*
    // path instead would answer for the binary itself as well, and report it as a symlink
    // pointing at itself.
    if (!program_path_.empty() && IsProcSelfExe(path)) {
        const size_t copied = std::min(static_cast<size_t>(size), program_path_.size());
        std::memcpy(out, program_path_.data(), copied);
        return copied;
    }

    std::string guest_path;
    // The link itself, not what it points at -- otherwise readlink is handed a regular
    // file and reports EINVAL for every symlink in the tree.
    const std::string host_path = ResolveAt(dirfd, path.c_str(), &guest_path, false);

    const ssize_t length = readlink(host_path.c_str(), out, size);
    return length < 0 ? Fail(errno) : static_cast<uint64_t>(length);
}

uint32_t LinuxSyscalls::ToHostSocketAddress(const void* guest_address, uint64_t guest_length,
                                            sockaddr_storage* out) const {
    const uint32_t length = fathom::net::ToHostAddress(guest_address, guest_length, out);
    if (length == 0 || out->ss_family != AF_UNIX) {
        return length;
    }

    // A unix socket is named by a path, and a path from the guest means a path inside the
    // guest root. Passed through untouched, a guest binding /tmp/.X11-unix/X0 would bind
    // the Mac's own /tmp -- outside the sandbox, and colliding with a real X server.
    auto* un = reinterpret_cast<sockaddr_un*>(out);
    std::string guest_path;
    if (un->sun_path[0] == '\0') {
        // Linux's abstract namespace, which Darwin does not have. X11 clients try the
        // abstract name before the filesystem one, so refusing it would work but would
        // cost a failed connection every time. Giving it a directory of its own instead
        // keeps both ends agreeing on where the socket is, which is all the namespace was
        // doing for them.
        const size_t name_length = strnlen(un->sun_path + 1, sizeof(un->sun_path) - 1);
        std::string name {un->sun_path + 1, name_length};
        std::replace(name.begin(), name.end(), '/', '%');
        guest_path = "/tmp/.fathom-abstract/" + name;
        ::mkdir(ResolveGuestPath("/tmp/.fathom-abstract").c_str(), 0777);
    } else {
        guest_path.assign(un->sun_path, strnlen(un->sun_path, sizeof(un->sun_path)));
    }

    const std::string host_path = ResolveGuestPath(guest_path);
    if (config_.trace) {
        FATHOM_DEBUG("unix socket %s -> %s", guest_path.c_str(), host_path.c_str());
    }
    if (host_path.size() >= sizeof(un->sun_path)) {
        // Darwin allows four fewer bytes here than Linux does, and the guest root is a
        // prefix on top of that, so this is a real limit rather than a formality.
        errno = ENAMETOOLONG;
        return 0;
    }
    std::memset(un->sun_path, 0, sizeof(un->sun_path));
    std::memcpy(un->sun_path, host_path.c_str(), host_path.size());
    un->sun_len = static_cast<uint8_t>(sizeof(sockaddr_un));
    return static_cast<uint32_t>(sizeof(sockaddr_un));
}

uint32_t LinuxSyscalls::ToGuestSocketAddress(sockaddr_storage* host_address, void* guest_address,
                                             uint64_t capacity) const {
    // The guest must not be told where its root really is, so the prefix comes back off.
    if (host_address->ss_family == AF_UNIX) {
        auto* un = reinterpret_cast<sockaddr_un*>(host_address);
        std::string path {un->sun_path, strnlen(un->sun_path, sizeof(un->sun_path))};
        const std::string& root = config_.guest_root;
        if (!root.empty() && path.rfind(root, 0) == 0) {
            path.erase(0, root.size());
            if (path.empty() || path.front() != '/') {
                path.insert(path.begin(), '/');
            }
            std::memset(un->sun_path, 0, sizeof(un->sun_path));
            std::memcpy(un->sun_path, path.c_str(), std::min(path.size(), sizeof(un->sun_path) - 1));
        }
    }
    return fathom::net::ToGuestAddress(reinterpret_cast<sockaddr*>(host_address), guest_address,
                                       capacity);
}

uint64_t LinuxSyscalls::DoMultiMessage(int fd, uint64_t vector_address, uint64_t count, int flags,
                                       bool sending) {
    // struct mmsghdr is a msghdr followed by the count of bytes transferred for it, so its
    // size follows the msghdr's: 32 bytes for an i386 guest, 64 here.
    const uint64_t header_size = config_.guest_is_32bit ? 28 : 56;
    const uint64_t entry_size = config_.guest_is_32bit ? 32 : 64;

    uint64_t done = 0;
    for (uint64_t index = 0; index < count; ++index) {
        const uint64_t entry = vector_address + index * entry_size;
        const uint64_t result = DoMessage(fd, entry, flags, sending);
        if (static_cast<int64_t>(result) < 0) {
            // Linux reports a failure only when nothing at all got through; otherwise it
            // returns how many messages it managed and leaves the error for next time.
            return done > 0 ? done : result;
        }
        auto* transferred = static_cast<uint32_t*>(GuestPointer(entry + header_size, 4, true));
        if (transferred == nullptr) {
            return done > 0 ? done : FailLinux(14);
        }
        *transferred = static_cast<uint32_t>(result);
        ++done;
    }
    return done;
}

uint64_t LinuxSyscalls::DoLlseek(int fd, uint32_t offset_high, uint32_t offset_low,
                                 uint64_t result_address, int whence) {
    // i386's answer to a 32-bit off_t: the offset arrives split across two registers and
    // the result comes back through a pointer rather than in the return value. Handed to
    // lseek unchanged -- which is what merely renumbering it to lseek does -- the high
    // half becomes the offset and the low half becomes the whence, and every seek fails
    // with EINVAL. A program reading an archive then produces nothing and reports no error
    // of its own, which is exactly what Steam's installer did.
    const int host_fd = HostFdFor(fd);
    if (host_fd < 0) {
        return IsConsole(fd) ? FailLinux(29) : FailLinux(9); // ESPIPE for a terminal.
    }
    const int64_t offset =
        (static_cast<int64_t>(static_cast<int32_t>(offset_high)) << 32) | offset_low;
    const off_t placed = lseek(host_fd, static_cast<off_t>(offset), whence);
    if (placed < 0) {
        return Fail(errno);
    }
    auto* out = static_cast<int64_t*>(GuestPointer(result_address, sizeof(int64_t), true));
    if (out == nullptr) {
        return FailLinux(14);
    }
    *out = placed;
    return 0;
}

uint64_t LinuxSyscalls::DoSocketcall(uint64_t call, uint64_t arguments_address) {
    // i386 reached every socket operation through this one entry point before it was
    // given individual numbers: `call` says which, and the arguments are an array of
    // 32-bit words rather than registers. Modern glibc prefers the direct numbers, so
    // this is here for the older binaries Steam ships alongside its own libraries.
    struct Call {
        uint64_t x86_64_number;
        int arguments;
    };
    static constexpr Call kCalls[] = {
        {0, 0},      {41, 3},  // socket
        {49, 3},     {42, 3},  // bind, connect
        {50, 2},     {43, 3},  // listen, accept
        {51, 3},     {52, 3},  // getsockname, getpeername
        {53, 4},     {44, 4},  // socketpair, send
        {45, 4},     {44, 6},  // recv, sendto
        {45, 6},     {48, 2},  // recvfrom, shutdown
        {54, 5},     {55, 5},  // setsockopt, getsockopt
        {46, 3},     {47, 3},  // sendmsg, recvmsg
        {288, 4},    {299, 5}, // accept4, recvmmsg
        {307, 4},              // sendmmsg
    };
    if (call == 0 || call >= std::size(kCalls)) {
        return FailLinux(22);
    }
    const Call& selected = kCalls[call];

    const auto* words = static_cast<const uint32_t*>(
        GuestPointer(arguments_address, static_cast<uint64_t>(selected.arguments) * 4, false));
    if (words == nullptr && selected.arguments > 0) {
        return FailLinux(14);
    }
    uint64_t unpacked[6] = {};
    for (int index = 0; index < selected.arguments; ++index) {
        unpacked[index] = words[index];
    }
    // send/recv are sendto/recvfrom with no address, which is how Linux implements them.
    if (call == 9 || call == 10) {
        unpacked[4] = 0;
        unpacked[5] = 0;
    }
    const uint64_t result = Dispatch(selected.x86_64_number, unpacked[0], unpacked[1],
                                     unpacked[2], unpacked[3], unpacked[4], unpacked[5]);
    if (config_.trace) {
        // Not routed through Handle's own tracing: socketcall is unpacked before the
        // number is translated, so without this every socket operation an older binary
        // makes is invisible in the log.
        FATHOM_INFO("[pid %d] socketcall %llu -> %s(%#llx, %#llx, %#llx) -> %lld", pid_,
                    static_cast<unsigned long long>(call), SyscallName(selected.x86_64_number),
                    static_cast<unsigned long long>(unpacked[0]),
                    static_cast<unsigned long long>(unpacked[1]),
                    static_cast<unsigned long long>(unpacked[2]),
                    static_cast<long long>(result));
    }
    return result;
}

bool LinuxSyscalls::IsProcSelfExe(const std::string& path) const {
    return path == "/proc/self/exe" || path == "/proc/" + std::to_string(pid_) + "/exe";
}

uint64_t LinuxSyscalls::DoSetThreadArea(uint64_t descriptor_address) {
    // struct user_desc: entry_number, base_addr, limit, then a word of bit fields
    // describing the segment. Fathom always installs a 32-bit read/write data segment,
    // which is the only kind glibc asks for; of the bit fields only limit_in_pages
    // changes what the limit means.
    auto* descriptor = static_cast<uint32_t*>(GuestPointer(descriptor_address, 16, true));
    if (descriptor == nullptr) {
        return FailLinux(14);
    }

    uint32_t entry = descriptor[0];
    if (entry == 0xFFFF'FFFFU) {
        // "Any free one." Linux picks a slot and writes the number back, and glibc reads
        // it to build the selector it loads into %gs. Three is all i386 has; asking for a
        // fourth is the caller's own bug, and telling it so is what Linux does.
        if (next_tls_entry_ > 14) {
            FATHOM_WARN("set_thread_area: all three thread-local slots are already taken");
            return FailLinux(22);
        }
        entry = next_tls_entry_++;
        descriptor[0] = entry;
    } else if (entry < 12 || entry > 14) {
        return FailLinux(22);
    }

    // The limit is in bytes unless the limit_in_pages bit says it is already in pages,
    // and glibc sets that bit with a limit of 0xfffff -- the whole address space. Shifting
    // it down regardless turned that into 0xff, a segment of one megabyte.
    constexpr uint32_t kLimitInPages = 1u << 4;
    const uint32_t limit = (descriptor[3] & kLimitInPages) != 0 ? descriptor[2]
                                                                : descriptor[2] >> 12;
    control_.SetTlsDescriptor(static_cast<int>(entry), descriptor[1], limit);
    return 0;
}


// ---------------------------------------------------------------------------
// Descriptors Darwin does not have
// ---------------------------------------------------------------------------

uint64_t LinuxSyscalls::DoEventfd(uint64_t initial, int flags) {
    constexpr int kEfdSemaphore = 1;
    constexpr int kEfdNonBlock = 0x800;

    // The pipe is not where the value lives -- it is what makes the descriptor visible to
    // poll, select and epoll, which is most of what an eventfd is used for.
    int ends[2] = {-1, -1};
    if (pipe(ends) != 0) {
        return Fail(errno);
    }
    if ((flags & kEfdNonBlock) != 0) {
        fcntl(ends[0], F_SETFL, fcntl(ends[0], F_GETFL, 0) | O_NONBLOCK);
    }
    fcntl(ends[1], F_SETFL, fcntl(ends[1], F_GETFL, 0) | O_NONBLOCK);

    auto counter = std::make_shared<EventCounter>();
    counter->value = initial;
    counter->semaphore = (flags & kEfdSemaphore) != 0;
    counter->signal_write_fd = ends[1];

    constexpr int kEfdCloexec = 0x80000;
    std::scoped_lock lock {shared_->mutex};
    const int fd = RegisterFile(ends[0], "anon_inode:[eventfd]", (flags & kEfdCloexec) != 0);
    shared_->files[fd].event = counter;
    if (initial != 0) {
        const char byte = 1;
        if (write(ends[1], &byte, 1) == 1) {
            counter->signalled = true;
        }
    }
    return static_cast<uint64_t>(fd);
}

// Darwin has no timerfd, but kqueue's EVFILT_TIMER is the same idea with a different
// name, and a kqueue descriptor is readable exactly when one of its timers has fired.
// That is what makes this work at all: the descriptor handed to the guest is a real host
// descriptor that poll, select and our epoll already know how to wait on, so none of them
// need to learn what a timer is.
uint64_t LinuxSyscalls::DoTimerfdCreate(int clock_id, int flags) {
    (void)clock_id;   // CLOCK_MONOTONIC and CLOCK_REALTIME both become a relative kqueue timer.
    const int queue = kqueue();
    if (queue < 0) {
        return Fail(errno);
    }
    constexpr int kTfdCloexec = 0o2000000;
    constexpr int kTfdNonblock = 0o4000;
    if ((flags & kTfdNonblock) != 0) {
        fcntl(queue, F_SETFL, fcntl(queue, F_GETFL, 0) | O_NONBLOCK);
    }
    if ((flags & kTfdCloexec) != 0) {
        fcntl(queue, F_SETFD, FD_CLOEXEC);
    }
    std::scoped_lock lock {shared_->mutex};
    const int fd = RegisterFile(queue, "anon_inode:[timerfd]");
    shared_->files[fd].is_timer = true;
    return static_cast<uint64_t>(fd);
}

uint64_t LinuxSyscalls::DoTimerfdSettime(int fd, int flags, uint64_t new_value,
                                         uint64_t old_value) {
    constexpr int kTfdTimerAbstime = 1;
    const size_t width = config_.guest_is_32bit ? 4 : 8;
    const auto* raw = static_cast<const unsigned char*>(GuestPointer(new_value, width * 4, false));
    if (raw == nullptr) {
        return FailLinux(14);
    }
    const auto field = [&](int index) {
        int64_t value = 0;
        std::memcpy(&value, raw + static_cast<size_t>(index) * width, width);
        return value;
    };
    // struct itimerspec is it_interval then it_value, each a timespec.
    const int64_t interval_ns = field(0) * 1000000000LL + field(1);
    int64_t value_ns = field(2) * 1000000000LL + field(3);

    int host_fd = -1;
    {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(fd);
        if (file == nullptr || !file->is_timer) {
            return FailLinux(9);
        }
        if (old_value != 0) {
            auto* out = static_cast<unsigned char*>(GuestPointer(old_value, width * 4, true));
            if (out != nullptr) {
                const int64_t previous[4] = {file->timer_interval_ns / 1000000000LL,
                                             file->timer_interval_ns % 1000000000LL,
                                             file->timer_value_ns / 1000000000LL,
                                             file->timer_value_ns % 1000000000LL};
                for (int index = 0; index < 4; ++index) {
                    std::memcpy(out + static_cast<size_t>(index) * width, &previous[index], width);
                }
            }
        }
        file->timer_interval_ns = interval_ns;
        file->timer_value_ns = value_ns;
        host_fd = file->host_fd;
    }

    struct kevent change {};
    if (value_ns == 0 && interval_ns == 0) {
        EV_SET(&change, 1, EVFILT_TIMER, EV_DELETE, 0, 0, nullptr);
        kevent(host_fd, &change, 1, nullptr, 0, nullptr);   // Already gone is not an error.
        return 0;
    }
    if ((flags & kTfdTimerAbstime) != 0) {
        struct timespec now {};
        clock_gettime(CLOCK_MONOTONIC, &now);
        const int64_t elapsed = static_cast<int64_t>(now.tv_sec) * 1000000000LL + now.tv_nsec;
        value_ns = value_ns > elapsed ? value_ns - elapsed : 0;
    }
    // A repeating timer is armed at its period, because that is what kqueue repeats at.
    // The first expiry of a repeating timer is almost always the period itself, and a
    // one-shot keeps exactly the delay it asked for.
    const int64_t delay_ns = interval_ns != 0 ? interval_ns : std::max<int64_t>(value_ns, 1);
    EV_SET(&change, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE | (interval_ns != 0 ? 0 : EV_ONESHOT),
           NOTE_NSECONDS, delay_ns, nullptr);
    if (kevent(host_fd, &change, 1, nullptr, 0, nullptr) < 0) {
        return Fail(errno);
    }
    return 0;
}

uint64_t LinuxSyscalls::DoTimerfdGettime(int fd, uint64_t current_value) {
    const size_t width = config_.guest_is_32bit ? 4 : 8;
    auto* out = static_cast<unsigned char*>(GuestPointer(current_value, width * 4, true));
    if (out == nullptr) {
        return FailLinux(14);
    }
    std::scoped_lock lock {shared_->mutex};
    auto* file = FindFile(fd);
    if (file == nullptr || !file->is_timer) {
        return FailLinux(9);
    }
    const int64_t fields[4] = {file->timer_interval_ns / 1000000000LL,
                               file->timer_interval_ns % 1000000000LL,
                               file->timer_value_ns / 1000000000LL,
                               file->timer_value_ns % 1000000000LL};
    for (int index = 0; index < 4; ++index) {
        std::memcpy(out + static_cast<size_t>(index) * width, &fields[index], width);
    }
    return 0;
}

uint64_t LinuxSyscalls::DoTimerfdRead(OpenFile& file, uint64_t buffer) {
    auto* out = static_cast<uint64_t*>(GuestPointer(buffer, sizeof(uint64_t), true));
    if (out == nullptr) {
        return FailLinux(14);
    }
    struct kevent event {};
    const struct timespec immediately {0, 0};
    const int ready = kevent(file.host_fd, nullptr, 0, &event, 1, &immediately);
    if (ready < 0) {
        return Fail(errno);
    }
    if (ready == 0) {
        return FailLinux(11); // EAGAIN: nothing has expired yet.
    }
    // How many times it fired since the last read, which is what timerfd reports.
    *out = event.data > 0 ? static_cast<uint64_t>(event.data) : 1;
    return sizeof(uint64_t);
}

uint64_t LinuxSyscalls::DoEventfdRead(OpenFile& file, uint64_t buffer) {
    auto* out = static_cast<uint64_t*>(GuestPointer(buffer, sizeof(uint64_t), true));
    if (out == nullptr) {
        return FailLinux(14);
    }
    auto counter = file.event;
    std::scoped_lock lock {counter->mutex};
    if (counter->value == 0) {
        return FailLinux(11); // EAGAIN; a blocking read would park here instead.
    }
    if (counter->semaphore) {
        *out = 1;
        counter->value -= 1;
    } else {
        *out = counter->value;
        counter->value = 0;
    }
    if (counter->value == 0 && counter->signalled) {
        char byte = 0;
        (void)read(file.host_fd, &byte, 1);
        counter->signalled = false;
    }
    return sizeof(uint64_t);
}

uint64_t LinuxSyscalls::DoEventfdWrite(OpenFile& file, uint64_t buffer) {
    const auto* in = static_cast<const uint64_t*>(GuestPointer(buffer, sizeof(uint64_t), false));
    if (in == nullptr) {
        return FailLinux(14);
    }
    if (*in == ~0ULL) {
        return FailLinux(22); // The one value the kernel refuses.
    }
    auto counter = file.event;
    std::scoped_lock lock {counter->mutex};
    counter->value += *in;
    if (counter->value != 0 && !counter->signalled) {
        const char byte = 1;
        if (write(counter->signal_write_fd, &byte, 1) == 1) {
            counter->signalled = true;
        }
    }
    return sizeof(uint64_t);
}

uint64_t LinuxSyscalls::DoEpollCreate(int flags) {
    constexpr int kEpollCloexec = 0x80000;
    std::scoped_lock lock {shared_->mutex};
    const int fd = RegisterFile(-1, "anon_inode:[eventpoll]", (flags & kEpollCloexec) != 0);
    shared_->files[fd].epoll = std::make_shared<EpollSet>();
    return static_cast<uint64_t>(fd);
}

uint64_t LinuxSyscalls::DoEpollCtl(int epoll_fd, int operation, int fd, uint64_t event_address) {
    constexpr int kEpollCtlAdd = 1;
    constexpr int kEpollCtlDel = 2;
    constexpr int kEpollCtlMod = 3;

    std::shared_ptr<EpollSet> set;
    {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(epoll_fd);
        if (file == nullptr || file->epoll == nullptr) {
            return FailLinux(9); // EBADF
        }
        if (FindFile(fd) == nullptr) {
            return FailLinux(9);
        }
        set = file->epoll;
    }

    if (operation == kEpollCtlDel) {
        std::scoped_lock lock {set->mutex};
        return set->interests.erase(fd) == 0 ? FailLinux(2) : 0;
    }

    // struct epoll_event is packed on x86: a 32-bit event mask followed by an eight-byte
    // union with no padding between them, on both i386 and x86-64.
    const auto* raw = static_cast<const unsigned char*>(GuestPointer(event_address, 12, false));
    if (raw == nullptr) {
        return FailLinux(14);
    }
    EpollInterest interest;
    std::memcpy(&interest.events, raw, 4);
    std::memcpy(&interest.data, raw + 4, 8);

    std::scoped_lock lock {set->mutex};
    if (operation == kEpollCtlAdd) {
        if (!set->interests.emplace(fd, interest).second) {
            return FailLinux(17); // EEXIST
        }
        return 0;
    }
    if (operation == kEpollCtlMod) {
        auto entry = set->interests.find(fd);
        if (entry == set->interests.end()) {
            return FailLinux(2);
        }
        entry->second = interest;
        return 0;
    }
    return FailLinux(22);
}

uint64_t LinuxSyscalls::DoEpollWait(int epoll_fd, uint64_t events_address, int max_events,
                                    int timeout_ms) {
    if (max_events <= 0) {
        return FailLinux(22);
    }
    std::shared_ptr<EpollSet> set;
    {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(epoll_fd);
        if (file == nullptr || file->epoll == nullptr) {
            return FailLinux(9);
        }
        set = file->epoll;
    }
    auto* out = static_cast<unsigned char*>(
        GuestPointer(events_address, static_cast<uint64_t>(max_events) * 12, true));
    if (out == nullptr) {
        return FailLinux(14);
    }

    constexpr int kSliceMilliseconds = 50;
    const auto waiting = EnterBlockingWait();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms < 0 ? 0 : timeout_ms);
    for (;;) {
        if (ShouldStop()) {
            exit_status_ = -1;
            control_.ExitGuest(-1);
        }

        // A snapshot, so the host poll below runs without either lock held.
        std::vector<std::pair<int, EpollInterest>> watched;
        {
            std::scoped_lock lock {set->mutex};
            watched.assign(set->interests.begin(), set->interests.end());
        }

        std::vector<struct pollfd> host_fds;
        std::vector<const EpollInterest*> owners;
        host_fds.reserve(watched.size());
        owners.reserve(watched.size());
        {
            std::scoped_lock lock {shared_->mutex};
            for (const auto& [guest_fd, interest] : watched) {
                auto* file = FindFile(guest_fd);
                if (file == nullptr || file->host_fd < 0) {
                    continue;
                }
                struct pollfd entry {};
                entry.fd = file->host_fd;
                if ((interest.events & kPollIn) != 0) entry.events |= POLLIN;
                if ((interest.events & kPollOut) != 0) entry.events |= POLLOUT;
                host_fds.push_back(entry);
                owners.push_back(&interest);
            }
        }

        // With a real timeout, not zero. Polling every descriptor with a zero timeout and
        // then sleeping ten milliseconds turns a thread that is waiting quietly for a
        // socket into a thread that wakes a hundred times a second, rebuilds this list and
        // allocates twice -- and Chromium has a dozen threads doing it at once, which was
        // enough to starve the X server in the same session of its own descriptors.
        int slice = 0;
        if (timeout_ms != 0) {
            slice = kSliceMilliseconds;
            if (timeout_ms > 0) {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           deadline - std::chrono::steady_clock::now())
                                           .count();
                slice = static_cast<int>(std::clamp<int64_t>(remaining, 0, kSliceMilliseconds));
            }
        }
        int ready = host_fds.empty() ? 0
                                     : poll(host_fds.data(), static_cast<nfds_t>(host_fds.size()), slice);
        if (ready < 0 && errno != EINTR) {
            return Fail(errno);
        }
        uint64_t reported = 0;
        for (size_t index = 0; index < host_fds.size() && reported < static_cast<uint64_t>(max_events); ++index) {
            uint32_t events = 0;
            if ((host_fds[index].revents & POLLIN) != 0) events |= kPollIn;
            if ((host_fds[index].revents & POLLOUT) != 0) events |= kPollOut;
            if ((host_fds[index].revents & POLLERR) != 0) events |= kPollErr;
            if ((host_fds[index].revents & POLLHUP) != 0) events |= kPollHup;
            if (events == 0) {
                continue;
            }
            std::memcpy(out + reported * 12, &events, 4);
            std::memcpy(out + reported * 12 + 4, &owners[index]->data, 8);
            ++reported;
        }
        if (reported > 0) {
            return reported;
        }
        if (timeout_ms == 0 || (timeout_ms > 0 && std::chrono::steady_clock::now() >= deadline)) {
            return 0;
        }
        // Only when there was nothing to wait on: the host poll above has already done the
        // waiting in every other case.
        if (host_fds.empty()) {
            console_.WaitForInput(kSliceMilliseconds);
        }
    }
}

uint64_t LinuxSyscalls::DoMknodAt(int dirfd, uint64_t path_address, uint32_t mode) {
    std::string path;
    if (!ReadGuestString(path_address, &path)) {
        return FailLinux(14);
    }
    const std::string host_path = ResolveAt(dirfd, path.c_str(), nullptr);
    const uint32_t kind = mode & S_IFMT;

    // Only the two kinds an unprivileged process can actually make. Linux answers EPERM
    // for a device node, which is what a program checks for.
    if (kind == S_IFIFO) {
        return mkfifo(host_path.c_str(), mode & 07777) != 0 ? Fail(errno) : 0;
    }
    if (kind == 0 || kind == S_IFREG) {
        const int fd = open(host_path.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode & 07777);
        if (fd < 0) {
            return Fail(errno);
        }
        close(fd);
        return 0;
    }
    return FailLinux(1); // EPERM
}

uint64_t LinuxSyscalls::DoPrctl(uint64_t option, uint64_t arg2) {
    constexpr uint64_t kPrSetPdeathsig = 1;
    constexpr uint64_t kPrGetDumpable = 3;
    constexpr uint64_t kPrSetDumpable = 4;
    constexpr uint64_t kPrSetName = 15;
    constexpr uint64_t kPrGetName = 16;
    constexpr uint64_t kPrSetPtracer = 0x59616d61;
    constexpr uint64_t kPrSetChildSubreaper = 36;
    constexpr uint64_t kPrSetNoNewPrivs = 38;

    switch (option) {
    case kPrSetName: {
        std::string name;
        if (!ReadGuestString(arg2, &name, 16)) {
            // The kernel takes 16 bytes with no terminator required, so a name that fills
            // the buffer exactly is not an error.
            const auto* raw = static_cast<const char*>(GuestPointer(arg2, 16, false));
            if (raw == nullptr) {
                return FailLinux(14);
            }
            name.assign(raw, 16);
        }
        thread_name_ = std::move(name);
        return 0;
    }
    case kPrGetName: {
        auto* out = static_cast<char*>(GuestPointer(arg2, 16, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::memset(out, 0, 16);
        std::memcpy(out, thread_name_.c_str(), std::min<size_t>(thread_name_.size(), 15));
        return 0;
    }
    case kPrGetDumpable:
        return 1;
    case kPrSetPdeathsig:
    case kPrSetDumpable:
    case kPrSetPtracer:
    case kPrSetChildSubreaper:
    case kPrSetNoNewPrivs:
        // Accepted and ignored: each of these is about how this process relates to a
        // parent, a debugger or the kernel's dumping machinery, none of which exists here.
        return 0;
    default:
        return FailLinux(22); // EINVAL, which is what an unknown option gets on Linux.
    }
}

bool LinuxSyscalls::ProcFileContents(const std::string& guest_path, std::string* out) const {
    // The system-wide files first: these describe the machine rather than this process.
    if (guest_path == "/proc/cpuinfo") {
        // What the guest is actually running on, described in x86's own terms. The
        // features listed are the ones FEXCore emulates and reports through CPUID, so a
        // program that reads this and a program that asks the CPU directly get the same
        // answer. A program refusing to start because this file is missing is common
        // enough to be worth answering properly -- Steam is one.
        const unsigned cores = std::max(1u, std::thread::hardware_concurrency());
        out->clear();
        for (unsigned index = 0; index < cores; ++index) {
            char entry[1024];
            std::snprintf(entry, sizeof(entry),
                          "processor\t: %u\n"
                          "vendor_id\t: AuthenticAMD\n"
                          "cpu family\t: 23\n"
                          "model\t\t: 1\n"
                          "model name\t: Fathom x86-64 (FEXCore on ARM64)\n"
                          "stepping\t: 0\n"
                          "cpu MHz\t\t: 3200.000\n"
                          "cache size\t: 1024 KB\n"
                          "physical id\t: 0\n"
                          "siblings\t: %u\n"
                          "core id\t\t: %u\n"
                          "cpu cores\t: %u\n"
                          "fpu\t\t: yes\n"
                          "fpu_exception\t: yes\n"
                          "cpuid level\t: 13\n"
                          "wp\t\t: yes\n"
                          "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca "
                          "cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext "
                          "fxsr_opt rdtscp lm constant_tsc rep_good nopl cpuid extd_apicid "
                          "pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes "
                          "xsave avx f16c rdrand lahf_lm abm sse4a misalignsse 3dnowprefetch "
                          "bmi1 avx2 bmi2 rdseed adx clflushopt\n"
                          "bugs\t\t:\n"
                          "bogomips\t: 6400.00\n"
                          "clflush size\t: 64\n"
                          "cache_alignment\t: 64\n"
                          "address sizes\t: 48 bits physical, 48 bits virtual\n"
                          "power management:\n\n",
                          index, cores, index, cores);
            out->append(entry);
        }
        return true;
    }
    if (guest_path == "/proc/meminfo") {
        uint64_t total = 0;
        size_t length = sizeof(total);
        if (sysctlbyname("hw.memsize", &total, &length, nullptr, 0) != 0) {
            total = 0;
        }
        uint32_t free_pages = 0;
        length = sizeof(free_pages);
        if (sysctlbyname("vm.page_free_count", &free_pages, &length, nullptr, 0) != 0) {
            free_pages = 0;
        }
        const uint64_t free_bytes = static_cast<uint64_t>(free_pages) *
                                    static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
        char buffer[512];
        std::snprintf(buffer, sizeof(buffer),
                      "MemTotal:       %llu kB\nMemFree:        %llu kB\n"
                      "MemAvailable:   %llu kB\nBuffers:               0 kB\n"
                      "Cached:                0 kB\nSwapTotal:             0 kB\n"
                      "SwapFree:              0 kB\n",
                      static_cast<unsigned long long>(total / 1024),
                      static_cast<unsigned long long>(free_bytes / 1024),
                      static_cast<unsigned long long>(free_bytes / 1024));
        *out = buffer;
        return true;
    }
    // No user namespaces here, and nothing that could make one: there is no kernel to ask.
    // Saying so matters because it is how a program decides whether it can sandbox itself.
    // Steam reads these two before starting its web helper and, finding neither, assumes
    // it can -- and Chromium then refuses to start at all, because a sandbox it cannot
    // build is a sandbox it will not run without.
    if (guest_path == "/proc/sys/kernel/unprivileged_userns_clone" ||
        guest_path == "/proc/sys/user/max_user_namespaces") {
        *out = "0\n";
        return true;
    }
    if (guest_path == "/proc/version") {
        *out = "Linux version 6.6.0-fathom (fathom@fathom) (gcc version 12.2.0) #1 SMP Fathom\n";
        return true;
    }
    if (guest_path == "/proc/uptime") {
        struct timespec now {};
        clock_gettime(CLOCK_MONOTONIC, &now);
        char buffer[128];
        std::snprintf(buffer, sizeof(buffer), "%lld.%02ld %lld.%02ld\n",
                      static_cast<long long>(now.tv_sec), now.tv_nsec / 10'000'000,
                      static_cast<long long>(now.tv_sec), now.tv_nsec / 10'000'000);
        *out = buffer;
        return true;
    }
    if (guest_path == "/proc/filesystems") {
        *out = "nodev\tproc\nnodev\tsysfs\nnodev\ttmpfs\n\text4\n";
        return true;
    }
    if (guest_path == "/proc/mounts" || guest_path == "/etc/mtab") {
        *out = "/dev/root / ext4 rw,relatime 0 0\nproc /proc proc rw,relatime 0 0\n"
               "tmpfs /tmp tmpfs rw,relatime 0 0\n";
        return true;
    }

    // Every process's own numbers, in the one line and the order Linux writes them. Only
    // the fields anything here reads are real: the name, the state, the parent, and
    // zeroes for the rest. Steam's client reads this for its web helper on a timer, and a
    // file that is not there reads as a helper that has died.
    const auto write_stat = [](std::string* text, int pid, int ppid, const std::string& name) {
        char buffer[512];
        std::snprintf(buffer, sizeof(buffer),
                      "%d (%s) S %d %d %d 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 "
                      "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                      pid, name.c_str(), ppid, pid, pid);
        *text = buffer;
    };

    const std::string self_prefix = "/proc/self/";
    const std::string pid_prefix = "/proc/" + std::to_string(pid_) + "/";
    std::string leaf;
    if (guest_path.rfind(self_prefix, 0) == 0) {
        leaf = guest_path.substr(self_prefix.size());
    } else if (guest_path.rfind(pid_prefix, 0) == 0) {
        leaf = guest_path.substr(pid_prefix.size());
    } else if (guest_path.rfind("/proc/", 0) == 0 && host_ != nullptr) {
        // Another process. Only the few fields a liveness check reads are answered.
        const auto rest = guest_path.substr(6);
        const auto slash = rest.find('/');
        if (slash == std::string::npos) {
            return false;
        }
        const std::string number = rest.substr(0, slash);
        if (number.empty() || number.find_first_not_of("0123456789") != std::string::npos) {
            FATHOM_INFO("[pid %d] no answer for %s", pid_, guest_path.c_str());
            return false;
        }
        const int other = std::atoi(number.c_str());
        int other_ppid = 0;
        std::string name;
        if (!host_->DescribeProcess(other, &other_ppid, &name)) {
            return false; // Genuinely gone: ENOENT is the right answer.
        }
        const std::string other_leaf = rest.substr(slash + 1);
        if (other_leaf == "stat") {
            write_stat(out, other, other_ppid, name);
            return true;
        }
        if (other_leaf == "status") {
            char buffer[512];
            std::snprintf(buffer, sizeof(buffer),
                          "Name:\t%s\nState:\tS (sleeping)\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\n"
                          "TracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nThreads:\t1\n",
                          name.c_str(), other, other, other_ppid);
            *out = buffer;
            return true;
        }
        FATHOM_INFO("[pid %d] no answer for %s", pid_, guest_path.c_str());
        return false;
    } else {
        return false;
    }

    if (leaf == "stat") {
        write_stat(out, pid_, ppid_, thread_name_.empty() ? "fathom" : thread_name_);
        return true;
    }
    // A descriptor's own line. Chromium reads these while it decides which descriptors to
    // keep across an exec; the position and flags it finds there do not change what it
    // does, but the file being absent makes it fall back to closing a million of them.
    if (leaf.rfind("fdinfo/", 0) == 0) {
        *out = "pos:\t0\nflags:\t02\nmnt_id:\t1\n";
        return true;
    }

    if (leaf == "cmdline") {
        // NUL-separated, with a trailing NUL: a program splits on it rather than on spaces.
        out->clear();
        for (const auto& argument : command_line_) {
            out->append(argument);
            out->push_back('\0');
        }
        return true;
    }
    if (leaf == "status") {
        char buffer[512];
        std::snprintf(buffer, sizeof(buffer),
                      "Name:\t%s\nState:\tR (running)\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\n"
                      "TracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nThreads:\t1\n",
                      thread_name_.empty() ? "fathom" : thread_name_.c_str(), pid_, pid_, ppid_);
        *out = buffer;
        return true;
    }
    FATHOM_INFO("[pid %d] no answer for %s", pid_, guest_path.c_str());
    return false;
}

void LinuxSyscalls::SetCommandLine(std::vector<std::string> argv) {
    command_line_ = std::move(argv);
    if (thread_name_.empty() && !command_line_.empty()) {
        const auto slash = command_line_.front().rfind('/');
        thread_name_ = slash == std::string::npos ? command_line_.front()
                                                  : command_line_.front().substr(slash + 1);
    }
}

// ---------------------------------------------------------------------------
// System V semaphores
// ---------------------------------------------------------------------------

namespace {

/// Linux and Darwin both inherited System V semaphores, but not its command numbering:
/// GETVAL is 12 on Linux and 5 here, and every other command is shifted too. The flag
/// bits (IPC_CREAT, IPC_EXCL, the permission bits) did carry across and need no mapping.
int ToHostSemctlCommand(int guest_command, bool* supported) {
    *supported = true;
    switch (guest_command & ~0x100 /* IPC_64, which only selects a struct layout */) {
    case 0: return IPC_RMID;
    case 1: return IPC_SET;
    case 2: return IPC_STAT;
    case 11: return GETPID;
    case 12: return GETVAL;
    case 13: return GETALL;
    case 14: return GETNCNT;
    case 15: return GETZCNT;
    case 16: return SETVAL;
    case 17: return SETALL;
    default: *supported = false; return 0;
    }
}

} // namespace

namespace {

/// A System V shared memory segment.
///
/// Sharing memory between guest processes needs no kernel here, because they already
/// share one: every guest process is a thread of this one, in one arena. A segment is a
/// range of that arena, and every process that attaches to it is handed the same guest
/// address -- which is not what Linux promises, but is indistinguishable from it for a
/// caller that asked the kernel to pick the address, and that is every caller X11's
/// MIT-SHM has.
///
/// Doing it this way rather than through Darwin's own System V shm also sidesteps a
/// 4MB default segment limit that a window the size of a screen goes straight past.
struct SharedSegment {
    int32_t key {};
    uint64_t guest_address {};
    uint64_t size {};
    int attachments {};
    bool removed {};
};

std::mutex g_shared_memory_mutex;
std::map<int, SharedSegment> g_shared_segments;
int g_next_shared_id = 1;

} // namespace

uint64_t LinuxSyscalls::DoShmget(int32_t key, uint64_t size, int flags) {
    constexpr int kIpcCreat = 0001000;
    constexpr int kIpcExcl = 0002000;
    constexpr int32_t kIpcPrivate = 0;

    std::scoped_lock lock {g_shared_memory_mutex};
    if (key != kIpcPrivate) {
        for (const auto& [id, segment] : g_shared_segments) {
            if (segment.key != key || segment.removed) {
                continue;
            }
            if ((flags & kIpcCreat) != 0 && (flags & kIpcExcl) != 0) {
                return FailLinux(17); // EEXIST
            }
            if (size != 0 && segment.size < size) {
                return FailLinux(22); // EINVAL: the existing one is too small.
            }
            return static_cast<uint64_t>(id);
        }
        if ((flags & kIpcCreat) == 0) {
            return FailLinux(2); // ENOENT
        }
    }
    if (size == 0) {
        return FailLinux(22);
    }
    const uint64_t host = space_.Allocate(size, 0, kGuestProtRead | kGuestProtWrite);
    if (host == 0) {
        return FailLinux(12); // ENOMEM
    }
    std::memset(reinterpret_cast<void*>(host), 0, size);
    const int id = g_next_shared_id++;
    g_shared_segments[id] = SharedSegment {key, ToGuest(host), size, 0, false};
    return static_cast<uint64_t>(id);
}

uint64_t LinuxSyscalls::DoShmat(int id, uint64_t address, int flags) {
    (void)address;  // The caller's hint; every segment already has one address.
    (void)flags;
    std::scoped_lock lock {g_shared_memory_mutex};
    const auto entry = g_shared_segments.find(id);
    if (entry == g_shared_segments.end()) {
        return FailLinux(22);
    }
    entry->second.attachments += 1;
    return entry->second.guest_address;
}

uint64_t LinuxSyscalls::DoShmdt(uint64_t address) {
    std::scoped_lock lock {g_shared_memory_mutex};
    for (auto entry = g_shared_segments.begin(); entry != g_shared_segments.end(); ++entry) {
        if (entry->second.guest_address != address) {
            continue;
        }
        if (entry->second.attachments > 0) {
            entry->second.attachments -= 1;
        }
        // Linux frees a removed segment once the last attachment goes, not when it was
        // marked -- Xlib relies on exactly that, removing a segment the moment it has
        // attached so a crash cannot leak it.
        if (entry->second.removed && entry->second.attachments == 0) {
            space_.Release(ToHost(entry->second.guest_address), entry->second.size);
            g_shared_segments.erase(entry);
        }
        return 0;
    }
    return FailLinux(22);
}

uint64_t LinuxSyscalls::DoShmctl(int id, int command, uint64_t buffer) {
    constexpr int kIpcRmid = 0;
    constexpr int kIpcStat = 2;

    std::scoped_lock lock {g_shared_memory_mutex};
    const auto entry = g_shared_segments.find(id);
    if (entry == g_shared_segments.end()) {
        return FailLinux(22);
    }
    switch (command & 0xFF) {
    case kIpcRmid:
        entry->second.removed = true;
        if (entry->second.attachments == 0) {
            space_.Release(ToHost(entry->second.guest_address), entry->second.size);
            g_shared_segments.erase(entry);
        }
        return 0;
    case kIpcStat: {
        // Only the size is answered for, at the offset struct shmid_ds keeps it at:
        // after struct ipc_perm, which is 48 bytes on x86-64 and 40 on i386.
        const size_t size_offset = config_.guest_is_32bit ? 40 : 48;
        const size_t width = config_.guest_is_32bit ? 4 : 8;
        auto* out = static_cast<unsigned char*>(GuestPointer(buffer, size_offset + width, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::memcpy(out + size_offset, &entry->second.size, width);
        return 0;
    }
    default:
        return FailLinux(22);
    }
}

uint64_t LinuxSyscalls::DoSemget(int32_t key, int count, int flags) {
    const int id = semget(static_cast<key_t>(key), count, flags);
    return id < 0 ? Fail(errno) : static_cast<uint64_t>(id);
}

uint64_t LinuxSyscalls::DoSemop(int id, uint64_t operations_address, uint64_t count) {
    // struct sembuf is three 16-bit fields on both systems, so it crosses unchanged.
    auto* operations = static_cast<struct sembuf*>(
        GuestPointer(operations_address, count * sizeof(struct sembuf), false));
    if (operations == nullptr) {
        return count == 0 ? 0 : FailLinux(14);
    }
    return semop(id, operations, static_cast<size_t>(count)) != 0 ? Fail(errno) : 0;
}

uint64_t LinuxSyscalls::DoSemctl(int id, int index, int command, uint64_t argument) {
    bool supported = false;
    const int host_command = ToHostSemctlCommand(command, &supported);
    if (!supported) {
        return FailLinux(22); // EINVAL
    }

    switch (host_command) {
    case IPC_RMID:
    case GETPID:
    case GETVAL:
    case GETNCNT:
    case GETZCNT: {
        const int result = semctl(id, index, host_command);
        return result < 0 ? Fail(errno) : static_cast<uint64_t>(result);
    }
    case SETVAL: {
        union semun value {};
        value.val = static_cast<int>(argument);
        return semctl(id, index, SETVAL, value) < 0 ? Fail(errno) : 0;
    }
    case GETALL:
    case SETALL: {
        // The guest hands over an array of unsigned shorts, one per semaphore, which is
        // the same shape here. How many there are is the set's own business, so ask it.
        struct semid_ds description {};
        union semun query {};
        query.buf = &description;
        if (semctl(id, 0, IPC_STAT, query) < 0) {
            return Fail(errno);
        }
        const uint64_t count = description.sem_nsems;
        auto* values = static_cast<unsigned short*>(
            GuestPointer(argument, count * sizeof(unsigned short), host_command == GETALL));
        if (values == nullptr) {
            return FailLinux(14);
        }
        union semun value {};
        value.array = values;
        return semctl(id, 0, host_command, value) < 0 ? Fail(errno) : 0;
    }
    case IPC_STAT: {
        struct semid_ds description {};
        union semun query {};
        query.buf = &description;
        if (semctl(id, 0, IPC_STAT, query) < 0) {
            return Fail(errno);
        }
        // Linux's struct semid64_ds: struct ipc64_perm, then three time_t-sized words and
        // the semaphore count. Written field by field at 64-bit offsets, the same way
        // every other structure in this file is.
        auto* out = static_cast<unsigned char*>(GuestPointer(argument, 104, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::memset(out, 0, 104);
        const auto put32 = [&](size_t offset, uint32_t value) { std::memcpy(out + offset, &value, 4); };
        const auto put64 = [&](size_t offset, uint64_t value) { std::memcpy(out + offset, &value, 8); };
        put32(0, static_cast<uint32_t>(description.sem_perm._key));  // key
        put32(4, description.sem_perm.uid);
        put32(8, description.sem_perm.gid);
        put32(12, description.sem_perm.cuid);
        put32(16, description.sem_perm.cgid);
        put32(20, description.sem_perm.mode);
        put64(64, static_cast<uint64_t>(description.sem_otime));
        put64(80, static_cast<uint64_t>(description.sem_ctime));
        put64(96, description.sem_nsems);
        return 0;
    }
    default:
        return FailLinux(22);
    }
}

uint64_t LinuxSyscalls::DoIpc(uint64_t call, uint64_t first, uint64_t second, uint64_t third,
                             uint64_t pointer) {
    // i386 reaches all of System V IPC through this one entry point, the way it once
    // reached all of sockets through socketcall.
    constexpr uint64_t kSemop = 1;
    constexpr uint64_t kSemget = 2;
    constexpr uint64_t kSemctl = 3;
    constexpr uint64_t kSemtimedop = 4;
    constexpr uint64_t kShmat = 21;
    constexpr uint64_t kShmdt = 22;
    constexpr uint64_t kShmget = 23;
    constexpr uint64_t kShmctl = 24;

    switch (call & 0xFFFF) {
    case kShmat: {
        // sys_ipc does not return the address: it writes it through `third` and returns
        // zero, which is the one place shmat's signature differs from every other libc.
        const uint64_t result = DoShmat(static_cast<int>(first), pointer,
                                        static_cast<int>(second));
        if (static_cast<int64_t>(result) < 0 && static_cast<int64_t>(result) > -4096) {
            return result;
        }
        auto* out = static_cast<uint32_t*>(GuestPointer(third, sizeof(uint32_t), true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        *out = static_cast<uint32_t>(result);
        return 0;
    }
    case kShmdt:
        return DoShmdt(pointer);
    case kShmget:
        return DoShmget(static_cast<int32_t>(first), second, static_cast<int>(third));
    case kShmctl:
        return DoShmctl(static_cast<int>(first), static_cast<int>(second), pointer);
    case kSemop:
    case kSemtimedop:
        // The timeout is ignored: semop blocks until it can proceed, which is the same
        // thing for every caller that does not actually set one.
        return DoSemop(static_cast<int>(first), pointer, second);
    case kSemget:
        return DoSemget(static_cast<int32_t>(first), static_cast<int>(second),
                        static_cast<int>(third));
    case kSemctl: {
        // The fourth argument arrives indirectly: `pointer` points at the union, it is
        // not the union. This is a quirk of sys_ipc, not of semctl.
        if (pointer == 0) {
            return FailLinux(22);
        }
        const auto* slot = static_cast<const uint32_t*>(GuestPointer(pointer, 4, false));
        if (slot == nullptr) {
            return FailLinux(14);
        }
        return DoSemctl(static_cast<int>(first), static_cast<int>(second),
                        static_cast<int>(third), *slot);
    }
    default:
        FATHOM_WARN("unimplemented System V IPC call %llu", static_cast<unsigned long long>(call));
        return FailLinux(38);
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

uint64_t LinuxSyscalls::Handle(uint64_t number, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                               uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    // Marks this thread as being inside the syscall layer for as long as it is, so that a
    // fork elsewhere in this process knows not to freeze it here -- it may be holding a
    // lock the forking child is about to need.
    in_runtime_.store(true, std::memory_order_release);
    struct LeaveRuntime {
        std::atomic<bool>* flag;
        ~LeaveRuntime() { flag->store(false, std::memory_order_release); }
    } leave_runtime {&in_runtime_};

    // An i386 guest numbers its syscalls entirely differently -- its 4 is write, where
    // x86-64's 4 is stat -- so the number is translated before anything looks at it, and
    // one implementation of each syscall serves both.
    if (config_.guest_is_32bit) {
        // Counted before the special cases below, not after: each of them returns without
        // reaching the common path, so leaving this until later makes every socket and
        // System V call invisible to the counter -- and a guest spinning on them looks
        // like a guest making no syscalls at all, which is a very misleading thing to see
        // while chasing a hang.
        if (number == kI386SetThreadArea || number == kI386Socketcall || number == kI386Ipc) {
            console_.NoteSyscall();
            // The crash handler keeps its own copy, and it is the one a state dump reads.
            NoteSyscall(number, arg1, console_.SyscallCount());
        }
        if (number == kI386SetThreadArea) {
            // x86-64 has no equivalent: a 64-bit guest sets its TLS pointer with
            // arch_prctl, so there is no number to translate this into.
            return DoSetThreadArea(arg1);
        }
        if (number == kI386Socketcall) {
            return DoSocketcall(arg1, arg2);
        }
        if (number == kI386Llseek) {
            console_.NoteSyscall();
            NoteSyscall(number, arg1, console_.SyscallCount());
            return DoLlseek(static_cast<int>(arg1), static_cast<uint32_t>(arg2),
                            static_cast<uint32_t>(arg3), arg4, static_cast<int>(arg5));
        }
        if (number == kI386Ipc) {
            return DoIpc(arg1, arg2, arg3, arg4, arg5);
        }
        if (number == kI386Mmap2) {
            // The only argument difference that matters here: mmap2 counts its offset in
            // 4096-byte pages so that a 32-bit register can address a large file.
            arg6 *= 4096;
        }
        // i386 kept its original 32-bit time_t syscalls and gained _time64 versions
        // beside them; glibc uses whichever the kernel offers. They translate to the same
        // x86-64 number, so which one was called is the only thing that says how wide the
        // structures are, and it has to be remembered before the number is lost.
        narrow_time_ = IsI386NarrowTime(number);

        const int64_t translated = X86_64SyscallForI386(number);
        if (translated < 0) {
            FATHOM_WARN("unimplemented i386 syscall %llu (%#llx, %#llx, %#llx, %#llx, %#llx)",
                        static_cast<unsigned long long>(number), static_cast<unsigned long long>(arg1),
                        static_cast<unsigned long long>(arg2), static_cast<unsigned long long>(arg3),
                        static_cast<unsigned long long>(arg4), static_cast<unsigned long long>(arg5));
            return FailLinux(38);
        }
        number = static_cast<uint64_t>(translated);
    }

    console_.NoteSyscall();

    if (ShouldStop()) {
        // Every syscall is a safe point to unwind from, which is what makes "stop" feel
        // immediate for anything that talks to the outside world at all.
        exit_status_ = -1;
        control_.ExitGuest(-1);
    }

    const auto count = console_.SyscallCount();
    NoteSyscall(number, arg1, count);

    if (config_.trace) {
        // The pid matters more than anything else on this line once there is more than
        // one process: the same syscall from a shell and from its child mean opposite
        // things, and without it a pipeline's trace is unreadable.
        FATHOM_INFO("[pid %d] %#llx syscall %llu %s(%#llx, %#llx, %#llx)", pid_,
                    static_cast<unsigned long long>(control_.GuestRip()),
                    static_cast<unsigned long long>(number), SyscallName(number),
                    static_cast<unsigned long long>(arg1),
                    static_cast<unsigned long long>(arg2), static_cast<unsigned long long>(arg3));
    }

    current_argument_.store(arg1, std::memory_order_relaxed);
    current_syscall_.store(number, std::memory_order_relaxed);
    const auto result = Dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6);
    current_syscall_.store(0, std::memory_order_relaxed);

    if (!config_.trace) {
        // Every refusal, without the volume of a full trace. A guest that gives up rather
        // than crashing almost always did so because something answered it with an error,
        // and the ones that are part of normal operation -- a would-block, a file that is
        // meant to be absent -- are the only ones worth leaving out.
        // EAGAIN, ENOENT, EEXIST, EINTR and ETIMEDOUT are all part of working normally --
        // a would-block, a file meant to be absent, a wait that ran out. A single Steam
        // launch times out on futexes tens of thousands of times, and formatting a line
        // for each of them costs more than the syscalls do.
        const auto failed = static_cast<int64_t>(result);
        if (failed < 0 && failed > -4096 && failed != -11 && failed != -2 && failed != -17 &&
            failed != -4 && failed != -110) {
            FATHOM_INFO("[pid %d] %llu %s(%#llx, %#llx, %#llx) failed: errno %lld", pid_,
                        static_cast<unsigned long long>(number),
                        SyscallName(number), static_cast<unsigned long long>(arg1),
                        static_cast<unsigned long long>(arg2),
                        static_cast<unsigned long long>(arg3), static_cast<long long>(-failed));
        }
    }

    if (config_.trace) {
        // The return value is the half that actually explains a stall: a syscall that
        // was reached and refused looks identical to one that was never reached unless
        // the answer is logged too.
        const auto signed_result = static_cast<int64_t>(result);
        if (signed_result < 0 && signed_result > -4096) {
            FATHOM_INFO("[pid %d]   -> error %lld", pid_, static_cast<long long>(-signed_result));
        } else {
            FATHOM_INFO("[pid %d]   -> %#llx", pid_, static_cast<unsigned long long>(result));
        }
    }
    return result;
}

namespace {

/// Each futex operation this layer does not implement, named once. Seen repeatedly in a
/// log it would be noise; seen once it is the first thing to look at when a guest's
/// locking goes wrong.
void ReportUnimplementedFutex(int operation) {
    static std::mutex mutex;
    static std::set<int> reported;
    std::scoped_lock lock {mutex};
    if (reported.insert(operation).second) {
        FATHOM_WARN("futex operation %d is not implemented", operation);
    }
}

} // namespace

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
        // Closing stdio has to really close it. A program redirects by closing fd 1 and
        // then dup'ing a pipe onto it, relying on dup returning the lowest free number:
        // leaving fd 1 occupied hands back some other descriptor, the program finds its
        // output is not where it put it, and it aborts. The console entries carry no host
        // descriptor, so removing one costs the app nothing.
        const int fd = static_cast<int>(arg1);
        std::scoped_lock lock {shared_->mutex};
        if (FindFile(fd) == nullptr) {
            return FailLinux(9);
        }
        CloseFd(fd);
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
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        // An i386 guest's off_t is 32 bits and arrives in a register whose upper half is
        // not defined, so it has to be taken as a signed 32-bit value. Read as 64 bits, a
        // backwards seek becomes an enormous forwards one and the call fails.
        const off_t offset = config_.guest_is_32bit
                                 ? static_cast<off_t>(static_cast<int32_t>(arg2))
                                 : static_cast<off_t>(arg2);
        const off_t position = lseek(file->host_fd, offset, static_cast<int>(arg3));
        return position < 0 ? Fail(errno) : static_cast<uint64_t>(position);
    }

    case kSysPread64: {
        void* data = GuestPointer(arg2, arg3, true);
        if (data == nullptr) {
            return arg3 == 0 ? 0 : FailLinux(14);
        }
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        const ssize_t bytes = pread(file->host_fd, data, arg3, static_cast<off_t>(arg4));
        return bytes < 0 ? Fail(errno) : static_cast<uint64_t>(bytes);
    }

    case kSysPwrite64: {
        const void* data = GuestPointer(arg2, arg3, false);
        if (data == nullptr) {
            return arg3 == 0 ? 0 : FailLinux(14);
        }
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        const ssize_t bytes = pwrite(file->host_fd, data, arg3, static_cast<off_t>(arg4));
        return bytes < 0 ? Fail(errno) : static_cast<uint64_t>(bytes);
    }

    // An anonymous file, which is how Chromium -- and so Steam's web helper -- makes the
    // shared memory it passes between its processes. Darwin has no memfd, so this is a
    // file in the host's temporary directory that is unlinked the moment it exists: what
    // is left is a descriptor onto storage with no name, which is what memfd is. Sealing
    // is not emulated; nothing that uses it here depends on a seal being refused.
    case kSysMemfdCreate: {
        const char* wanted = static_cast<const char*>(GuestPointer(arg1, 1, false));
        std::string name = wanted == nullptr ? "guest" : std::string {wanted};
        const char* directory = getenv("TMPDIR");
        std::string pattern = (directory == nullptr ? "/tmp/" : std::string {directory} + "/") +
                              "fathom-memfd-XXXXXX";
        std::vector<char> path {pattern.begin(), pattern.end()};
        path.push_back('\0');
        const int fd = mkstemp(path.data());
        if (fd < 0) {
            return Fail(errno);
        }
        unlink(path.data());
        std::scoped_lock lock {shared_->mutex};
        return static_cast<uint64_t>(RegisterFile(fd, "memfd:" + name));
    }

    // Darwin has no fallocate. What callers here want is for the file to be at least
    // offset+length long -- Chromium sizes its shared memory this way -- and truncating
    // up does exactly that. FALLOC_FL_KEEP_SIZE asks for space without changing the
    // length, which on a file that is already long enough is nothing to do.
    case kSysFallocate: {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        const uint64_t wanted_end = arg3 + arg4;
        struct stat info {};
        if (fstat(file->host_fd, &info) != 0) {
            return Fail(errno);
        }
        if ((arg2 & 1) == 0 && static_cast<uint64_t>(info.st_size) < wanted_end) {
            if (ftruncate(file->host_fd, static_cast<off_t>(wanted_end)) != 0) {
                return Fail(errno);
            }
        }
        return 0;
    }

    case kSysReadv:
        return DoReadv(static_cast<int>(arg1), arg2, arg3);
    case kSysWritev:
        return DoWritev(static_cast<int>(arg1), arg2, arg3);

    case kSysMmap:
        return DoMmap(arg1, arg2, static_cast<int>(arg3), static_cast<int>(arg4),
                      static_cast<int>(arg5), static_cast<int64_t>(arg6));

    case kSysMunmap: {
        const uint64_t host_address = ToHost(arg1);
        {
            std::scoped_lock lock {shared_->mutex};
            std::erase_if(shared_->mappings, [&](const auto& entry) {
                return entry.first >= host_address && entry.first + entry.second <= host_address + arg2;
            });
        }
        return space_.Release(host_address, arg2) ? 0 : FailLinux(22);
    }

    case kSysMprotect: {
        int guest_protection = 0;
        if ((arg3 & guest::kProtRead) != 0) guest_protection |= kGuestProtRead;
        if ((arg3 & guest::kProtWrite) != 0) guest_protection |= kGuestProtWrite;
        if ((arg3 & guest::kProtExec) != 0) guest_protection |= kGuestProtExec;
        return space_.Protect(ToHost(arg1), arg2, guest_protection) ? 0 : FailLinux(22);
    }

    case kSysMremap: {
        constexpr uint64_t kMremapMayMove = 1;
        const uint64_t old_address = ToHost(arg1);
        const uint64_t old_size = arg2;
        const uint64_t new_size = arg3;
        const uint64_t flags = arg4;

        if (new_size <= old_size) {
            return arg1;
        }
        // Without MREMAP_MAYMOVE the caller has said the mapping must not move, and Linux
        // answers ENOMEM rather than relocating it. Moving anyway hands back an address
        // the caller never agreed to, and anything still holding a pointer into the old
        // mapping is now pointing at released memory.
        if ((flags & kMremapMayMove) == 0) {
            return FailLinux(12); // ENOMEM
        }

        const uint64_t placed = space_.Allocate(new_size, 0, kGuestProtRead | kGuestProtWrite);
        if (placed == 0) {
            return FailLinux(12);
        }
        std::memcpy(reinterpret_cast<void*>(placed), reinterpret_cast<const void*>(old_address), old_size);
        // The part past the old end is fresh anonymous memory, which Linux guarantees
        // reads as zero.
        std::memset(reinterpret_cast<uint8_t*>(placed) + old_size, 0, new_size - old_size);
        space_.Release(old_address, old_size);
        return ToGuest(placed);
    }

    case kSysBrk:
        return DoBrk(arg1);

    case kSysMincore: {
        // One byte per guest page, low bit set when the page is resident. Every arena
        // page is, so the answer is uniform -- but it has to actually be written, because
        // the caller reads the vector rather than the return value.
        const uint64_t pages = (arg2 + guest::kPageSize - 1) / guest::kPageSize;
        auto* out = static_cast<unsigned char*>(GuestPointer(arg3, pages, true));
        if (out == nullptr) {
            return pages == 0 ? 0 : FailLinux(14);
        }
        std::memset(out, 1, pages);
        return 0;
    }

    case kSysMadvise:
    case kSysMsync:
    case kSysFsync:
    case kSysFdatasync:
    // Guest memory is never paged out, so locking it is already true.
    case kSysMlock:
    case kSysMunlock:
    case kSysMlockall:
    case kSysMunlockall:
        return 0;

    case kSysIoctl: {
        const int fd = static_cast<int>(arg1);
        bool is_display = false;
        {
            std::scoped_lock lock {shared_->mutex};
            auto* file = FindFile(fd);
            is_display = file != nullptr && file->is_framebuffer;
        }
        if (is_display) {
            return DoFramebufferIoctl(arg2, arg3);
        }

        // The descriptor-level ioctls, which are not terminal ioctls at all and are
        // numbered differently on the two systems. FIONBIO is the one that matters most:
        // it is how a program that does not use fcntl puts a socket into non-blocking
        // mode, and answering it with ENOTTY tells that program its socket is unusable.
        // Steam sets up every connection this way and reports "needs to be online" when
        // it fails.
        constexpr uint64_t kGuestFionread = 0x541B;
        constexpr uint64_t kGuestFionbio = 0x5421;
        constexpr uint64_t kGuestFioasync = 0x5452;
        constexpr uint64_t kGuestFioclex = 0x5451;
        constexpr uint64_t kGuestFionclex = 0x5450;
        if (arg2 == kGuestFionread || arg2 == kGuestFionbio || arg2 == kGuestFioasync ||
            arg2 == kGuestFioclex || arg2 == kGuestFionclex) {
            const int host_fd = HostFdFor(fd);
            if (host_fd < 0) {
                // The console has no host descriptor; it is never in a mode these change.
                return IsConsole(fd) ? 0 : FailLinux(9);
            }
            if (arg2 == kGuestFioclex || arg2 == kGuestFionclex) {
                return fcntl(host_fd, F_SETFD, arg2 == kGuestFioclex ? FD_CLOEXEC : 0) < 0 ? Fail(errno)
                                                                                           : 0;
            }
            auto* value = static_cast<int32_t*>(
                GuestPointer(arg3, sizeof(int32_t), arg2 == kGuestFionread));
            if (value == nullptr) {
                return FailLinux(14);
            }
            const unsigned long host_request = arg2 == kGuestFionread  ? FIONREAD
                                               : arg2 == kGuestFionbio ? FIONBIO
                                                                       : FIOASYNC;
            int argument = *value;
            if (ioctl(host_fd, host_request, &argument) < 0) {
                return Fail(errno);
            }
            if (arg2 == kGuestFionread) {
                *value = argument;
            }
            return 0;
        }
        if (IsConsole(fd) && arg2 == guest::kTcgets) {
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
        if (IsConsole(fd) &&
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
            const bool was_raw = console_.WantsKeys();
            console_.SetRawMode(raw);
            if (raw != was_raw) {
                FATHOM_INFO("guest terminal mode: %s", raw ? "raw (wants individual keys)" : "canonical");
            }
            return 0;
        }
        if (IsConsole(fd) && arg2 == guest::kTiocgwinsz) {
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
        std::scoped_lock lock {shared_->mutex};
        if (shared_->cwd.size() + 1 > arg2) {
            return FailLinux(34); // ERANGE
        }
        std::memcpy(out, shared_->cwd.c_str(), shared_->cwd.size() + 1);
        return shared_->cwd.size() + 1;
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
        std::scoped_lock lock {shared_->mutex};
        shared_->cwd = guest_path;
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
        // Not followed: unlink removes the link, not what it points at. Resolving through
        // it deletes the target and leaves the link behind, so a directory being emptied
        // never empties and its rmdir fails with ENOTEMPTY for ever after.
        const std::string host_path = ResolveAt(is_at ? static_cast<int>(arg1) : guest::kAtFdCwd,
                                                path.c_str(), nullptr, false);
        const bool remove_directory = is_at && (arg3 & 0x200) != 0; // AT_REMOVEDIR
        const int result = remove_directory ? rmdir(host_path.c_str()) : unlink(host_path.c_str());
        if (result == 0) {
            return 0;
        }
        // Darwin refuses to unlink a directory with EPERM; Linux says EISDIR, and a caller
        // walking a tree branches on exactly that to decide whether to recurse. Told
        // EPERM it concludes it is not allowed to delete anything and gives up.
        if (!remove_directory && errno == EPERM) {
            struct stat info {};
            if (lstat(host_path.c_str(), &info) == 0 && S_ISDIR(info.st_mode)) {
                return FailLinux(21); // EISDIR
            }
        }
        return Fail(errno);
    }

    case kSysRmdir: {
        std::string path;
        if (!ReadGuestString(arg1, &path)) {
            return FailLinux(14);
        }
        return rmdir(ResolveGuestPath(path).c_str()) == 0 ? 0 : Fail(errno);
    }

    case kSysFtruncate: {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        return ftruncate(file->host_fd, static_cast<off_t>(arg2)) == 0 ? 0 : Fail(errno);
    }

    case kSysFcntl: {
        constexpr int kGuestFDupfd = 0;
        constexpr int kGuestFGetfd = 1;
        constexpr int kGuestFSetfd = 2;
        constexpr int kGuestFGetfl = 3;
        constexpr int kGuestFSetfl = 4;
        constexpr int kGuestFDupfdCloexec = 1030;
        const int fd = static_cast<int>(arg1);
        const int command = static_cast<int>(arg2);

        if (command == kGuestFSetfl && fd == 0) {
            const bool nonblocking = (arg3 & guest::kONonBlock) != 0;
            console_.SetNonblockingStdin(nonblocking);
            return 0;
        }
        if (command == kGuestFDupfd || command == kGuestFDupfdCloexec) {
            std::scoped_lock lock {shared_->mutex};
            auto* file = FindFile(fd);
            if (file == nullptr) {
                return FailLinux(9);
            }
            return static_cast<uint64_t>(DuplicateTo(*file, AllocateFd()));
        }
        // Close-on-exec, kept and answered honestly. What it controls -- which
        // descriptors survive an exec -- decides whether a program that passes one end of
        // a socket pair to a child ever sees the other end close.
        constexpr uint64_t kGuestFdCloexec = 1;
        if (command == kGuestFGetfd) {
            std::scoped_lock lock {shared_->mutex};
            auto* file = FindFile(fd);
            return file != nullptr && file->close_on_exec ? kGuestFdCloexec : 0;
        }
        if (command == kGuestFSetfd) {
            // Anything this process has open, whether or not it is backed by a host
            // descriptor. An epoll set, an eventfd and a timer are all real descriptors to
            // the guest and have none of their own here, and answering "bad descriptor"
            // for them makes a library that marks its own descriptors close-on-exec --
            // libevent does, on every one it creates -- believe they were never opened.
            {
                std::scoped_lock lock {shared_->mutex};
                auto* file = FindFile(fd);
                if (file != nullptr) {
                    file->close_on_exec = (arg3 & kGuestFdCloexec) != 0;
                    return 0;
                }
            }
            if (IsConsole(fd)) {
                return 0;
            }
            // Said once per process: a descriptor a program believes it has and this
            // table does not is how a program that was handed a socket ends up talking to
            // nobody. The list says which ones it does have.
            if (!reported_missing_fd_) {
                reported_missing_fd_ = true;
                std::string open_fds;
                {
                    std::scoped_lock lock {shared_->mutex};
                    for (const auto& [number, file] : shared_->files) {
                        open_fds += std::to_string(number);
                        open_fds += ' ';
                    }
                }
                FATHOM_WARN("[pid %d] fd %d is not open here; open: %s", pid_, fd,
                            open_fds.c_str());
            }
            return FailLinux(9);
        }

        // F_GETFL and F_SETFL are about the open file description, and they have to be
        // real: a program that sets O_NONBLOCK and is told it succeeded, but whose
        // descriptor still blocks, deadlocks the first time it writes more than the
        // socket buffer holds and waits for a short write that never comes.
        const int host_fd = HostFdFor(fd);
        if (host_fd < 0) {
            // The console, an epoll set, an eventfd, a timer: real to the guest, with no
            // host descriptor of their own. Read-write and blocking is the truthful answer
            // for all of them.
            bool known = IsConsole(fd);
            if (!known) {
                std::scoped_lock lock {shared_->mutex};
                known = shared_->files.count(fd) != 0;
            }
            return known ? (command == kGuestFGetfl ? 2 : 0) : FailLinux(9);
        }
        if (command == kGuestFGetfl) {
            const int host_flags = fcntl(host_fd, F_GETFL, 0);
            if (host_flags < 0) {
                return Fail(errno);
            }
            int guest_flags = host_flags & O_ACCMODE;
            if ((host_flags & O_NONBLOCK) != 0) guest_flags |= guest::kONonBlock;
            if ((host_flags & O_APPEND) != 0) guest_flags |= guest::kOAppend;
            return static_cast<uint64_t>(guest_flags);
        }
        if (command == kGuestFSetfl) {
            int host_flags = fcntl(host_fd, F_GETFL, 0);
            if (host_flags < 0) {
                return Fail(errno);
            }
            // Only these two are settable after the fact; the rest of the word describes
            // how the file was opened and the kernel ignores changes to it.
            host_flags &= ~(O_NONBLOCK | O_APPEND);
            if ((arg3 & guest::kONonBlock) != 0) host_flags |= O_NONBLOCK;
            if ((arg3 & guest::kOAppend) != 0) host_flags |= O_APPEND;
            return fcntl(host_fd, F_SETFL, host_flags) < 0 ? Fail(errno) : 0;
        }
        return 0;
    }

    case kSysDup: {
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        return static_cast<uint64_t>(DuplicateTo(*file, AllocateFd()));
    }

    case kSysDup2:
    case kSysDup3: {
        const int from = static_cast<int>(arg1);
        const int to = static_cast<int>(arg2);
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(from);
        if (file == nullptr) {
            return FailLinux(9);
        }
        if (from == to) {
            return static_cast<uint64_t>(to);
        }
        // Whatever was on the target goes, silently: this is how a shell puts a pipe on
        // stdout, and the descriptor it is replacing is usually the console.
        CloseFd(to);
        return static_cast<uint64_t>(DuplicateTo(*file, to));
    }

    case kSysPipe:
    case kSysPipe2: {
        int ends[2] = {-1, -1};
        if (pipe(ends) != 0) {
            return Fail(errno);
        }
        if (number == kSysPipe2 && (arg2 & guest::kONonBlock) != 0) {
            fcntl(ends[0], F_SETFL, fcntl(ends[0], F_GETFL, 0) | O_NONBLOCK);
            fcntl(ends[1], F_SETFL, fcntl(ends[1], F_GETFL, 0) | O_NONBLOCK);
        }
        auto* out = static_cast<int32_t*>(GuestPointer(arg1, sizeof(int32_t) * 2, true));
        if (out == nullptr) {
            close(ends[0]);
            close(ends[1]);
            return FailLinux(14);
        }
        const bool cloexec = number == kSysPipe2 && (arg2 & guest::kOCloExec) != 0;
        std::scoped_lock lock {shared_->mutex};
        out[0] = static_cast<int32_t>(RegisterFile(ends[0], "pipe:[read]", cloexec));
        out[1] = static_cast<int32_t>(RegisterFile(ends[1], "pipe:[write]", cloexec));
        return 0;
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

    case kSysClockGetres:
        WriteGuestTimespec(arg2, 0, 1);
        return 0;

    case kSysGettimeofday: {
        // Same shape as a timespec, and the same pair of widths: a timeval is a time_t
        // and a suseconds_t, both of which narrow together on i386.
        struct timeval host {};
        gettimeofday(&host, nullptr);
        return WriteGuestTimespec(arg1, host.tv_sec, host.tv_usec) ? 0 : FailLinux(14);
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
        constexpr int kTimerAbstime = 1;
        const uint64_t request_address = number == kSysNanosleep ? arg1 : arg3;
        int64_t seconds = 0;
        int64_t nanoseconds = 0;
        if (!ReadGuestTimespec(request_address, &seconds, &nanoseconds)) {
            return FailLinux(14);
        }
        // clock_nanosleep's TIMER_ABSTIME makes the request a deadline rather than a
        // duration, and sleeping for the deadline itself would be a sleep until the heat
        // death of the universe.
        if (number == kSysClockNanosleep && (static_cast<int>(arg2) & kTimerAbstime) != 0) {
            bool supported = false;
            const clockid_t host_clock = ToHostClock(static_cast<int>(arg1), &supported);
            struct timespec now {};
            clock_gettime(supported ? host_clock : CLOCK_MONOTONIC, &now);
            int64_t remaining_seconds = seconds - now.tv_sec;
            int64_t remaining_nanoseconds = nanoseconds - now.tv_nsec;
            if (remaining_nanoseconds < 0) {
                remaining_nanoseconds += 1'000'000'000;
                --remaining_seconds;
            }
            if (remaining_seconds < 0) {
                return 0; // Already past.
            }
            seconds = remaining_seconds;
            nanoseconds = remaining_nanoseconds;
        }
        struct timespec host {static_cast<time_t>(seconds), static_cast<long>(nanoseconds)};
        // A sleeping thread holds nothing, so it is safe to stop where it stands -- which
        // matters because a fork cannot take a copy of its parent while any thread of that
        // parent is still writing, and Steam's client keeps several threads asleep.
        const auto waiting = EnterBlockingWait();
        nanosleep(&host, nullptr);
        return 0;
    }

    case kSysSchedYield:
        sched_yield();
        return 0;

    // Scheduling, answered rather than refused. Nothing here can change how this host
    // schedules a guest thread -- they are ordinary threads of one process and Darwin
    // decides -- but a program that is told "not implemented" concludes something is
    // seriously wrong: Steam prints a warning for every thread it starts, and Chromium's
    // renderer treats a failed priority change as a reason to log and retry.
    case kSysSetpriority:
    case kSysSchedSetparam:
    case kSysSchedSetscheduler:
        return 0;
    case kSysGetpriority:
        return 20; // nice 0, in the encoding getpriority uses on Linux.
    case kSysSchedGetscheduler:
        return 0; // SCHED_OTHER
    case kSysSchedGetparam: {
        // One field, sched_priority, and it is zero for SCHED_OTHER.
        void* out = GuestPointer(arg2, sizeof(int32_t), true);
        if (out == nullptr) {
            return FailLinux(14);
        }
        const int32_t priority = 0;
        std::memcpy(out, &priority, sizeof(priority));
        return 0;
    }
    case kSysSchedGetPriorityMax:
    case kSysSchedGetPriorityMin:
        // SCHED_OTHER is the only policy here, and its range is zero to zero.
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
        return static_cast<uint64_t>(pid_);
    case kSysGettid:
        return static_cast<uint64_t>(Tid());
    case kSysGetppid:
    case kSysGetpgrp:
        return static_cast<uint64_t>(ppid_);
    case kSysGetuid:
    case kSysGeteuid:
    case kSysGetgid:
    case kSysGetegid:
        return 1000;
    // The guest is uid 1000 and stays that way. Setting it to what it already is
    // succeeds, which is what busybox does at startup; anything else is EPERM, the same
    // answer an unprivileged process gets on Linux. ENOSYS was simply the wrong error.
    case kSysSetuid:
    case kSysSetgid:
        return arg1 == 1000 ? 0 : FailLinux(1);

    // The same bargain for the three-argument forms, where -1 means "leave this one
    // alone". An X server calls these to drop privileges it was never given.
    case kSysSetresuid:
    case kSysSetresgid: {
        const auto unchanged_or_self = [](uint64_t value) {
            return value == ~0ULL || static_cast<uint32_t>(value) == 0xFFFF'FFFFU || value == 1000;
        };
        return unchanged_or_self(arg1) && unchanged_or_self(arg2) && unchanged_or_self(arg3)
                   ? 0
                   : FailLinux(1);
    }
    case kSysGetresuid:
    case kSysGetresgid: {
        // Real, effective and saved, all the same and all writable separately.
        for (uint64_t address : {arg1, arg2, arg3}) {
            auto* out = static_cast<uint32_t*>(GuestPointer(address, sizeof(uint32_t), true));
            if (out == nullptr) {
                return FailLinux(14);
            }
            *out = 1000;
        }
        return 0;
    }

    // There is one process group and one session here, and the guest is in it. Accepting
    // these rather than refusing them matters: a server that cannot detach from its
    // terminal treats that as fatal.
    case kSysSetpgid:
    case kSysSetsid:
        return 0;
    case kSysGetpgid:
    case kSysGetsid:
        return static_cast<uint64_t>(pid_);

    case kSysUmask:
        return 0022;

    case kSysSetTidAddress:
        clear_child_tid_ = arg1;
        return static_cast<uint64_t>(Tid());

    case kSysSetRobustList:
        robust_list_head_ = arg1;
        robust_list_size_ = arg2;
        return 0;

    case kSysGetRobustList: {
        // Answered properly, not just accepted. glibc's pthreads registers a robust-mutex
        // list at thread start and some programs read it back to confirm the thread is
        // set up; told it is empty, they treat the thread as broken and abort with
        // "futex robust_list not initialized by pthreads".
        const size_t width = config_.guest_is_32bit ? 4 : 8;
        auto* head = static_cast<unsigned char*>(GuestPointer(arg2, width, true));
        auto* length = static_cast<unsigned char*>(GuestPointer(arg3, width, true));
        if (head == nullptr || length == nullptr) {
            return FailLinux(14);
        }
        std::memcpy(head, &robust_list_head_, width);
        std::memcpy(length, &robust_list_size_, width);
        return 0;
    }

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
        // struct rlimit's two fields are `unsigned long`, so an i386 guest's is eight
        // bytes and this process's is sixteen. prlimit64 is the exception: it is
        // explicitly 64-bit on both. Writing sixteen bytes into an eight-byte stack
        // buffer lands squarely on the canary, and glibc answers with "stack smashing
        // detected" in whatever function returns next.
        const bool narrow = config_.guest_is_32bit && number == kSysGetrlimit;
        const uint64_t width = narrow ? 4 : 8;
        auto* out = static_cast<unsigned char*>(GuestPointer(out_address, width * 2, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        const uint64_t resource = number == kSysGetrlimit ? arg1 : arg2;
        constexpr uint64_t kRlimitStack = 3;
        constexpr uint64_t kRlimitNofile = 7;
        const uint64_t infinity = narrow ? 0xFFFF'FFFFULL : ~0ULL;
        uint64_t soft = infinity;
        uint64_t hard = infinity;
        if (resource == kRlimitStack) {
            soft = 8ULL * 1024 * 1024;
        } else if (resource == kRlimitNofile) {
            soft = 1024;
            hard = 4096;
        }
        std::memcpy(out, &soft, width);
        std::memcpy(out + width, &hard, width);
        return 0;
    }

    case kSysWaitid: {
        // waitid says the same thing as wait4 and reports it differently: the result comes
        // back in a siginfo rather than in a status word and a return value.
        constexpr uint64_t kPAll = 0;
        constexpr uint64_t kPPid = 1;
        constexpr int kWNoHang = 1;
        if (host_ == nullptr) {
            return FailLinux(38);
        }
        if (arg1 != kPAll && arg1 != kPPid) {
            return FailLinux(22); // Process groups are not a thing here.
        }

        int status = 0;
        const int wanted = arg1 == kPAll ? -1 : static_cast<int>(arg2);
        const int options = (static_cast<int>(arg4) & kWNoHang) != 0 ? kWNoHang : 0;
        // Waiting on a child is waiting: the process table's lock is dropped for the
        // duration, so a fork happening elsewhere may stop this thread where it stands.
        // It is the fork that holds that lock while it stops anything, which is what makes
        // this safe -- a thread cannot be caught having just taken it back.
        const auto waiting = EnterBlockingWait();
        const int64_t reaped = host_->WaitForChild(pid_, wanted, &status, options);
        if (reaped < 0) {
            return static_cast<uint64_t>(reaped);
        }

        if (arg3 != 0) {
            // siginfo_t is 128 bytes on both architectures, but the fields after si_code
            // sit at different offsets: an i386 guest has no padding before them.
            auto* out = static_cast<unsigned char*>(GuestPointer(arg3, 128, true));
            if (out == nullptr) {
                return FailLinux(14);
            }
            std::memset(out, 0, 128);
            const size_t fields = config_.guest_is_32bit ? 12 : 16;
            const auto put = [&](size_t offset, int32_t value) {
                std::memcpy(out + offset, &value, 4);
            };
            constexpr int32_t kSigchld = 17;
            constexpr int32_t kCldExited = 1;
            put(0, kSigchld);              // si_signo
            put(8, kCldExited);            // si_code
            put(fields, static_cast<int32_t>(reaped));       // si_pid
            put(fields + 4, 1000);                           // si_uid
            put(fields + 8, (status >> 8) & 0xFF);           // si_status: the exit code
        }
        // WNOWAIT would mean "leave the child reapable"; nothing here asks for it, and
        // the child has already been reaped by the call above.
        return 0;
    }

    case kSysGetgroups: {
        // One group, which is the guest's own. A caller asking for the count passes zero.
        const int capacity = static_cast<int>(arg1);
        if (capacity == 0) {
            return 1;
        }
        auto* out = static_cast<uint32_t*>(GuestPointer(arg2, sizeof(uint32_t), true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        *out = 1000;
        return 1;
    }
    case kSysSetgroups:
        // There is one group and the guest is already in it.
        return 0;

    case kSysSchedSetaffinity:
        // Accepted and ignored: guest threads are host threads, and which core they run
        // on is the host scheduler's business. Refusing it is not a neutral answer -- a
        // worker pool that cannot pin its threads treats that as a setup failure and
        // stops, which is how Steam's update applier ends without a word.
        return 0;

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
        constexpr int kFutexRequeue = 3;
        constexpr int kFutexCmpRequeue = 4;
        constexpr int kFutexWakeOp = 5;
        constexpr int kFutexLockPi = 6;
        constexpr int kFutexUnlockPi = 7;
        constexpr int kFutexTrylockPi = 8;
        constexpr int kFutexWaitBitset = 9;
        constexpr int kFutexWakeBitset = 10;
        constexpr uint32_t kFutexTidMask = 0x3FFF'FFFFu;
        constexpr uint32_t kFutexWaiters = 0x8000'0000u;
        // The PRIVATE and CLOCK_REALTIME bits change nothing here: every guest thread is
        // a thread of this one host process, so private and shared are the same thing.
        const int operation = static_cast<int>(arg2) & 0x7f;

        switch (operation) {
        case kFutexWake:
        case kFutexWakeBitset:
        case kFutexRequeue:
        case kFutexCmpRequeue: {
            // Requeue moves waiters from one futex to another. Waking them instead is
            // allowed -- a futex waiter must re-check its own condition on waking -- and
            // it avoids keeping a queue per address.
            const uint64_t host_address = ToHost(arg1);
            WakeFutex(host_address);
            if (operation == kFutexRequeue || operation == kFutexCmpRequeue) {
                WakeFutex(ToHost(arg5));
            }
            return arg3;  // How many were woken; the caller only checks for an error.
        }
        case kFutexWakeOp: {
            // Apply an operation to the second word, wake the first futex, and wake the
            // second one too if the value that word held satisfies the comparison. glibc
            // uses this to hand a condition variable's waiters over to its mutex in one
            // call, and answering "woke nobody, changed nothing" leaves that mutex's
            // count describing waiters that were never released.
            auto* second = static_cast<uint32_t*>(GuestPointer(arg5, sizeof(uint32_t), true));
            if (second == nullptr) {
                return FailLinux(14);
            }
            const uint32_t encoded = static_cast<uint32_t>(arg6);
            const uint32_t operation_code = (encoded >> 28) & 0xF;
            const uint32_t comparison = (encoded >> 24) & 0xF;
            uint32_t operand = (encoded >> 12) & 0xFFF;
            const uint32_t against = encoded & 0xFFF;
            constexpr uint32_t kOpargShift = 8;
            if ((operation_code & kOpargShift) != 0) {
                operand = 1u << (operand & 31);
            }
            const uint32_t previous = *second;
            switch (operation_code & 7) {
            case 0: *second = operand; break;              // FUTEX_OP_SET
            case 1: *second = previous + operand; break;    // FUTEX_OP_ADD
            case 2: *second = previous | operand; break;    // FUTEX_OP_OR
            case 3: *second = previous & ~operand; break;   // FUTEX_OP_ANDN
            case 4: *second = previous ^ operand; break;    // FUTEX_OP_XOR
            default: break;
            }
            WakeFutex(ToHost(arg1));
            bool matched = false;
            switch (comparison) {
            case 0: matched = previous == against; break;
            case 1: matched = previous != against; break;
            case 2: matched = previous < against; break;
            case 3: matched = previous <= against; break;
            case 4: matched = previous > against; break;
            case 5: matched = previous >= against; break;
            default: break;
            }
            if (matched) {
                WakeFutex(ToHost(arg5));
            }
            return arg3;
        }
        case kFutexWait:
        case kFutexWaitBitset: {
            const auto* value = static_cast<const uint32_t*>(GuestPointer(arg1, sizeof(uint32_t), false));
            if (value == nullptr) {
                return FailLinux(14);
            }

            // FUTEX_WAIT's timeout is relative; FUTEX_WAIT_BITSET's is absolute. Either
            // way it is optional, and a null pointer means wait indefinitely.
            std::chrono::steady_clock::time_point deadline;
            bool timed = false;
            if (arg4 != 0) {
                const size_t width = config_.guest_is_32bit ? 4 : 8;
                const auto* raw = static_cast<const unsigned char*>(GuestPointer(arg4, width * 2, false));
                if (raw == nullptr) {
                    return FailLinux(14);
                }
                int64_t seconds = 0;
                int64_t nanoseconds = 0;
                std::memcpy(&seconds, raw, width);
                std::memcpy(&nanoseconds, raw + width, width);
                auto interval = std::chrono::seconds(seconds) + std::chrono::nanoseconds(nanoseconds);
                if (operation == kFutexWaitBitset) {
                    // Absolute rather than relative, and against CLOCK_MONOTONIC unless
                    // FUTEX_CLOCK_REALTIME says otherwise. Reading the wrong one is not a
                    // small error: the two epochs are decades apart, so a monotonic
                    // deadline measured against the realtime clock is always already
                    // past, and every wait returns ETIMEDOUT immediately. A guest waiting
                    // for a thread to start up then reports a deadlock.
                    constexpr uint64_t kFutexClockRealtime = 0x100;
                    struct timespec now {};
                    clock_gettime((arg2 & kFutexClockRealtime) != 0 ? CLOCK_REALTIME : CLOCK_MONOTONIC, &now);
                    const auto elapsed = std::chrono::seconds(now.tv_sec) + std::chrono::nanoseconds(now.tv_nsec);
                    interval = interval > elapsed ? interval - elapsed : std::chrono::nanoseconds(0);
                }
                deadline = std::chrono::steady_clock::now() + interval;
                timed = true;
            }

            const auto waiting = EnterBlockingWait();
            auto& queue = FutexQueue(ToHost(arg1));
            std::unique_lock lock {queue.mutex};
            if (*value != static_cast<uint32_t>(arg3)) {
                return FailLinux(11); // EAGAIN: the value moved, which is the common case.
            }
            const uint64_t seen = queue.generation;
            for (;;) {
                if (ShouldStop()) {
                    lock.unlock();
                    exit_status_ = -1;
                    control_.ExitGuest(-1);
                }
                // Woken by a FUTEX_WAKE, or by the value changing under us. Either way the
                // caller re-checks its own condition, which is what the API promises.
                if (queue.generation != seen || *value != static_cast<uint32_t>(arg3)) {
                    return 0;
                }
                // Bounded, so that a stop request is noticed and so that a wake this
                // layer never saw -- a value written with no futex call after it -- does
                // not hang the guest for good.
                const auto slice = std::chrono::milliseconds(20);
                if (timed) {
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= deadline) {
                        return FailLinux(110); // ETIMEDOUT
                    }
                    queue.changed.wait_for(lock, std::min<std::chrono::steady_clock::duration>(slice, deadline - now));
                } else {
                    queue.changed.wait_for(lock, slice);
                }
            }
        }
        // Priority-inheritance mutexes. There is no priority to inherit here -- every
        // guest thread is an ordinary thread of one host process and Darwin schedules them
        // -- but the *protocol* is what matters: the word holds the owning thread's id,
        // with the top bit set when somebody is waiting. Steam's client and its web helper
        // share a mutex of this kind across processes, and answering "not implemented" to
        // the unlock leaves it locked forever by a thread that has long since let go.
        case kFutexLockPi:
        case kFutexTrylockPi: {
            auto* value = static_cast<std::atomic<uint32_t>*>(
                GuestPointer(arg1, sizeof(uint32_t), true));
            if (value == nullptr) {
                return FailLinux(14);
            }
            const uint32_t mine = static_cast<uint32_t>(tid_ == 0 ? pid_ : tid_) & kFutexTidMask;
            const auto waiting = EnterBlockingWait();
            for (;;) {
                uint32_t held = value->load(std::memory_order_acquire);
                if ((held & kFutexTidMask) == 0) {
                    uint32_t taken = mine | (held & kFutexWaiters);
                    if (value->compare_exchange_weak(held, taken, std::memory_order_acq_rel)) {
                        return 0;
                    }
                    continue;
                }
                if ((held & kFutexTidMask) == mine) {
                    return FailLinux(35); // EDEADLK: already ours.
                }
                if (operation == kFutexTrylockPi) {
                    return FailLinux(16); // EBUSY
                }
                // Tell the owner there is somebody here, then wait to be woken.
                value->compare_exchange_weak(held, held | kFutexWaiters, std::memory_order_acq_rel);
                auto& queue = FutexQueue(ToHost(arg1));
                std::unique_lock lock {queue.mutex};
                if ((value->load(std::memory_order_acquire) & kFutexTidMask) == 0) {
                    continue;
                }
                if (ShouldStop()) {
                    lock.unlock();
                    exit_status_ = -1;
                    control_.ExitGuest(-1);
                }
                queue.changed.wait_for(lock, std::chrono::milliseconds(20));
            }
        }
        case kFutexUnlockPi: {
            auto* value = static_cast<std::atomic<uint32_t>*>(
                GuestPointer(arg1, sizeof(uint32_t), true));
            if (value == nullptr) {
                return FailLinux(14);
            }
            const uint32_t mine = static_cast<uint32_t>(tid_ == 0 ? pid_ : tid_) & kFutexTidMask;
            uint32_t held = value->load(std::memory_order_acquire);
            if ((held & kFutexTidMask) != mine) {
                return FailLinux(1); // EPERM: not the owner.
            }
            value->store(0, std::memory_order_release);
            WakeFutex(ToHost(arg1));
            return 0;
        }
        default:
            // Saying "done" to an operation that was not performed is how a lock ends up
            // believing it is held by a thread that never took it; ENOSYS at least makes
            // the guest's own fallback path run, and says in the log which one is missing.
            ReportUnimplementedFutex(operation);
            return FailLinux(38); // -ENOSYS
        }
    }

    case kSysExit:
    case kSysExitGroup:
        exit_status_ = static_cast<int>(arg1);
        FATHOM_INFO("guest exited with status %d after %llu syscalls", exit_status_,
                    static_cast<unsigned long long>(console_.SyscallCount()));
        control_.ExitGuest(exit_status_);

    case kSysClone:
    case kSysClone3:
    case kSysFork:
    case kSysVfork: {
        if (host_ == nullptr) {
            return FailLinux(38);
        }
        if (number == kSysClone3) {
            // clone3 moved every argument into a structure, whose fields are 64-bit on
            // both architectures. `stack` is its lowest address rather than its top,
            // which is the opposite of what clone takes.
            const auto* arguments = static_cast<const uint64_t*>(GuestPointer(arg1, 64, false));
            if (arguments == nullptr) {
                return FailLinux(14);
            }
            const uint64_t flags = arguments[0];
            const uint64_t child_tid = arguments[2];
            const uint64_t parent_tid = arguments[3];
            const uint64_t stack = arguments[5] + arguments[6];
            const uint64_t tls = arguments[7];
            if ((flags & guest::kCloneThread) != 0) {
                return static_cast<uint64_t>(
                    host_->CreateThread(pid_, flags, stack, parent_tid, child_tid, tls));
            }
            return static_cast<uint64_t>(
                host_->ForkProcess(pid_, (flags & guest::kCloneVm) != 0 ? stack : 0));
        }

        // Sharing the address space is not what makes a clone a thread -- CLONE_THREAD is,
        // and posix_spawn asks for CLONE_VM|CLONE_VFORK without it: a process that shares
        // its parent's memory, runs on a stack of its own, and holds the parent until it
        // execs. Read as a thread it got no thread-local storage of its own and none
        // inherited, and read its own control block out of guest address zero.
        if (number == kSysClone && (arg1 & guest::kCloneThread) != 0) {
            // The argument order is not the same on the two architectures: i386 puts the
            // TLS descriptor where x86-64 puts the child's tid pointer, so a thread
            // created with the wrong one gets a tid written over its thread-local block.
            const uint64_t tls = config_.guest_is_32bit ? arg4 : arg5;
            const uint64_t child_tid = config_.guest_is_32bit ? arg5 : arg4;
            return static_cast<uint64_t>(host_->CreateThread(pid_, arg1, arg2, arg3, child_tid, tls));
        }
        const uint64_t shared_stack =
            number == kSysClone && (arg1 & guest::kCloneVm) != 0 ? arg2 : 0;
        return static_cast<uint64_t>(host_->ForkProcess(pid_, shared_stack));
    }

    case kSysExecve: {
        if (host_ == nullptr) {
            return FailLinux(38);
        }
        std::string path;
        if (!ReadGuestString(arg1, &path)) {
            return FailLinux(14);
        }
        std::vector<std::string> argv;
        std::vector<std::string> envp;
        if (!ReadGuestStringArray(arg2, &argv) || !ReadGuestStringArray(arg3, &envp)) {
            return FailLinux(14);
        }
        // Returns only on failure: a successful exec unwinds out of the JIT and the
        // process comes back to life running something else entirely.
        return static_cast<uint64_t>(host_->ExecProcess(pid_, path, std::move(argv), std::move(envp)));
    }

    case kSysWait4: {
        if (host_ == nullptr) {
            return FailLinux(38);
        }
        int status = 0;
        const auto waiting = EnterBlockingWait();
        const int64_t reaped = host_->WaitForChild(pid_, static_cast<int>(static_cast<int32_t>(arg1)),
                                                   &status, static_cast<int>(arg3));
        if (reaped > 0 && arg2 != 0) {
            auto* out = static_cast<int32_t*>(GuestPointer(arg2, sizeof(int32_t), true));
            if (out != nullptr) {
                // Linux packs a normal exit as the status in bits 8..15; the low byte
                // being zero is what tells the shell it was not a signal.
                *out = static_cast<int32_t>((status & 0xff) << 8);
            }
        }
        return static_cast<uint64_t>(reaped);
    }

    case kSysKill:
    case kSysTgkill:
        return 0;

    case kSysRseq:
        // Refusing this is correct and expected: glibc treats ENOSYS as "no restartable
        // sequences" and carries on.
        return FailLinux(38);

    case kSysStatx: {
        // Answered properly rather than refused. glibc falls back to fstatat when this
        // returns ENOSYS, but GNU coreutils calls statx directly and does not -- so with
        // it unimplemented, `ls -l` reports "Function not implemented" for every file.
        const int dirfd = static_cast<int>(arg1);
        const int flags = static_cast<int>(arg3);
        std::string path;
        if (!ReadGuestString(arg2, &path)) {
            return FailLinux(14);
        }

        struct stat host {};
        int result = 0;
        if (path.empty() && (flags & guest::kAtEmptyPath) != 0) {
            const int host_fd = HostFdFor(dirfd);
            result = host_fd >= 0 ? fstat(host_fd, &host) : stat(ResolveGuestPath(shared_->cwd).c_str(), &host);
        } else {
            const std::string host_path = ResolveAt(dirfd, path.c_str(), nullptr);
            result = (flags & guest::kAtSymlinkNoFollow) != 0 ? lstat(host_path.c_str(), &host)
                                                              : stat(host_path.c_str(), &host);
        }
        if (result != 0) {
            return Fail(errno);
        }

        auto* out = static_cast<uint8_t*>(GuestPointer(arg5, 256, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::memset(out, 0, 256);
        const auto put32 = [&](size_t offset, uint32_t value) { std::memcpy(out + offset, &value, 4); };
        const auto put64 = [&](size_t offset, uint64_t value) { std::memcpy(out + offset, &value, 8); };
        const auto put16 = [&](size_t offset, uint16_t value) { std::memcpy(out + offset, &value, 2); };
        const auto put_time = [&](size_t offset, int64_t seconds, uint32_t nanoseconds) {
            put64(offset, static_cast<uint64_t>(seconds));
            put32(offset + 8, nanoseconds);
        };

        constexpr uint32_t kStatxBasicStats = 0x07ff;
        put32(0, kStatxBasicStats);                            // stx_mask: what is filled in
        put32(4, static_cast<uint32_t>(host.st_blksize));
        put32(16, static_cast<uint32_t>(host.st_nlink));
        put32(20, host.st_uid);
        put32(24, host.st_gid);
        put16(28, static_cast<uint16_t>(host.st_mode));
        put64(32, host.st_ino);
        put64(40, static_cast<uint64_t>(host.st_size));
        put64(48, static_cast<uint64_t>(host.st_blocks));
        put_time(64, host.st_atimespec.tv_sec, static_cast<uint32_t>(host.st_atimespec.tv_nsec));
        put_time(80, host.st_birthtimespec.tv_sec, static_cast<uint32_t>(host.st_birthtimespec.tv_nsec));
        put_time(96, host.st_ctimespec.tv_sec, static_cast<uint32_t>(host.st_ctimespec.tv_nsec));
        put_time(112, host.st_mtimespec.tv_sec, static_cast<uint32_t>(host.st_mtimespec.tv_nsec));
        put32(128, static_cast<uint32_t>(major(host.st_rdev)));
        put32(132, static_cast<uint32_t>(minor(host.st_rdev)));
        put32(136, static_cast<uint32_t>(major(host.st_dev)));
        put32(140, static_cast<uint32_t>(minor(host.st_dev)));
        return 0;
    }

    case kSysPoll:
        return DoPoll(arg1, arg2, static_cast<int>(arg3));

    case kSysSocket: {
        bool nonblocking = false;
        bool cloexec = false;
        constexpr int kGuestAfNetlink = 16;
        constexpr int kNetlinkKobjectUevent = 15;
        // udev watches for devices arriving over a netlink socket. There is no netlink
        // here and no devices to announce, but refusing the socket is not the same as
        // there being nothing on it: SDL takes the refusal as a failure, reloads libudev
        // and tries again, several times a second, for as long as Steam is running.
        // A pipe nothing writes to says the truthful thing instead -- no events, ever.
        if (static_cast<int>(arg1) == kGuestAfNetlink) {
            if (static_cast<int>(arg3) != kNetlinkKobjectUevent) {
                // Route and the rest expect answers to the requests sent on them, and a
                // socket that never answers is worse than one that was never made.
                return FailLinux(93); // EPROTONOSUPPORT
            }
            fathom::net::HostType(static_cast<int>(arg2), &nonblocking, &cloexec);
            int pair[2] = {-1, -1};
            if (pipe(pair) != 0) {
                return Fail(errno);
            }
            if (nonblocking) {
                fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL, 0) | O_NONBLOCK);
            }
            std::scoped_lock lock {shared_->mutex};
            const int fd = RegisterFile(pair[0], "netlink");
            auto& file = shared_->files[fd];
            file.is_netlink = true;
            file.netlink_peer = pair[1];
            return static_cast<uint64_t>(fd);
        }
        const int domain = fathom::net::HostDomain(static_cast<int>(arg1));
        const int type = fathom::net::HostType(static_cast<int>(arg2), &nonblocking, &cloexec);
        if (domain < 0) {
            FATHOM_WARN("guest asked for an address family this host has no answer for: %d",
                        static_cast<int>(arg1));
            return FailLinux(97); // EAFNOSUPPORT
        }
        const int host_fd = socket(domain, type, static_cast<int>(arg3));
        if (host_fd < 0) {
            return Fail(errno);
        }
        if (nonblocking) {
            fcntl(host_fd, F_SETFL, fcntl(host_fd, F_GETFL, 0) | O_NONBLOCK);
        }
        if (cloexec) {
            fcntl(host_fd, F_SETFD, FD_CLOEXEC);
        }
        // Darwin raises SIGPIPE where Linux callers expect EPIPE from send(); the guest
        // never installed a handler for a signal its libc does not expect here.
        int on = 1;
        setsockopt(host_fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));

        std::scoped_lock lock {shared_->mutex};
        return static_cast<uint64_t>(RegisterFile(host_fd, "socket", cloexec));
    }

    case kSysConnect:
    case kSysBind: {
        {
            std::scoped_lock lock {shared_->mutex};
            auto* file = FindFile(static_cast<int>(arg1));
            if (file != nullptr && file->is_netlink) {
                return 0; // Bound, to the one address a netlink socket can have.
            }
        }
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        const void* address = GuestPointer(arg2, arg3, false);
        if (address == nullptr) {
            return FailLinux(14);
        }
        sockaddr_storage host_address {};
        const socklen_t length = ToHostSocketAddress(address, arg3, &host_address);
        if (length == 0) {
            return FailLinux(97);
        }
        int result = number == kSysConnect
                         ? connect(host_fd, reinterpret_cast<sockaddr*>(&host_address), length)
                         : bind(host_fd, reinterpret_cast<sockaddr*>(&host_address), length);

        // Linux lets a datagram socket be connected to port 0 -- it only records a default
        // destination -- and glibc leans on that. With no AF_NETLINK to enumerate
        // interfaces, getaddrinfo's AI_ADDRCONFIG check falls back to opening a UDP socket
        // and connecting it to a candidate address to see whether that family works at
        // all. Darwin refuses port 0 with EADDRNOTAVAIL, so the check concludes there is
        // no IPv4 connectivity, every lookup comes back empty, and the program reports
        // itself offline while DNS is in fact working perfectly.
        if (result < 0 && errno == EADDRNOTAVAIL && number == kSysConnect &&
            host_address.ss_family == AF_INET &&
            reinterpret_cast<const sockaddr_in*>(&host_address)->sin_port == 0) {
            int socket_type = 0;
            socklen_t option_size = sizeof(socket_type);
            if (getsockopt(host_fd, SOL_SOCKET, SO_TYPE, &socket_type, &option_size) == 0 &&
                socket_type == SOCK_DGRAM) {
                result = 0;
            }
        }
        // Every local socket a process reaches for, said out loud. There are only a few
        // per process and they are how the parts of a program find each other -- Steam's
        // client and its web helper among them -- so a connection that never happens is
        // otherwise invisible.
        if (host_address.ss_family == AF_UNIX) {
            const auto* local = reinterpret_cast<const sockaddr_un*>(&host_address);
            FATHOM_INFO("[pid %d] %s fd %d to %s%s%s", pid_,
                        number == kSysConnect ? "connect" : "bind", static_cast<int>(arg1),
                        local->sun_path, result < 0 ? " failed: " : "",
                        result < 0 ? std::strerror(errno) : "");
        }
        if (result < 0) {
            char text[64] = "?";
            if (host_address.ss_family == AF_INET) {
                const auto* in = reinterpret_cast<const sockaddr_in*>(&host_address);
                inet_ntop(AF_INET, &in->sin_addr, text, sizeof(text));
                FATHOM_WARN("%s fd %d -> %s:%u failed: %s", number == kSysConnect ? "connect" : "bind",
                            static_cast<int>(arg1), text, ntohs(in->sin_port), std::strerror(errno));
            } else {
                FATHOM_WARN("%s fd %d family %u failed: %s", number == kSysConnect ? "connect" : "bind",
                            static_cast<int>(arg1), host_address.ss_family, std::strerror(errno));
            }
        }
        return result < 0 ? Fail(errno) : 0;
    }

    case kSysListen: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        return listen(host_fd, static_cast<int>(arg2)) < 0 ? Fail(errno) : 0;
    }

    case kSysSendmsg:
        return DoMessage(static_cast<int>(arg1), arg2, static_cast<int>(arg3), true);

    case kSysRecvmsg:
        return DoMessage(static_cast<int>(arg1), arg2, static_cast<int>(arg3), false);

    case kSysShutdown: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        return shutdown(host_fd, static_cast<int>(arg2)) < 0 ? Fail(errno) : 0;
    }

    case kSysSendto: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        const void* buffer = GuestPointer(arg2, arg3, false);
        if (buffer == nullptr && arg3 != 0) {
            return FailLinux(14);
        }
        sockaddr_storage host_address {};
        socklen_t length = 0;
        if (arg5 != 0 && arg6 != 0) {
            const void* address = GuestPointer(arg5, arg6, false);
            if (address != nullptr) {
                length = ToHostSocketAddress(address, arg6, &host_address);
            }
        }
        // A DNS query, spelled out. Resolution failing is the single most common reason a
        // guest decides it has no network, and the name it asked for is the first thing
        // worth knowing about it.
        if (arg3 > 12 && arg3 < 512) {
            const auto* packet = static_cast<const unsigned char*>(buffer);
            std::string name;
            size_t at = 12;
            while (at < arg3 && packet[at] != 0 && name.size() < 200) {
                const size_t label = packet[at];
                if (label > 63 || at + label >= arg3) {
                    name.clear();
                    break;
                }
                if (!name.empty()) name.push_back('.');
                name.append(reinterpret_cast<const char*>(packet + at + 1), label);
                at += label + 1;
            }
            if (!name.empty()) {
                FATHOM_INFO("dns query for %s", name.c_str());
            }
        }
        const ssize_t sent = sendto(host_fd, buffer, arg3, HostMessageFlags(static_cast<int>(arg4)),
                                    length != 0 ? reinterpret_cast<sockaddr*>(&host_address) : nullptr,
                                    length);
        return sent < 0 ? Fail(errno) : static_cast<uint64_t>(sent);
    }

    case kSysRecvfrom: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        void* buffer = GuestPointer(arg2, arg3, true);
        if (buffer == nullptr && arg3 != 0) {
            return FailLinux(14);
        }
        sockaddr_storage from {};
        socklen_t from_length = sizeof(from);
        const ssize_t received = recvfrom(host_fd, buffer, arg3, HostMessageFlags(static_cast<int>(arg4)),
                                          reinterpret_cast<sockaddr*>(&from), &from_length);
        if (received < 0) {
            return Fail(errno);
        }
        if (arg5 != 0 && arg6 != 0) {
            auto* out_length = static_cast<uint32_t*>(GuestPointer(arg6, sizeof(uint32_t), true));
            if (out_length != nullptr) {
                void* out = GuestPointer(arg5, *out_length, true);
                if (out != nullptr) {
                    *out_length = ToGuestSocketAddress(&from, out,
                                                              *out_length);
                }
            }
        }
        return static_cast<uint64_t>(received);
    }

    case kSysGetsockname:
    case kSysGetpeername: {
        {
            std::scoped_lock lock {shared_->mutex};
            auto* file = FindFile(static_cast<int>(arg1));
            if (file != nullptr && file->is_netlink) {
                // struct sockaddr_nl: family, a pad, the port id, the group mask. udev
                // reads the port id back to know which address the kernel gave it.
                auto* size = static_cast<uint32_t*>(GuestPointer(arg3, sizeof(uint32_t), true));
                if (size == nullptr) {
                    return FailLinux(14);
                }
                const uint32_t wanted = std::min<uint32_t>(*size, 12);
                auto* out = static_cast<unsigned char*>(GuestPointer(arg2, wanted, true));
                if (out == nullptr && wanted != 0) {
                    return FailLinux(14);
                }
                unsigned char address[12] = {};
                const uint16_t family = 16;
                const uint32_t port = static_cast<uint32_t>(pid_);
                std::memcpy(address, &family, sizeof(family));
                std::memcpy(address + 4, &port, sizeof(port));
                if (wanted != 0) {
                    std::memcpy(out, address, wanted);
                }
                *size = 12;
                return 0;
            }
        }
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        auto* out_length = static_cast<uint32_t*>(GuestPointer(arg3, sizeof(uint32_t), true));
        if (out_length == nullptr) {
            return FailLinux(14);
        }
        void* out = GuestPointer(arg2, *out_length, true);
        if (out == nullptr) {
            return FailLinux(14);
        }
        sockaddr_storage address {};
        socklen_t length = sizeof(address);
        const int result = number == kSysGetsockname
                               ? getsockname(host_fd, reinterpret_cast<sockaddr*>(&address), &length)
                               : getpeername(host_fd, reinterpret_cast<sockaddr*>(&address), &length);
        if (result < 0) {
            return Fail(errno);
        }
        *out_length = ToGuestSocketAddress(&address, out, *out_length);
        return 0;
    }

    case kSysSetsockopt: {
        {
            std::scoped_lock lock {shared_->mutex};
            auto* file = FindFile(static_cast<int>(arg1));
            if (file != nullptr && file->is_netlink) {
                return 0; // A buffer size or a credential hint, on a socket with no traffic.
            }
        }
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        const int level = fathom::net::HostLevel(static_cast<int>(arg2));
        const int option = fathom::net::HostOption(static_cast<int>(arg2), static_cast<int>(arg3));
        if (option < 0) {
            // Accepting an option we cannot express beats failing: a program that cannot
            // set a hint usually carries on, and one that gets an error often gives up.
            return 0;
        }
        const void* value = GuestPointer(arg4, arg5, false);
        if (value == nullptr && arg5 != 0) {
            return FailLinux(14);
        }
        if (setsockopt(host_fd, level, option, value, static_cast<socklen_t>(arg5)) == 0) {
            return 0;
        }
        // Darwin refuses some options Linux accepts -- a size it considers out of range, a
        // flag it spells differently -- and the guest's own error handling is usually
        // harsher than the option deserves: Steam asserts and stops on any failure from
        // its default socket setup. An option it could not express is already reported as
        // success above, so doing the same for one the host would not take keeps that
        // consistent rather than making it a special case.
        FATHOM_WARN("setsockopt level %d option %d (guest %d/%d) refused: %s; reporting success",
                    level, option, static_cast<int>(arg2), static_cast<int>(arg3),
                    std::strerror(errno));
        return 0;
    }

    case kSysGetsockopt: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        const int level = fathom::net::HostLevel(static_cast<int>(arg2));
        const int option = fathom::net::HostOption(static_cast<int>(arg2), static_cast<int>(arg3));
        auto* out_length = static_cast<uint32_t*>(GuestPointer(arg5, sizeof(uint32_t), true));
        if (out_length == nullptr) {
            return FailLinux(14);
        }
        void* value = GuestPointer(arg4, *out_length, true);
        if (value == nullptr) {
            return FailLinux(14);
        }
        if (option < 0) {
            std::memset(value, 0, *out_length);
            return 0;
        }
        socklen_t length = *out_length;
        if (getsockopt(host_fd, level, option, value, &length) < 0) {
            return Fail(errno);
        }
        *out_length = length;
        return 0;
    }

    case kSysAccept:
    case kSysAccept4: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        sockaddr_storage address {};
        socklen_t length = sizeof(address);
        const int accepted = accept(host_fd, reinterpret_cast<sockaddr*>(&address), &length);
        if (accepted < 0) {
            return Fail(errno);
        }
        if (arg2 != 0 && arg3 != 0) {
            auto* out_length = static_cast<uint32_t*>(GuestPointer(arg3, sizeof(uint32_t), true));
            if (out_length != nullptr) {
                void* out = GuestPointer(arg2, *out_length, true);
                if (out != nullptr) {
                    *out_length = ToGuestSocketAddress(&address, out,
                                                              *out_length);
                }
            }
        }
        std::scoped_lock lock {shared_->mutex};
        return static_cast<uint64_t>(RegisterFile(accepted, "socket"));
    }

    case kSysSocketpair: {
        bool nonblocking = false;
        bool cloexec = false;
        const int domain = fathom::net::HostDomain(static_cast<int>(arg1));
        const int type = fathom::net::HostType(static_cast<int>(arg2), &nonblocking, &cloexec);
        if (domain < 0) {
            return FailLinux(97);
        }
        // Darwin's local sockets have no SOCK_SEQPACKET. Datagrams keep message
        // boundaries, which is the whole reason anything asks for seqpacket, and a
        // socketpair's two ends are connected to each other either way -- so Chromium's
        // IPC, which Steam's web helper is built on, works across it.
        int host_type = type;
        if (domain == AF_UNIX && host_type == SOCK_SEQPACKET) {
            host_type = SOCK_DGRAM;
        }
        int pair[2] = {-1, -1};
        if (socketpair(domain, host_type, static_cast<int>(arg3), pair) < 0) {
            return Fail(errno);
        }
        auto* out = static_cast<int32_t*>(GuestPointer(arg4, sizeof(int32_t) * 2, true));
        if (out == nullptr) {
            close(pair[0]);
            close(pair[1]);
            return FailLinux(14);
        }
        std::scoped_lock lock {shared_->mutex};
        const int first = RegisterFile(pair[0], "socketpair", cloexec);
        const int second = RegisterFile(pair[1], "socketpair", cloexec);
        // Each end named after the other, so a report about a thread waiting on one says
        // which descriptor is supposed to be writing to it.
        shared_->files[first].guest_path = "socketpair with " + std::to_string(second);
        shared_->files[second].guest_path = "socketpair with " + std::to_string(first);
        out[0] = static_cast<int32_t>(first);
        out[1] = static_cast<int32_t>(second);
        return 0;
    }

    case kSysSelect:
    case kSysPselect6: {
        int64_t timeout_us = -1;
        if (arg5 != 0) {
            if (number == kSysSelect) {
                const auto* tv = static_cast<const int64_t*>(GuestPointer(arg5, 16, false));
                if (tv != nullptr) {
                    timeout_us = tv[0] * 1000000 + tv[1];
                }
            } else {
                const auto* ts = static_cast<const int64_t*>(GuestPointer(arg5, 16, false));
                if (ts != nullptr) {
                    timeout_us = ts[0] * 1000000 + ts[1] / 1000;
                }
            }
        }
        return DoSelect(static_cast<int>(arg1), arg2, arg3, arg4, timeout_us);
    }

    case kSysRename:
    case kSysRenameat:
    case kSysRenameat2: {
        // The three differ only in how the two paths are addressed, and renameat2 adds
        // flags. RENAME_NOREPLACE is the one that matters: a package manager uses it to
        // avoid clobbering a file it did not expect to be there.
        constexpr uint64_t kRenameNoreplace = 1;
        uint64_t old_path_address = arg1;
        uint64_t new_path_address = arg2;
        int old_dirfd = guest::kAtFdCwd;
        int new_dirfd = guest::kAtFdCwd;
        uint64_t flags = 0;
        if (number != kSysRename) {
            old_dirfd = static_cast<int>(arg1);
            old_path_address = arg2;
            new_dirfd = static_cast<int>(arg3);
            new_path_address = arg4;
            if (number == kSysRenameat2) {
                flags = arg5;
            }
        }

        std::string old_path;
        std::string new_path;
        if (!ReadGuestString(old_path_address, &old_path) ||
            !ReadGuestString(new_path_address, &new_path)) {
            return FailLinux(14);
        }
        // Neither side is followed: rename moves the link, not what it points at, and
        // moving a staged file onto an existing symlink has to replace the link.
        const std::string from = ResolveAt(old_dirfd, old_path.c_str(), nullptr, false);
        const std::string to = ResolveAt(new_dirfd, new_path.c_str(), nullptr, false);
        if ((flags & kRenameNoreplace) != 0 && access(to.c_str(), F_OK) == 0) {
            return FailLinux(17); // EEXIST
        }
        return rename(from.c_str(), to.c_str()) != 0 ? Fail(errno) : 0;
    }

    case kSysSymlink:
    case kSysSymlinkat: {
        std::string target;
        std::string link_path;
        const uint64_t target_address = arg1;
        const uint64_t link_address = number == kSysSymlink ? arg2 : arg3;
        const int dirfd = number == kSysSymlink ? guest::kAtFdCwd : static_cast<int>(arg2);
        if (!ReadGuestString(target_address, &target) || !ReadGuestString(link_address, &link_path)) {
            return FailLinux(14);
        }
        // The target is stored exactly as given: it is resolved later, by the guest,
        // against the guest's root.
        return symlink(target.c_str(),
                       ResolveAt(dirfd, link_path.c_str(), nullptr, false).c_str()) != 0
                   ? Fail(errno)
                   : 0;
    }

    case kSysLink:
    case kSysLinkat: {
        const bool at = number == kSysLinkat;
        std::string old_path;
        std::string new_path;
        if (!ReadGuestString(at ? arg2 : arg1, &old_path) ||
            !ReadGuestString(at ? arg4 : arg2, &new_path)) {
            return FailLinux(14);
        }
        const std::string from = ResolveAt(at ? static_cast<int>(arg1) : guest::kAtFdCwd,
                                           old_path.c_str(), nullptr);
        const std::string to = ResolveAt(at ? static_cast<int>(arg3) : guest::kAtFdCwd,
                                         new_path.c_str(), nullptr);
        return link(from.c_str(), to.c_str()) != 0 ? Fail(errno) : 0;
    }

    case kSysChmod:
    case kSysFchmodat: {
        std::string path;
        const bool at = number == kSysFchmodat;
        if (!ReadGuestString(at ? arg2 : arg1, &path)) {
            return FailLinux(14);
        }
        const std::string host_path = ResolveAt(at ? static_cast<int>(arg1) : guest::kAtFdCwd,
                                                path.c_str(), nullptr);
        const auto mode = static_cast<mode_t>(at ? arg3 : arg2);
        return chmod(host_path.c_str(), mode) != 0 ? Fail(errno) : 0;
    }

    case kSysFchmod: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        return fchmod(host_fd, static_cast<mode_t>(arg2)) != 0 ? Fail(errno) : 0;
    }

    case kSysUtimensat:
        // Timestamps are cosmetic here, and a package manager that cannot set them still
        // installs correctly; failing would stop it dead.
        return 0;

    case kSysMount:
    case kSysUmount2:
        // Nothing here is mountable, and this is not root. EPERM is the truthful answer,
        // and unlike ENOSYS it is one callers are written to expect.
        return FailLinux(1);

    case kSysGetxattr:
    case kSysLgetxattr:
    case kSysFgetxattr:
        // "This file has no such attribute" rather than "this system has no attributes".
        // ls asks every file whether it carries a security label, and handles ENODATA
        // quietly while reporting ENOSYS as an error against the file itself.
        return FailLinux(61); // ENODATA

    case kSysListxattr:
    case kSysLlistxattr:
    case kSysFlistxattr:
        return 0;  // An empty list of attributes.

    case kSysFchdir: {
        // The working directory is tracked as a guest path, not as a host descriptor, so
        // this is answered from the path the descriptor was opened with rather than by
        // calling the host's fchdir.
        std::scoped_lock lock {shared_->mutex};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        if (file->guest_path.empty() || file->guest_path.front() != '/') {
            return FailLinux(22); // EINVAL
        }
        shared_->cwd = file->guest_path;
        return 0;
    }

    case kSysChown:
    case kSysLchown:
    case kSysFchown:
    case kSysFchownat:
        // There is one user here and everything already belongs to it, so ownership
        // changes are accepted and ignored. Refusing them stops installers that are only
        // tidying up permissions they do not actually need.
        return 0;

    case kSysFlock: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        // LOCK_SH, LOCK_EX, LOCK_NB and LOCK_UN happen to be 1, 2, 4 and 8 on both
        // systems, so the operation passes through untouched.
        return flock(host_fd, static_cast<int>(arg2)) < 0 ? Fail(errno) : 0;
    }

    case kSysStatfs:
    case kSysFstatfs: {
        struct statfs host {};
        if (number == kSysFstatfs) {
            const int host_fd = HostFdFor(static_cast<int>(arg1));
            if (host_fd < 0 || fstatfs(host_fd, &host) != 0) {
                return host_fd < 0 ? FailLinux(9) : Fail(errno);
            }
        } else {
            std::string path;
            if (!ReadGuestString(arg1, &path)) {
                return FailLinux(14);
            }
            if (statfs(ResolveGuestPath(path).c_str(), &host) != 0) {
                return Fail(errno);
            }
        }

        // Linux's struct statfs is 120 bytes of 64-bit fields in an order all its own,
        // and nothing about Darwin's matches, so it is written out field by field.
        //
        // i386's statfs64 is a different structure again: 84 bytes, with everything except
        // the block and inode counts narrowed to 32 bits. Writing the 64-bit layout into
        // it overruns the caller's buffer and puts the block size where the free-block
        // count belongs, which a guest reports as a filesystem with no free space.
        // i386's statfs64 and fstatfs64 take the structure's size as their second
        // argument, so the buffer is the third. Writing to the second puts a filesystem
        // description over the size the caller passed, and leaves the buffer as it was --
        // which a guest reads back as a filesystem with no free space.
        if (config_.guest_is_32bit) {
            auto* out = static_cast<uint8_t*>(GuestPointer(arg3, 84, true));
            if (out == nullptr) {
                return FailLinux(14);
            }
            std::memset(out, 0, 84);
            const auto put32 = [&](size_t offset, uint32_t value) { std::memcpy(out + offset, &value, 4); };
            const auto put64 = [&](size_t offset, uint64_t value) { std::memcpy(out + offset, &value, 8); };
            put32(0, 0x858458f6);           // f_type: report RAMFS_MAGIC
            put32(4, static_cast<uint32_t>(host.f_bsize));
            put64(8, host.f_blocks);
            put64(16, host.f_bfree);
            put64(24, host.f_bavail);
            put64(32, host.f_files);
            put64(40, host.f_ffree);
            put32(56, 255);                 // f_namelen
            put32(60, static_cast<uint32_t>(host.f_bsize));  // f_frsize
            return 0;
        }

        auto* out = static_cast<uint8_t*>(GuestPointer(arg2, 120, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::memset(out, 0, 120);
        const auto put = [&](size_t offset, uint64_t value) { std::memcpy(out + offset, &value, 8); };
        put(0, 0x858458f6);                 // f_type: report RAMFS_MAGIC
        put(8, host.f_bsize);
        put(16, host.f_blocks);
        put(24, host.f_bfree);
        put(32, host.f_bavail);
        put(40, host.f_files);
        put(48, host.f_ffree);
        put(64, 255);                       // f_namelen
        put(72, host.f_bsize);              // f_frsize
        return 0;
    }

    // An interval timer delivers SIGALRM, and Fathom delivers no signals to the guest at
    // all, so arming one would be a promise this cannot keep. The value is remembered and
    // handed back, which is what a caller that reads it expects, and no timer runs. An X
    // server uses this for its screen saver; refusing it outright made it retry forever.
    case kSysSetitimer:
    case kSysGetitimer: {
        const size_t width = config_.guest_is_32bit ? 4 : 8;
        const size_t size = width * 4;  // Two timevals: interval, then value.
        if (number == kSysSetitimer) {
            if (arg3 != 0) {
                auto* previous = static_cast<unsigned char*>(GuestPointer(arg3, size, true));
                if (previous == nullptr) {
                    return FailLinux(14);
                }
                std::memset(previous, 0, size);
            }
            return 0;
        }
        auto* out = static_cast<unsigned char*>(GuestPointer(arg2, size, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::memset(out, 0, size);  // Disarmed, which is the truth.
        return 0;
    }

    case kSysSendmmsg:
    case kSysRecvmmsg:
        // glibc's resolver sends its A and AAAA queries with one sendmmsg, and it does not
        // fall back when that fails -- it retries, forever. Without this, name resolution
        // simply never completes and a program reports itself offline.
        return DoMultiMessage(static_cast<int>(arg1), arg2, arg3, static_cast<int>(arg4),
                              number == kSysSendmmsg);

    case kSysPrctl:
        return DoPrctl(arg1, arg2);

    case kSysSemget:
        return DoSemget(static_cast<int32_t>(arg1), static_cast<int>(arg2), static_cast<int>(arg3));
    case kSysSemop:
        return DoSemop(static_cast<int>(arg1), arg2, arg3);
    case kSysSemctl:
        return DoSemctl(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3), arg4);

    case kSysMknod:
        return DoMknodAt(guest::kAtFdCwd, arg1, static_cast<uint32_t>(arg2));
    case kSysMknodat:
        return DoMknodAt(static_cast<int>(arg1), arg2, static_cast<uint32_t>(arg3));

    case kSysShmget:
        return DoShmget(static_cast<int32_t>(arg1), arg2, static_cast<int>(arg3));

    case kSysShmat:
        return DoShmat(static_cast<int>(arg1), arg2, static_cast<int>(arg3));

    case kSysShmdt:
        return DoShmdt(arg1);

    case kSysShmctl:
        return DoShmctl(static_cast<int>(arg1), static_cast<int>(arg2), arg3);

    case kSysTimerfdCreate:
        return DoTimerfdCreate(static_cast<int>(arg1), static_cast<int>(arg2));

    case kSysTimerfdSettime:
        return DoTimerfdSettime(static_cast<int>(arg1), static_cast<int>(arg2), arg3, arg4);

    case kSysTimerfdGettime:
        return DoTimerfdGettime(static_cast<int>(arg1), arg2);

    case kSysEventfd:
        return DoEventfd(arg1, 0);
    case kSysEventfd2:
        return DoEventfd(arg1, static_cast<int>(arg2));

    case kSysEpollCreate:
    case kSysEpollCreate1:
        return DoEpollCreate(number == kSysEpollCreate1 ? static_cast<int>(arg1) : 0);
    case kSysEpollCtl:
        return DoEpollCtl(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3), arg4);
    case kSysEpollWait:
    case kSysEpollPwait:
        return DoEpollWait(static_cast<int>(arg1), arg2, static_cast<int>(arg3),
                           static_cast<int>(arg4));

    case kSysSysinfo: {
        // Every field is a long, so the whole structure is half the width for an i386
        // guest: 64 bytes rather than 112.
        const bool narrow = config_.guest_is_32bit;
        const size_t width = narrow ? 4 : 8;
        const size_t size = narrow ? 64 : 112;
        auto* out = static_cast<uint8_t*>(GuestPointer(arg1, size, true));
        if (out == nullptr) {
            return FailLinux(14);
        }
        std::memset(out, 0, size);

        uint64_t total_ram = 0;
        size_t length = sizeof(total_ram);
        if (sysctlbyname("hw.memsize", &total_ram, &length, nullptr, 0) != 0) {
            total_ram = 0;
        }
        uint32_t free_pages = 0;
        length = sizeof(free_pages);
        if (sysctlbyname("vm.page_free_count", &free_pages, &length, nullptr, 0) != 0) {
            free_pages = 0;
        }
        const uint64_t page_size = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
        uint64_t free_ram = static_cast<uint64_t>(free_pages) * page_size;
        if (narrow) {
            // A 32-bit guest cannot hold more than 4GB in an unsigned long, and reporting
            // a wrapped value is worse than reporting a ceiling.
            total_ram = std::min<uint64_t>(total_ram, 0xFFFF'FFFFULL);
            free_ram = std::min<uint64_t>(free_ram, 0xFFFF'FFFFULL);
        }

        struct timespec uptime {};
        clock_gettime(CLOCK_MONOTONIC, &uptime);

        const auto put = [&](size_t offset, uint64_t value) { std::memcpy(out + offset, &value, width); };
        put(0, static_cast<uint64_t>(uptime.tv_sec));                    // uptime
        put(width * 4, total_ram);                                       // totalram
        put(width * 5, free_ram);                                        // freeram
        const uint16_t processes = 1;
        std::memcpy(out + width * 10, &processes, 2);                    // procs
        const uint32_t unit = 1;
        std::memcpy(out + (narrow ? 52 : 104), &unit, 4);                // mem_unit
        return 0;
    }

    default:
        FATHOM_WARN("unimplemented syscall %llu (%s)", static_cast<unsigned long long>(number),
                    SyscallName(number));
        return FailLinux(38); // ENOSYS
    }
}

} // namespace fathom

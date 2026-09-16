#include "linux_syscalls.h"

#include "guest_net.h"
#include "guest_syscalls32.h"
#include "guest_path.h"

#include <poll.h>

#include "crash_handler.h"
#include "fathom_log.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
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
    kSysSemop = 65,
    kSysSemctl = 66,
    kSysMknod = 133,
    kSysMknodat = 259,
    kSysEpollCreate = 213,
    kSysEpollWait = 232,
    kSysEpollCtl = 233,
    kSysEpollPwait = 281,
    kSysEventfd = 284,
    kSysEventfd2 = 290,
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
    case kSysSemop: return "semop";
    case kSysSemctl: return "semctl";
    case kSysMknod: return "mknod";
    case kSysMknodat: return "mknodat";
    case kSysEpollCreate: return "epoll_create";
    case kSysEpollCreate1: return "epoll_create1";
    case kSysEpollCtl: return "epoll_ctl";
    case kSysEpollWait: return "epoll_wait";
    case kSysEpollPwait: return "epoll_pwait";
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
    case kSysGetrandom: return "getrandom";
    case kSysStatx: return "statx";
    case kSysRseq: return "rseq";
    default: return "?";
    }
}

} // namespace

LinuxSyscalls::LinuxSyscalls(GuestAddressSpace& space, GuestThreadControl& control,
                             GuestConsole& console, SyscallConfig config)
    : space_ {space}
    , control_ {control}
    , console_ {console}
    , config_ {std::move(config)} {
    if (!config_.work_dir.empty()) {
        cwd_ = NormaliseGuestPath(config_.work_dir);
    }
    // stdin, stdout and stderr are entries like any other, so that a shell can point them
    // at a pipe or a file and everything downstream keeps working by number alone.
    for (int stream = 0; stream <= 2; ++stream) {
        OpenFile console;
        console.console_stream = stream;
        console.guest_path = "/dev/console";
        files_[stream] = console;
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

void LinuxSyscalls::SetProcess(int pid, int ppid, ProcessHost* host) {
    pid_ = pid;
    ppid_ = ppid;
    host_ = host;
}

void LinuxSyscalls::CloneInto(LinuxSyscalls& child) const {
    std::scoped_lock lock {mutex_};
    // Every descriptor is dup'd rather than shared outright: the child must be able to
    // close one, or point it somewhere else for a redirection, without the parent's
    // table changing underneath it. dup keeps the underlying file description shared,
    // which is exactly what fork promises.
    for (const auto& [fd, file] : files_) {
        OpenFile inherited;
        inherited.guest_path = file.guest_path;
        // Carried across, and not obvious: without it a child's fd 1 is neither the
        // console nor a file, so the first thing it prints fails and it exits reporting
        // a write error instead of doing its job.
        inherited.console_stream = file.console_stream;
        inherited.is_framebuffer = file.is_framebuffer;
        inherited.event = file.event;
        inherited.epoll = file.epoll;

        if (file.host_fd >= 0) {
            inherited.host_fd = dup(file.host_fd);
            if (inherited.host_fd < 0) {
                continue;  // Out of descriptors: the child simply does not inherit it.
            }
        }
        child.files_[fd] = std::move(inherited);
    }
    child.cwd_ = cwd_;
    child.heap_base_ = heap_base_;
    child.heap_limit_ = heap_limit_;
    child.heap_break_ = heap_break_;
    child.config_.work_dir = config_.work_dir;
}

void LinuxSyscalls::AdoptImage(uint64_t heap_base, uint64_t heap_reserved, const std::string& path) {
    InitialiseHeap(heap_base, heap_reserved);
    config_.work_dir = path;
    // An exec replaces the whole address space, so nothing the old program mapped is
    // this process's any more. Keeping the list would make a later fork snapshot and
    // then restore regions that have since been released and handed to somebody else --
    // which corrupts whichever process is now living there.
    std::scoped_lock lock {mutex_};
    mappings_.clear();
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
    return ResolveGuestPathOnHost(config_.guest_root, guest_path);
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
    // The guest's number, not the host's. Identical for a 64-bit guest; for a 32-bit one
    // the arena lives high in the host's address space and this is where that is undone.
    address = space_.ToHost(address);
    const int required = kGuestProtRead | (writable ? kGuestProtWrite : 0);
    if (!space_.Validate(address, size, required)) {
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
    const uint64_t host_address = space_.ToHost(address);
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
    const auto entry = files_.find(fd);
    return entry == files_.end() ? nullptr : &entry->second;
}

std::vector<std::pair<uint64_t, uint64_t>> LinuxSyscalls::Mappings() const {
    std::scoped_lock lock {mutex_};
    return mappings_;
}

int LinuxSyscalls::AllocateFd() {
    int fd = 0;
    while (files_.count(fd) != 0) {
        ++fd;
    }
    return fd;
}

int LinuxSyscalls::RegisterFile(int host_fd, std::string guest_path) {
    // Guest descriptors are their own numbering, not the host's. They have to be, because
    // a guest expects the lowest free number back and expects to be able to move one onto
    // fd 1 -- and fd 1 on the host belongs to this app.
    const int fd = AllocateFd();
    OpenFile file;
    file.host_fd = host_fd;
    file.guest_path = std::move(guest_path);
    files_[fd] = std::move(file);
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
        std::scoped_lock lock {mutex_};
        const int fd = AllocateFd();
        OpenFile display;
        display.guest_path = guest_path;
        display.is_framebuffer = true;
        files_[fd] = std::move(display);
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
        std::scoped_lock lock {mutex_};
        return static_cast<uint64_t>(RegisterFile(backing, guest_path));
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

    int host_fd = -1;
    {
        std::scoped_lock lock {mutex_};
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
    {
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(fd);
        if (file == nullptr) {
            return FailLinux(9); // EBADF
        }
        if (file->event != nullptr) {
            return DoEventfdRead(*file, buffer);
        }
        from_console = file->console_stream >= 0;
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

    std::scoped_lock lock {mutex_};
    auto* file = FindFile(fd);
    if (file == nullptr) {
        return FailLinux(9);
    }
    const ssize_t bytes = read(file->host_fd, data, count);
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
        if (console_.StopRequested()) {
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
                std::scoped_lock lock {mutex_};
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

    for (;;) {
        if (console_.StopRequested()) {
            exit_status_ = -1;
            control_.ExitGuest(-1);
        }

        uint64_t ready = 0;
        for (uint64_t index = 0; index < count; ++index) {
            auto& entry = fds[index];
            entry.revents = 0;
            if (entry.fd < 0) {
                continue;  // Negative fds are ignored, not errors.
            }

            if (entry.fd == 0) {
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
                    std::scoped_lock lock {mutex_};
                    auto* file = FindFile(entry.fd);
                    if (file != nullptr) {
                        host_fd = file->host_fd;
                    }
                }
                if (host_fd < 0) {
                    entry.revents |= kPollNval;
                } else {
                    // Ask the host about its own descriptor; a regular file is always ready.
                    struct pollfd probe {};
                    probe.fd = host_fd;
                    probe.events = static_cast<short>(entry.events);
                    if (poll(&probe, 1, 0) > 0) {
                        entry.revents = static_cast<int16_t>(probe.revents);
                    }
                }
            }

            if (entry.revents != 0) {
                ++ready;
            }
        }

        if (ready > 0 || timeout_ms == 0) {
            return ready;
        }
        if (timeout_ms > 0 && std::chrono::steady_clock::now() >= deadline) {
            return 0;
        }

        // Sleep until a key arrives, in slices so a stop request is still noticed.
        console_.WaitForInput(10);
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
    const int host_fd = HostFdFor(fd);
    if (host_fd < 0) {
        return FailLinux(9);
    }

    constexpr uint64_t kGuestMsghdrSize = 56;
    auto* header = static_cast<uint8_t*>(GuestPointer(header_address, kGuestMsghdrSize, true));
    if (header == nullptr) {
        return FailLinux(14);
    }

    uint64_t name_address = 0;
    uint32_t name_length = 0;
    uint64_t iov_address = 0;
    uint64_t iov_count = 0;
    uint64_t control_length = 0;
    std::memcpy(&name_address, header + 0, 8);
    std::memcpy(&name_length, header + 8, 4);
    std::memcpy(&iov_address, header + 16, 8);
    std::memcpy(&iov_count, header + 24, 8);
    std::memcpy(&control_length, header + 40, 8);

    if (iov_count > 1024) {
        return FailLinux(22); // EINVAL
    }
    auto* vectors = static_cast<LinuxIovec*>(
        GuestPointer(iov_address, iov_count * sizeof(LinuxIovec), true));
    if (vectors == nullptr && iov_count != 0) {
        return FailLinux(14);
    }
    for (uint64_t index = 0; index < iov_count; ++index) {
        if (vectors[index].length != 0 &&
            GuestPointer(vectors[index].base, vectors[index].length, !sending) == nullptr) {
            return FailLinux(14);
        }
    }
    if (control_length != 0) {
        // Ancillary data is laid out differently again, and nothing Fathom runs yet passes
        // any. Dropping it is better than misreading it.
        FATHOM_WARN("%s with %llu bytes of control data, which is being ignored",
                    sending ? "sendmsg" : "recvmsg",
                    static_cast<unsigned long long>(control_length));
    }

    sockaddr_storage address {};
    msghdr host_header {};
    host_header.msg_iov = reinterpret_cast<iovec*>(vectors);
    host_header.msg_iovlen = static_cast<int>(iov_count);

    if (sending) {
        if (name_address != 0 && name_length != 0) {
            const void* guest_name = GuestPointer(name_address, name_length, false);
            if (guest_name != nullptr) {
                const socklen_t length = fathom::net::ToHostAddress(guest_name, name_length, &address);
                if (length != 0) {
                    host_header.msg_name = &address;
                    host_header.msg_namelen = length;
                }
            }
        }
        const ssize_t sent = sendmsg(host_fd, &host_header, HostMessageFlags(flags));
        return sent < 0 ? Fail(errno) : static_cast<uint64_t>(sent);
    }

    if (name_address != 0 && name_length != 0) {
        host_header.msg_name = &address;
        host_header.msg_namelen = sizeof(address);
    }
    const ssize_t received = recvmsg(host_fd, &host_header, HostMessageFlags(flags));
    if (received < 0) {
        return Fail(errno);
    }
    if (host_header.msg_name != nullptr && host_header.msg_namelen != 0) {
        void* guest_name = GuestPointer(name_address, name_length, true);
        if (guest_name != nullptr) {
            const socklen_t written =
                fathom::net::ToGuestAddress(reinterpret_cast<sockaddr*>(&address), guest_name, name_length);
            std::memcpy(header + 8, &written, 4);
        }
    }
    const int32_t out_flags = host_header.msg_flags;
    std::memcpy(header + 48, &out_flags, 4);
    return static_cast<uint64_t>(received);
}

int LinuxSyscalls::HostFdFor(int guest_fd) {
    std::scoped_lock lock {mutex_};
    auto* file = FindFile(guest_fd);
    return file == nullptr ? -1 : file->host_fd;
}

bool LinuxSyscalls::IsConsole(int fd) {
    std::scoped_lock lock {mutex_};
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
    files_[target] = std::move(copy);
    return target;
}

/// Closes one descriptor. The caller holds the lock.
void LinuxSyscalls::CloseFd(int fd) {
    auto entry = files_.find(fd);
    if (entry == files_.end()) {
        return;
    }
    if (entry->second.directory != nullptr) {
        closedir(static_cast<DIR*>(entry->second.directory)); // also closes host_fd
    } else if (entry->second.host_fd >= 0) {
        close(entry->second.host_fd);
    }
    files_.erase(entry);
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
            result = stat(ResolveGuestPath(cwd_).c_str(), &host);
        } else {
            const int host_fd = HostFdFor(dirfd);
            if (host_fd < 0) {
                // The console, which has no host descriptor behind it.
                return DoFstat(dirfd, stat_address);
            }
            result = fstat(host_fd, &host);
        }
    } else {
        const std::string host_path = ResolveAt(dirfd, path.c_str(), nullptr);
        result = (flags & guest::kAtSymlinkNoFollow) != 0 ? lstat(host_path.c_str(), &host)
                                                          : stat(host_path.c_str(), &host);
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
        std::scoped_lock lock {mutex_};
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
    // Everything below -- the arena, mappings_, the framebuffer -- is in host addresses.
    // The guest's hint comes in guest-numbered and the result goes back out the same way;
    // for a 1:1 (64-bit) guest both conversions are the identity.
    if (address != 0) {
        address = space_.ToHost(address);
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
            return space_.ToGuest(display.address);
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
    {
        std::scoped_lock lock {mutex_};
        mappings_.emplace_back(placed, length);
    }
    return space_.ToGuest(placed);
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
    return Dispatch(selected.x86_64_number, unpacked[0], unpacked[1], unpacked[2], unpacked[3],
                    unpacked[4], unpacked[5]);
}

uint64_t LinuxSyscalls::DoSetThreadArea(uint64_t descriptor_address) {
    // struct user_desc: entry_number, base_addr, limit, then a word of bit fields
    // describing the segment. Only the first three matter here -- Fathom always installs
    // a 32-bit read/write data segment, which is the only kind glibc asks for.
    auto* descriptor = static_cast<uint32_t*>(GuestPointer(descriptor_address, 16, true));
    if (descriptor == nullptr) {
        return FailLinux(14);
    }

    uint32_t entry = descriptor[0];
    if (entry == 0xFFFF'FFFFU) {
        // "Any free one." Linux picks a slot and writes the number back, and glibc reads
        // it to build the selector it loads into %gs.
        if (next_tls_entry_ > 14) {
            return FailLinux(22);
        }
        entry = next_tls_entry_++;
        descriptor[0] = entry;
    } else if (entry < 12 || entry > 14) {
        return FailLinux(22);
    }

    control_.SetTlsDescriptor(static_cast<int>(entry), descriptor[1], descriptor[2] >> 12);
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

    std::scoped_lock lock {mutex_};
    const int fd = RegisterFile(ends[0], "anon_inode:[eventfd]");
    files_[fd].event = counter;
    if (initial != 0) {
        const char byte = 1;
        if (write(ends[1], &byte, 1) == 1) {
            counter->signalled = true;
        }
    }
    return static_cast<uint64_t>(fd);
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
    (void)flags;
    std::scoped_lock lock {mutex_};
    const int fd = RegisterFile(-1, "anon_inode:[eventpoll]");
    files_[fd].epoll = std::make_shared<EpollSet>();
    return static_cast<uint64_t>(fd);
}

uint64_t LinuxSyscalls::DoEpollCtl(int epoll_fd, int operation, int fd, uint64_t event_address) {
    constexpr int kEpollCtlAdd = 1;
    constexpr int kEpollCtlDel = 2;
    constexpr int kEpollCtlMod = 3;

    std::shared_ptr<EpollSet> set;
    {
        std::scoped_lock lock {mutex_};
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
        std::scoped_lock lock {mutex_};
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

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms < 0 ? 0 : timeout_ms);
    for (;;) {
        if (console_.StopRequested()) {
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
            std::scoped_lock lock {mutex_};
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

        int ready = host_fds.empty() ? 0 : poll(host_fds.data(), static_cast<nfds_t>(host_fds.size()), 0);
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
        console_.WaitForInput(10);
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
    const std::string self_prefix = "/proc/self/";
    const std::string pid_prefix = "/proc/" + std::to_string(pid_) + "/";
    std::string leaf;
    if (guest_path.rfind(self_prefix, 0) == 0) {
        leaf = guest_path.substr(self_prefix.size());
    } else if (guest_path.rfind(pid_prefix, 0) == 0) {
        leaf = guest_path.substr(pid_prefix.size());
    } else {
        return false;
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

    switch (call & 0xFFFF) {
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
    // An i386 guest numbers its syscalls entirely differently -- its 4 is write, where
    // x86-64's 4 is stat -- so the number is translated before anything looks at it, and
    // one implementation of each syscall serves both.
    if (config_.guest_is_32bit) {
        if (number == kI386SetThreadArea) {
            // x86-64 has no equivalent: a 64-bit guest sets its TLS pointer with
            // arch_prctl, so there is no number to translate this into.
            return DoSetThreadArea(arg1);
        }
        if (number == kI386Socketcall) {
            return DoSocketcall(arg1, arg2);
        }
        if (number == kI386Ipc) {
            return DoIpc(arg1, arg2, arg3, arg4, arg5);
        }
        if (number == kI386Mmap2) {
            // The only argument difference that matters here: mmap2 counts its offset in
            // 4096-byte pages so that a 32-bit register can address a large file.
            arg6 *= 4096;
        }
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

    if (console_.StopRequested()) {
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
        FATHOM_INFO("[pid %d] syscall %llu %s(%#llx, %#llx, %#llx)", pid_,
                    static_cast<unsigned long long>(number), SyscallName(number),
                    static_cast<unsigned long long>(arg1),
                    static_cast<unsigned long long>(arg2), static_cast<unsigned long long>(arg3));
    }

    const auto result = Dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6);

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
        std::scoped_lock lock {mutex_};
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

    case kSysMunmap: {
        const uint64_t host_address = space_.ToHost(arg1);
        {
            std::scoped_lock lock {mutex_};
            std::erase_if(mappings_, [&](const auto& entry) {
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
        return space_.Protect(space_.ToHost(arg1), arg2, guest_protection) ? 0 : FailLinux(22);
    }

    case kSysMremap: {
        constexpr uint64_t kMremapMayMove = 1;
        const uint64_t old_address = space_.ToHost(arg1);
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
        return space_.ToGuest(placed);
    }

    case kSysBrk:
        return DoBrk(arg1);

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
            std::scoped_lock lock {mutex_};
            auto* file = FindFile(fd);
            is_display = file != nullptr && file->is_framebuffer;
        }
        if (is_display) {
            return DoFramebufferIoctl(arg2, arg3);
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
            console_.SetNonblockingStdin(nonblocking);
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

    case kSysDup: {
        std::scoped_lock lock {mutex_};
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
        std::scoped_lock lock {mutex_};
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
        std::scoped_lock lock {mutex_};
        out[0] = static_cast<int32_t>(RegisterFile(ends[0], "pipe:[read]"));
        out[1] = static_cast<int32_t>(RegisterFile(ends[1], "pipe:[write]"));
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
        return static_cast<uint64_t>(pid_);
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
                    static_cast<unsigned long long>(console_.SyscallCount()));
        control_.ExitGuest(exit_status_);

    case kSysClone:
    case kSysClone3:
    case kSysFork:
    case kSysVfork: {
        if (host_ == nullptr) {
            return FailLinux(38);
        }
        // Threads -- clone with a shared address space -- are a different thing and are
        // not supported yet. A shell only ever asks for a process.
        if (number == kSysClone && (arg1 & guest::kCloneVm) != 0) {
            FATHOM_WARN("guest asked for a thread (clone flags %#llx), which Fathom cannot make yet",
                        static_cast<unsigned long long>(arg1));
            return FailLinux(38);
        }
        return static_cast<uint64_t>(host_->ForkProcess(pid_));
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
            result = host_fd >= 0 ? fstat(host_fd, &host) : stat(ResolveGuestPath(cwd_).c_str(), &host);
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

        std::scoped_lock lock {mutex_};
        return static_cast<uint64_t>(RegisterFile(host_fd, "socket"));
    }

    case kSysConnect:
    case kSysBind: {
        const int host_fd = HostFdFor(static_cast<int>(arg1));
        if (host_fd < 0) {
            return FailLinux(9);
        }
        const void* address = GuestPointer(arg2, arg3, false);
        if (address == nullptr) {
            return FailLinux(14);
        }
        sockaddr_storage host_address {};
        const socklen_t length = fathom::net::ToHostAddress(address, arg3, &host_address);
        if (length == 0) {
            return FailLinux(97);
        }
        const int result = number == kSysConnect
                               ? connect(host_fd, reinterpret_cast<sockaddr*>(&host_address), length)
                               : bind(host_fd, reinterpret_cast<sockaddr*>(&host_address), length);
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
                length = fathom::net::ToHostAddress(address, arg6, &host_address);
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
                    *out_length = fathom::net::ToGuestAddress(reinterpret_cast<sockaddr*>(&from), out,
                                                              *out_length);
                }
            }
        }
        return static_cast<uint64_t>(received);
    }

    case kSysGetsockname:
    case kSysGetpeername: {
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
        *out_length = fathom::net::ToGuestAddress(reinterpret_cast<sockaddr*>(&address), out, *out_length);
        return 0;
    }

    case kSysSetsockopt: {
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
        return setsockopt(host_fd, level, option, value, static_cast<socklen_t>(arg5)) < 0 ? Fail(errno) : 0;
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
                    *out_length = fathom::net::ToGuestAddress(reinterpret_cast<sockaddr*>(&address), out,
                                                              *out_length);
                }
            }
        }
        std::scoped_lock lock {mutex_};
        return static_cast<uint64_t>(RegisterFile(accepted, "socket"));
    }

    case kSysSocketpair: {
        bool nonblocking = false;
        const int domain = fathom::net::HostDomain(static_cast<int>(arg1));
        const int type = fathom::net::HostType(static_cast<int>(arg2), &nonblocking, nullptr);
        if (domain < 0) {
            return FailLinux(97);
        }
        int pair[2] = {-1, -1};
        if (socketpair(domain, type, static_cast<int>(arg3), pair) < 0) {
            return Fail(errno);
        }
        auto* out = static_cast<int32_t*>(GuestPointer(arg4, sizeof(int32_t) * 2, true));
        if (out == nullptr) {
            close(pair[0]);
            close(pair[1]);
            return FailLinux(14);
        }
        std::scoped_lock lock {mutex_};
        out[0] = static_cast<int32_t>(RegisterFile(pair[0], "socketpair"));
        out[1] = static_cast<int32_t>(RegisterFile(pair[1], "socketpair"));
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
        const std::string from = ResolveAt(old_dirfd, old_path.c_str(), nullptr);
        const std::string to = ResolveAt(new_dirfd, new_path.c_str(), nullptr);
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
        return symlink(target.c_str(), ResolveAt(dirfd, link_path.c_str(), nullptr).c_str()) != 0
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
        std::scoped_lock lock {mutex_};
        auto* file = FindFile(static_cast<int>(arg1));
        if (file == nullptr) {
            return FailLinux(9);
        }
        if (file->guest_path.empty() || file->guest_path.front() != '/') {
            return FailLinux(22); // EINVAL
        }
        cwd_ = file->guest_path;
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
        auto* out = static_cast<uint8_t*>(GuestPointer(number == kSysFstatfs ? arg2 : arg2, 120, true));
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

    case kSysSysinfo:
    case kSysMemfdCreate:
        return FailLinux(38);

    default:
        FATHOM_WARN("unimplemented syscall %llu (%s)", static_cast<unsigned long long>(number),
                    SyscallName(number));
        return FailLinux(38); // ENOSYS
    }
}

} // namespace fathom

#include "guest_syscalls32.h"

#include <unordered_map>

namespace fathom {

int64_t X86_64SyscallForI386(uint64_t i386_number) {
    // Only what a 32-bit program actually reaches for: process startup, files, memory,
    // signals, sockets and time. Anything missing returns -1 and is reported as
    // unimplemented by number, which is exactly the signal needed to add it.
    static const std::unordered_map<uint64_t, int64_t> kTable = {
        {1, 231},    // exit -> exit_group is wrong; exit is 60. Corrected below.
        {2, 57},     // fork
        {3, 0},      // read
        {4, 1},      // write
        {5, 2},      // open
        {6, 3},      // close
        {10, 87},    // unlink
        {11, 59},    // execve
        {12, 80},    // chdir
        {15, 90},    // chmod
        {19, 8},     // lseek
        {20, 39},    // getpid
        {33, 21},    // access
        {37, 62},    // kill
        {38, 82},    // rename
        {39, 83},    // mkdir
        {40, 84},    // rmdir
        {41, 32},    // dup
        {42, 22},    // pipe
        {45, 12},    // brk
        {54, 16},    // ioctl
        {55, 72},    // fcntl
        {57, 109},   // setpgid
        {60, 95},    // umask
        {63, 33},    // dup2
        {64, 110},   // getppid
        {78, 96},    // gettimeofday
        {83, 88},    // symlink
        {85, 89},    // readlink
        {91, 11},    // munmap
        {94, 91},    // fchmod
        {114, 61},   // wait4
        {122, 63},   // uname
        {125, 10},   // mprotect
        {140, 8},    // _llseek -> lseek, reshaped at the call site
        {141, 78},   // getdents
        {143, 73},   // flock
        {145, 19},   // readv
        {146, 20},   // writev
        {162, 35},   // nanosleep
        {168, 7},    // poll
        {174, 13},   // rt_sigaction
        {175, 14},   // rt_sigprocmask
        {183, 79},   // getcwd
        {192, 9},    // mmap2 -> mmap, offset scaled at the call site
        {195, 4},    // stat64 -> stat
        {196, 6},    // lstat64 -> lstat
        {197, 5},    // fstat64 -> fstat
        {199, 102},  // getuid32
        {200, 104},  // getgid32
        {201, 107},  // geteuid32
        {202, 108},  // getegid32
        {207, 93},   // fchown32
        {219, 28},   // madvise
        {220, 217},  // getdents64
        {221, 72},   // fcntl64 -> fcntl
        {224, 186},  // gettid
        {240, 202},  // futex
        {252, 231},  // exit_group
        {258, 218},  // set_tid_address
        {265, 228},  // clock_gettime
        {266, 229},  // clock_getres
        {270, 234},  // tgkill
        {295, 257},  // openat
        {296, 258},  // mkdirat
        {300, 262},  // fstatat64 -> newfstatat
        {301, 263},  // unlinkat
        {302, 264},  // renameat
        {303, 265},  // linkat
        {304, 266},  // symlinkat
        {305, 267},  // readlinkat
        {306, 268},  // fchmodat
        {307, 269},  // faccessat
        {308, 270},  // pselect6
        {309, 271},  // ppoll
        {320, 280},  // utimensat
        {329, 291},  // epoll_create1
        {330, 292},  // dup3
        {331, 293},  // pipe2
        {340, 302},  // prlimit64
        {355, 318},  // getrandom
        {359, 41},   // socket
        {360, 49},   // bind
        {361, 42},   // connect
        {362, 50},   // listen
        {363, 43},   // accept4 -> accept
        {364, 51},   // getsockname
        {365, 52},   // getpeername
        {366, 53},   // socketpair
        {367, 44},   // sendto
        {368, 45},   // recvfrom
        {369, 48},   // shutdown
        {370, 54},   // setsockopt
        {371, 55},   // getsockopt
        {372, 46},   // sendmsg
        {373, 47},   // recvmsg
        {383, 332},  // statx
        {384, 158},  // arch_prctl
        {403, 228},  // clock_gettime64 -> clock_gettime
        {439, 437},  // openat2
    };

    // exit(1) is 60 on x86-64, not exit_group. Corrected here rather than in the table so
    // the table stays a plain transcription.
    if (i386_number == 1) {
        return 60;
    }

    const auto entry = kTable.find(i386_number);
    return entry == kTable.end() ? -1 : entry->second;
}

} // namespace fathom

#include "guest_syscalls32.h"

#include <unordered_map>

namespace fathom {

int64_t X86_64SyscallForI386(uint64_t i386_number) {
    // Only what a 32-bit program actually reaches for: process startup, files, memory,
    // signals, sockets and time. Anything missing returns -1 and is reported as
    // unimplemented by number, which is exactly the signal needed to add it.
    static const std::unordered_map<uint64_t, int64_t> kTable = {
        {1, 60},     // exit
        {2, 57},     // fork
        {3, 0},      // read
        {4, 1},      // write
        {5, 2},      // open
        {6, 3},      // close
        {9, 86},     // link
        {10, 87},    // unlink
        {11, 59},    // execve
        {12, 80},    // chdir
        {14, 133},   // mknod
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
        {104, 38},   // setitimer
        {105, 36},   // getitimer
        {114, 61},   // wait4
        {122, 63},   // uname
        {125, 10},   // mprotect
        {140, -2},   // _llseek: a split 64-bit offset and a result pointer, handled at the call site
        {203, 203},  // sched_setaffinity
        {141, 78},   // getdents
        {143, 73},   // flock
        {144, 26},   // msync
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
        {218, 27},   // mincore
        {219, 28},   // madvise
        {220, 217},  // getdents64
        {221, 72},   // fcntl64 -> fcntl
        {224, 186},  // gettid
        {240, 202},  // futex
        {252, 231},  // exit_group
        {258, 218},  // set_tid_address
        {264, 227},  // clock_settime
        {265, 228},  // clock_gettime
        {266, 229},  // clock_getres
        {267, 230},  // clock_nanosleep
        {270, 234},  // tgkill
        {295, 257},  // openat
        {296, 258},  // mkdirat
        {297, 259},  // mknodat
        {298, 260},  // fchownat
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
        {29, 34},    // pause
        {43, 100},   // times
        {65, 111},   // getpgrp
        {66, 112},   // setsid
        {92, 76},    // truncate
        {93, 77},    // ftruncate
        {102, -2},   // socketcall: the old multiplexed socket entry, unpacked at the call site
        {116, 99},   // sysinfo
        {117, -2},   // ipc: the System V IPC multiplexer, unpacked at the call site
        {120, 56},   // clone
        {126, 14},   // sigprocmask -> rt_sigprocmask
        {132, 121},  // getpgid
        {147, 124},  // getsid
        {148, 75},   // fdatasync
        {150, 149},  // mlock
        {151, 150},  // munlock
        {152, 151},  // mlockall
        {153, 152},  // munlockall
        {158, 24},   // sched_yield
        {159, 146},  // sched_get_priority_max
        {160, 147},  // sched_get_priority_min
        {163, 25},   // mremap
        {172, 157},  // prctl
        {173, 15},   // rt_sigreturn
        {178, 129},  // rt_sigqueueinfo
        {179, 130},  // rt_sigsuspend
        {180, 17},   // pread64
        {181, 18},   // pwrite64
        {186, 131},  // sigaltstack
        {190, 58},   // vfork
        {191, 97},   // ugetrlimit -> getrlimit
        {193, 76},   // truncate64
        {194, 77},   // ftruncate64
        {198, 94},   // lchown32
        {203, 113},  // setreuid32
        {204, 114},  // setregid32
        {205, 115},  // getgroups32
        {208, 117},  // setresuid32
        {209, 118},  // getresuid32
        {210, 119},  // setresgid32
        {211, 120},  // getresgid32
        {212, 92},   // chown32
        {213, 105},  // setuid32
        {214, 106},  // setgid32
        {226, 188},  // setxattr
        {227, 189},  // lsetxattr
        {228, 190},  // fsetxattr
        {229, 191},  // getxattr
        {230, 192},  // lgetxattr
        {231, 193},  // fgetxattr
        {232, 194},  // listxattr
        {233, 195},  // llistxattr
        {234, 196},  // flistxattr
        {235, 197},  // removexattr
        {236, 198},  // lremovexattr
        {237, 199},  // fremovexattr
        {238, 200},  // tkill
        {239, 40},   // sendfile64 -> sendfile
        {242, 203},  // sched_setaffinity
        {250, 221},  // fadvise64
        {254, 213},  // epoll_create
        {255, 233},  // epoll_ctl
        {256, 232},  // epoll_wait
        {268, 137},  // statfs64 -> statfs
        {269, 138},  // fstatfs64 -> fstatfs
        {271, 235},  // utimes
        {272, 221},  // fadvise64_64
        {284, 247},  // waitid
        {291, 253},  // inotify_init
        {292, 254},  // inotify_add_watch
        {293, 255},  // inotify_rm_watch
        {311, 273},  // set_robust_list
        {312, 274},  // get_robust_list
        {313, 275},  // splice
        {315, 277},  // sync_file_range
        {316, 276},  // tee
        {317, 278},  // vmsplice
        {319, 309},  // getcpu
        {321, 282},  // signalfd
        {322, 283},  // timerfd_create
        {323, 284},  // eventfd
        {324, 285},  // fallocate
        {325, 286},  // timerfd_settime
        {326, 287},  // timerfd_gettime
        {327, 289},  // signalfd4
        {328, 290},  // eventfd2
        {332, 294},  // inotify_init1
        {333, 295},  // preadv
        {334, 296},  // pwritev
        {338, 299},  // recvmmsg
        {344, 306},  // syncfs
        {345, 307},  // sendmmsg
        {353, 316},  // renameat2
        {356, 319},  // memfd_create
        {358, 322},  // execveat
        {359, 41},   // socket
        {360, 53},   // socketpair
        {361, 49},   // bind
        {362, 42},   // connect
        {363, 50},   // listen
        {364, 288},  // accept4
        {365, 55},   // getsockopt
        {366, 54},   // setsockopt
        {367, 51},   // getsockname
        {368, 52},   // getpeername
        {369, 44},   // sendto
        {370, 46},   // sendmsg
        {371, 45},   // recvfrom
        {372, 47},   // recvmsg
        {373, 48},   // shutdown
        {374, 323},  // userfaultfd
        {375, 324},  // membarrier
        {376, 325},  // mlock2
        {377, 326},  // copy_file_range
        {378, 327},  // preadv2
        {379, 328},  // pwritev2
        {383, 332},  // statx
        {384, 158},  // arch_prctl
        {386, 334},  // rseq
        {403, 228},  // clock_gettime64 -> clock_gettime
        {404, 227},  // clock_settime64
        {406, 229},  // clock_getres_time64
        {407, 230},  // clock_nanosleep_time64
        {412, 280},  // utimensat_time64
        {413, 270},  // pselect6_time64
        {414, 271},  // ppoll_time64
        {417, 299},  // recvmmsg_time64
        {422, 202},  // futex_time64
        {435, 435},  // clone3
        {437, 437},  // openat2
        {439, 439},  // faccessat2
        {441, 441},  // epoll_pwait2
    };

    const auto entry = kTable.find(i386_number);
    return entry == kTable.end() ? -1 : entry->second;
}

bool IsI386NarrowTime(uint64_t i386_number) {
    switch (i386_number) {
    case 78:   // gettimeofday
    case 79:   // settimeofday
    case 142:  // _newselect
    case 162:  // nanosleep
    case 168:  // poll takes a plain millisecond count, but ppoll below does not
    case 264:  // clock_settime
    case 265:  // clock_gettime
    case 266:  // clock_getres
    case 267:  // clock_nanosleep
    case 240:  // futex
    case 271:  // utimes
    case 308:  // pselect6
    case 309:  // ppoll
    case 320:  // utimensat
        return true;
    default:
        return false;
    }
}

} // namespace fathom

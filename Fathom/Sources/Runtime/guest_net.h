// guest_net.h -- translating between Linux's socket ABI and Darwin's.
//
// Sockets look like the one part of Unix everybody agrees on, and then they are not. The
// disagreements are small, silent, and each one breaks a connection in a way that looks
// like a network problem rather than a translation bug:
//
//   * A socket address begins with a 16-bit family on Linux. On Darwin it begins with a
//     one-byte length and then a one-byte family. Handing a Linux sockaddr straight to
//     Darwin's connect() gives it family 0 and a nonsense length.
//   * AF_INET6 is 10 on Linux and 30 on Darwin. AF_INET and AF_UNIX happen to agree,
//     which makes the one that does not agree easy to miss.
//   * SOL_SOCKET is 1 on Linux and 0xFFFF on Darwin, and almost every SO_* constant under
//     it differs too.
//   * Linux packs SOCK_NONBLOCK and SOCK_CLOEXEC into the socket type; Darwin has no such
//     thing and rejects the type outright.
#pragma once

#include <cstdint>
#include <sys/socket.h>

namespace fathom::net {

/// Linux address families, as the guest knows them.
constexpr int kGuestAfUnix = 1;
constexpr int kGuestAfInet = 2;
constexpr int kGuestAfInet6 = 10;

/// Flags Linux allows to be folded into the socket type.
constexpr int kGuestSockNonblock = 0o4000;   // 0x800
constexpr int kGuestSockCloexec = 0o2000000; // 0x80000

/// Maps a Linux address family onto the host's. Returns -1 for one the host cannot serve.
int HostDomain(int guest_domain);

/// Strips Linux's type flags, reporting them separately, and returns the bare host type.
int HostType(int guest_type, bool* nonblocking, bool* cloexec);

/// Maps a Linux setsockopt/getsockopt level onto the host's, or -1.
int HostLevel(int guest_level);

/// Maps a Linux socket option onto the host's, or -1 for one with no equivalent.
int HostOption(int guest_level, int guest_option);

/// Rewrites a guest sockaddr into `out` in the host's layout. Returns the host address
/// length, or 0 if the family is not one this can translate.
socklen_t ToHostAddress(const void* guest_address, uint64_t guest_length, sockaddr_storage* out);

/// Rewrites a host sockaddr into the guest's layout at `guest_address`, writing at most
/// `capacity` bytes. Returns the length the guest should be told the address really is,
/// which may exceed `capacity` exactly as Linux reports it.
socklen_t ToGuestAddress(const sockaddr* host_address, void* guest_address, uint64_t capacity);

} // namespace fathom::net

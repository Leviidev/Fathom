#include "guest_net.h"

#include <algorithm>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>

namespace fathom::net {

int HostDomain(int guest_domain) {
    switch (guest_domain) {
    case kGuestAfUnix: return AF_UNIX;
    case kGuestAfInet: return AF_INET;
    case kGuestAfInet6: return AF_INET6;
    default: return -1;
    }
}

int HostType(int guest_type, bool* nonblocking, bool* cloexec) {
    if (nonblocking != nullptr) {
        *nonblocking = (guest_type & kGuestSockNonblock) != 0;
    }
    if (cloexec != nullptr) {
        *cloexec = (guest_type & kGuestSockCloexec) != 0;
    }
    return guest_type & ~(kGuestSockNonblock | kGuestSockCloexec);
}

int HostLevel(int guest_level) {
    switch (guest_level) {
    case 1: return SOL_SOCKET;   // Linux SOL_SOCKET
    case 0: return IPPROTO_IP;
    case 6: return IPPROTO_TCP;
    case 17: return IPPROTO_UDP;
    case 41: return IPPROTO_IPV6;
    default: return guest_level;
    }
}

int HostOption(int guest_level, int guest_option) {
    if (guest_level != 1) {
        // Outside SOL_SOCKET the numbers line up: TCP_NODELAY is 1 on both, and the IP
        // and IPv6 options a client uses agree as well.
        return guest_option;
    }
    switch (guest_option) {
    case 1: return SO_DEBUG;
    case 2: return SO_REUSEADDR;
    case 3: return SO_TYPE;
    case 4: return SO_ERROR;
    case 5: return SO_DONTROUTE;
    case 6: return SO_BROADCAST;
    case 7: return SO_SNDBUF;
    case 8: return SO_RCVBUF;
    case 9: return SO_KEEPALIVE;
    case 10: return SO_OOBINLINE;
    case 13: return SO_LINGER;
    case 15: return SO_REUSEPORT;
    case 20: return SO_RCVTIMEO;
    case 21: return SO_SNDTIMEO;
    default: return -1;  // No equivalent; the caller answers 0 rather than failing.
    }
}

socklen_t ToHostAddress(const void* guest_address, uint64_t guest_length, sockaddr_storage* out) {
    if (guest_address == nullptr || out == nullptr || guest_length < 2) {
        return 0;
    }
    std::memset(out, 0, sizeof(*out));

    uint16_t family = 0;
    std::memcpy(&family, guest_address, sizeof(family));
    const auto* bytes = static_cast<const uint8_t*>(guest_address);

    switch (family) {
    case kGuestAfInet: {
        if (guest_length < 8) {
            return 0;
        }
        auto* inet = reinterpret_cast<sockaddr_in*>(out);
        inet->sin_len = sizeof(sockaddr_in);
        inet->sin_family = AF_INET;
        std::memcpy(&inet->sin_port, bytes + 2, 2);      // already network order
        std::memcpy(&inet->sin_addr, bytes + 4, 4);
        return sizeof(sockaddr_in);
    }
    case kGuestAfInet6: {
        if (guest_length < 24) {
            return 0;
        }
        auto* inet6 = reinterpret_cast<sockaddr_in6*>(out);
        inet6->sin6_len = sizeof(sockaddr_in6);
        inet6->sin6_family = AF_INET6;
        std::memcpy(&inet6->sin6_port, bytes + 2, 2);
        std::memcpy(&inet6->sin6_flowinfo, bytes + 4, 4);
        std::memcpy(&inet6->sin6_addr, bytes + 8, 16);
        if (guest_length >= 28) {
            std::memcpy(&inet6->sin6_scope_id, bytes + 24, 4);
        }
        return sizeof(sockaddr_in6);
    }
    case kGuestAfUnix: {
        auto* un = reinterpret_cast<sockaddr_un*>(out);
        un->sun_family = AF_UNIX;
        const uint64_t path_length = guest_length > 2 ? guest_length - 2 : 0;
        const size_t copied = std::min<size_t>(path_length, sizeof(un->sun_path) - 1);
        std::memcpy(un->sun_path, bytes + 2, copied);
        un->sun_path[copied] = '\0';
        un->sun_len = static_cast<uint8_t>(sizeof(sockaddr_un));
        return sizeof(sockaddr_un);
    }
    default:
        return 0;
    }
}

socklen_t ToGuestAddress(const sockaddr* host_address, void* guest_address, uint64_t capacity) {
    if (host_address == nullptr || guest_address == nullptr) {
        return 0;
    }
    uint8_t scratch[128] = {};
    socklen_t produced = 0;

    switch (host_address->sa_family) {
    case AF_INET: {
        const auto* inet = reinterpret_cast<const sockaddr_in*>(host_address);
        const uint16_t family = kGuestAfInet;
        std::memcpy(scratch, &family, 2);
        std::memcpy(scratch + 2, &inet->sin_port, 2);
        std::memcpy(scratch + 4, &inet->sin_addr, 4);
        produced = 16;
        break;
    }
    case AF_INET6: {
        const auto* inet6 = reinterpret_cast<const sockaddr_in6*>(host_address);
        const uint16_t family = kGuestAfInet6;
        std::memcpy(scratch, &family, 2);
        std::memcpy(scratch + 2, &inet6->sin6_port, 2);
        std::memcpy(scratch + 4, &inet6->sin6_flowinfo, 4);
        std::memcpy(scratch + 8, &inet6->sin6_addr, 16);
        std::memcpy(scratch + 24, &inet6->sin6_scope_id, 4);
        produced = 28;
        break;
    }
    case AF_UNIX: {
        const auto* un = reinterpret_cast<const sockaddr_un*>(host_address);
        const uint16_t family = kGuestAfUnix;
        std::memcpy(scratch, &family, 2);
        const size_t path_length = strnlen(un->sun_path, sizeof(un->sun_path));
        std::memcpy(scratch + 2, un->sun_path, path_length);
        produced = static_cast<socklen_t>(2 + path_length + 1);
        break;
    }
    default:
        return 0;
    }

    // Linux truncates into the caller's buffer but still reports the full length, which
    // is how a caller learns its buffer was too small.
    const uint64_t copied = std::min<uint64_t>(capacity, produced);
    std::memcpy(guest_address, scratch, copied);
    return produced;
}

} // namespace fathom::net

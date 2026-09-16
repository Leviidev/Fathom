#include "guest_path.h"

#include <climits>
#include <deque>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fathom {
namespace {

/// A symlink chain longer than this is a loop as far as anyone is concerned; Linux uses
/// the same limit and answers ELOOP.
constexpr int kMaxSymlinkHops = 40;

std::deque<std::string> Split(const std::string& path) {
    std::deque<std::string> parts;
    size_t index = 0;
    while (index < path.size()) {
        while (index < path.size() && path[index] == '/') {
            ++index;
        }
        const size_t start = index;
        while (index < path.size() && path[index] != '/') {
            ++index;
        }
        if (start != index) {
            parts.push_back(path.substr(start, index - start));
        }
    }
    return parts;
}

std::string Join(const std::string& root, const std::vector<std::string>& parts) {
    std::string result = root;
    for (const auto& part : parts) {
        result += '/';
        result += part;
    }
    return result;
}

} // namespace

std::string ResolveGuestPathOnHost(const std::string& guest_root, const std::string& guest_path,
                                   bool follow_final) {
    if (guest_root.empty()) {
        return guest_path;
    }

    std::deque<std::string> pending = Split(guest_path);
    std::vector<std::string> resolved;
    int hops = 0;

    while (!pending.empty()) {
        const std::string part = pending.front();
        pending.pop_front();

        if (part == ".") {
            continue;
        }
        if (part == "..") {
            // At the root ".." is the root, which is also what stops a guest climbing out.
            if (!resolved.empty()) {
                resolved.pop_back();
            }
            continue;
        }

        resolved.push_back(part);

        // The last component, when the caller is operating on the link rather than
        // through it.
        if (!follow_final && pending.empty()) {
            break;
        }

        const std::string host = Join(guest_root, resolved);

        struct stat info {};
        if (lstat(host.c_str(), &info) != 0 || !S_ISLNK(info.st_mode)) {
            continue;  // Not a link, or does not exist: either way, nothing to follow.
        }
        if (++hops > kMaxSymlinkHops) {
            break;  // Give up and let the caller's open() fail on what we have.
        }

        char target[PATH_MAX];
        const ssize_t length = readlink(host.c_str(), target, sizeof(target) - 1);
        if (length <= 0) {
            continue;
        }
        target[length] = '\0';

        // The link itself is replaced by what it points at, and anything still queued
        // behind it follows the target rather than the link.
        resolved.pop_back();
        if (target[0] == '/') {
            resolved.clear();
        }
        const auto pieces = Split(target);
        for (auto piece = pieces.rbegin(); piece != pieces.rend(); ++piece) {
            pending.push_front(*piece);
        }
    }

    return resolved.empty() ? guest_root : Join(guest_root, resolved);
}

std::string GuestPathForHostPath(const std::string& guest_root, const std::string& host_path) {
    if (guest_root.empty() || host_path.size() < guest_root.size() ||
        host_path.compare(0, guest_root.size(), guest_root) != 0) {
        return {};
    }
    std::string remainder = host_path.substr(guest_root.size());
    if (remainder.empty()) {
        return "/";
    }
    return remainder.front() == '/' ? remainder : "/" + remainder;
}

} // namespace fathom

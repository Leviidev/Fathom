// guest_path.h -- turning a guest path into a host path, the way the guest's kernel would.
//
// The guest's root filesystem is a directory inside the app container, and the symlinks
// in it are stored exactly as the distribution wrote them. Alpine's /bin/sh is a link to
// "/bin/busybox" -- an absolute path in the *guest's* world. Handing that to the host's
// open() resolves it against the host's root, where there is no /bin/busybox, so the
// open fails and every one of the ~300 commands in /bin is unreachable.
//
// Resolving symlinks here, against the guest root, is what makes them mean what the guest
// means by them.
#pragma once

#include <string>

namespace fathom {

/// Maps `guest_path` (guest-absolute, already normalised or not) to a host path beneath
/// `guest_root`, following symlinks with guest semantics: an absolute link target restarts
/// at the guest root rather than the host's.
///
/// A path that does not exist is still mapped, so the caller's own open() reports the
/// error rather than this having to invent one.
/// `follow_final` false stops at the last component instead of following it, which is
/// what every operation that acts on a symlink *itself* needs: unlink, lstat, rename,
/// readlink and creating a link where one already exists. Following it there deletes or
/// inspects whatever the link points at instead of the link, and a program removing a
/// directory tree then finds the tree still full of links it thought it had deleted.
std::string ResolveGuestPathOnHost(const std::string& guest_root, const std::string& guest_path,
                                   bool follow_final = true);

/// The inverse, for a host path already known to sit inside the guest root: the guest-
/// absolute path it corresponds to, or an empty string if it is not inside the root.
std::string GuestPathForHostPath(const std::string& guest_root, const std::string& host_path);

} // namespace fathom

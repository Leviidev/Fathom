// GuestRootfs.swift -- installing the Linux root filesystem the guest runs inside.
//
// A dynamically linked program does not carry its libraries with it. It names an
// interpreter -- /lib/ld-musl-x86_64.so.1 -- and expects the kernel to have a filesystem
// where that, and every library it goes on to open, can be found. Static binaries needed
// none of this, which is why Fathom got this far without one.
//
// The filesystem ships inside the app as a tar and is unpacked into Documents on first
// launch, because Fathom has no networking yet and so has no way to fetch one on device.
// Unpacking into Documents rather than reading it out of the bundle is what makes it
// writable: the guest can create files, and they survive the app being closed.

import Foundation

enum GuestRootfs {
    /// Bumping this re-installs over the existing root on next launch. Files the guest
    /// created are left alone; only what the tar carries is overwritten.
    static let version = "alpine-3.22.5"

    private static var stampURL: URL {
        ProgramLibrary.guestRootDirectory.appendingPathComponent(".fathom-rootfs", isDirectory: false)
    }

    static var isInstalled: Bool {
        (try? String(contentsOf: stampURL, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) == version
    }

    /// Whether this root filesystem has Steam in it. Steam is not part of the root
    /// filesystem itself -- it is installed into it -- so the launcher's presence is what
    /// says whether there is anything to show.
    static var hasSteam: Bool {
        FileManager.default.isReadableFile(
            atPath: ProgramLibrary.guestRootDirectory.appendingPathComponent("usr/local/bin/fathom-steam").path)
    }

    /// Unpacks the bundled root filesystem unless the installed one is already current.
    /// Cheap to call on every launch; it does nothing once the stamp matches.
    static func installIfNeeded() throws {
        if isInstalled {
            return
        }
        guard let source = Bundle.main.url(forResource: "guest-rootfs", withExtension: "tar") else {
            throw RootfsError.missingFromBundle
        }

        let root = ProgramLibrary.guestRootDirectory
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        log("installing guest root filesystem (\(version))")
        let started = Date()
        let archive = try Data(contentsOf: source, options: .mappedIfSafe)
        let count = try extract(archive, into: root)
        try version.write(to: stampURL, atomically: true, encoding: .utf8)

        let elapsed = Date().timeIntervalSince(started)
        log(String(format: "guest root filesystem ready: %d entries in %.1fs", count, elapsed))
    }

    // MARK: - tar

    enum RootfsError: LocalizedError {
        case missingFromBundle
        case malformed(String)

        var errorDescription: String? {
            switch self {
            case .missingFromBundle:
                return "the guest root filesystem is missing from the app bundle"
            case let .malformed(detail):
                return "the guest root filesystem archive is malformed: \(detail)"
            }
        }
    }

    /// A ustar reader covering exactly what a root filesystem contains: files,
    /// directories, symlinks and hard links. Most of an Alpine root is symlinks -- every
    /// one of the ~300 commands in /bin is a link to busybox -- so those are not an
    /// optional extra here.
    static func extract(_ archive: Data, into root: URL) throws -> Int {
        let manager = FileManager.default
        let blockSize = 512
        var offset = 0
        var installed = 0
        // GNU tar stores a name too long for the 100-byte field in a preceding entry.
        var pendingLongName: String?

        func field(_ base: Int, _ length: Int) -> String {
            let bytes = archive[(offset + base)..<(offset + base + length)]
            let trimmed = bytes.prefix { $0 != 0 }
            return String(decoding: trimmed, as: UTF8.self)
                .trimmingCharacters(in: .whitespaces)
        }

        func octal(_ base: Int, _ length: Int) -> Int {
            Int(field(base, length), radix: 8) ?? 0
        }

        while offset + blockSize <= archive.count {
            let name = field(0, 100)
            if name.isEmpty {
                break  // Two zero blocks end the archive.
            }

            let size = octal(124, 12)
            let mode = octal(100, 8)
            let type = archive[offset + 156]
            let linkName = field(157, 100)
            let prefix = field(345, 155)

            var path = prefix.isEmpty ? name : "\(prefix)/\(name)"
            if let long = pendingLongName {
                path = long
                pendingLongName = nil
            }
            offset += blockSize

            let payload = offset
            offset += (size + blockSize - 1) / blockSize * blockSize

            // 'L' is the long-name entry itself: its payload is the next entry's path.
            if type == UInt8(ascii: "L") {
                pendingLongName = String(decoding: archive[payload..<(payload + size)].prefix { $0 != 0 },
                                         as: UTF8.self)
                continue
            }

            guard let destination = resolve(path, under: root) else {
                continue  // A path trying to climb out of the root is simply skipped.
            }

            switch type {
            case UInt8(ascii: "5"):
                try manager.createDirectory(at: destination, withIntermediateDirectories: true)

            case UInt8(ascii: "2"):
                try manager.createDirectory(at: destination.deletingLastPathComponent(),
                                            withIntermediateDirectories: true)
                try? manager.removeItem(at: destination)
                // Stored verbatim: a symlink's target is resolved by the guest, against
                // the guest's root, not by the host filesystem here.
                try manager.createSymbolicLink(atPath: destination.path, withDestinationPath: linkName)

            case UInt8(ascii: "1"):
                guard let existing = resolve(linkName, under: root) else { break }
                try manager.createDirectory(at: destination.deletingLastPathComponent(),
                                            withIntermediateDirectories: true)
                try? manager.removeItem(at: destination)
                try manager.linkItem(at: existing, to: destination)

            case UInt8(ascii: "0"), 0:
                try manager.createDirectory(at: destination.deletingLastPathComponent(),
                                            withIntermediateDirectories: true)
                guard payload + size <= archive.count else {
                    throw RootfsError.malformed("entry \(path) runs past the end")
                }
                try archive[payload..<(payload + size)].write(to: destination, options: .atomic)
                // The executable bit has to survive, or /bin/busybox is just a file.
                try? manager.setAttributes([.posixPermissions: mode], ofItemAtPath: destination.path)

            default:
                continue  // Character devices, FIFOs and the rest: not in a minirootfs.
            }
            installed += 1
        }
        return installed
    }

    /// Joins a tar path onto the root, refusing anything that would escape it.
    static func resolve(_ path: String, under root: URL) -> URL? {
        var parts: [String] = []
        for piece in path.split(separator: "/") {
            switch piece {
            case ".", "":
                continue
            case "..":
                if parts.isEmpty { return nil }
                parts.removeLast()
            default:
                parts.append(String(piece))
            }
        }
        guard !parts.isEmpty else { return nil }
        return parts.reduce(root) { $0.appendingPathComponent($1) }
    }
}

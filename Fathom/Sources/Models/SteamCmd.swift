import Compression
import CryptoKit
import Foundation

/// Valve's command-line Steam client, running inside the guest root, is how Fathom
/// downloads games: it speaks Steam's own download protocol, so nothing has to be
/// reimplemented, and it signs in with the user's own account and nothing else.
///
/// It is a 32-bit glibc program and the guest root is Alpine (musl), so installing it
/// means fetching steamcmd itself plus Debian's 32-bit C library and unpacking both into
/// the root. Everything downloaded is pinned by checksum.
@MainActor
final class SteamCmd: ObservableObject {
    static let shared = SteamCmd()

    enum Phase: Equatable {
        case missing
        case installing(String, Double)
        case ready
        case failed(String)
    }

    @Published private(set) var phase: Phase

    struct Artifact {
        let name: String
        let url: URL
        let sha256: String
        let kind: Kind
        enum Kind { case tarGz(into: String), deb }
    }

    /// What gets fetched, and exactly which bytes are accepted. The Debian files come from the
    /// permanent snapshot archive as well, for when a point release moves them out of the pool.
    static let artifacts: [Artifact] = [
        Artifact(name: "steamcmd",
                 url: URL(string: "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz")!,
                 sha256: "cebf0046bfd08cf45da6bc094ae47aa39ebf4155e5ede41373b579b8f1071e7c",
                 kind: .tarGz(into: "opt/steamcmd")),
        Artifact(name: "32-bit C library",
                 url: URL(string: "https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u14_i386.deb")!,
                 sha256: "76b12e06be66ec3fc2c1791d7d8cf34c2b828ed210e3913feeeb8edc9688f820",
                 kind: .deb),
        Artifact(name: "32-bit GCC runtime",
                 url: URL(string: "https://deb.debian.org/debian/pool/main/g/gcc-12/libgcc-s1_12.2.0-14+deb12u1_i386.deb")!,
                 sha256: "56b95a550b342418f6c4765d5c9b08df2c7167134767e44f1f1bc82ced363ece",
                 kind: .deb),
    ]

    static let version = "steamcmd-1"
    static var root: URL { ProgramLibrary.guestRootDirectory }
    private static var stamp: URL { root.appendingPathComponent(".fathom-steamcmd") }

    static var isInstalled: Bool {
        (try? String(contentsOf: stamp, encoding: .utf8)) == version
            && FileManager.default.fileExists(atPath: root.appendingPathComponent("opt/steamcmd/linux32/steamcmd").path)
            && FileManager.default.fileExists(atPath: root.appendingPathComponent("lib/i386-linux-gnu/libc.so.6").path)
    }

    private init() {
        phase = Self.isInstalled ? .ready : .missing
    }

    // MARK: - Installing

    func install() async {
        if case .installing = phase { return }
        let root = Self.root
        do {
            let steps = Double(Self.artifacts.count + 1)
            for (index, artifact) in Self.artifacts.enumerated() {
                phase = .installing("Downloading \(artifact.name)", Double(index) / steps)
                let data = try await Self.fetch(artifact)
                phase = .installing("Unpacking \(artifact.name)", (Double(index) + 0.6) / steps)
                try await Task.detached(priority: .userInitiated) {
                    switch artifact.kind {
                    case .tarGz(let into):
                        let target = root.appendingPathComponent(into, isDirectory: true)
                        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
                        _ = try GuestRootfs.extract(try Decompress.gzip(data), into: target)
                    case .deb:
                        _ = try GuestRootfs.extract(try Decompress.xz(try Self.debData(data)), into: root)
                    }
                }.value
            }
            phase = .installing("Finishing", (steps - 1) / steps)
            try Self.prepareRoot()
            try Self.version.write(to: Self.stamp, atomically: true, encoding: .utf8)
            phase = .ready
            log("steamcmd installed into the guest root")
        } catch {
            phase = .failed(error.localizedDescription)
            log("steamcmd install failed: \(error.localizedDescription)", level: .error)
        }
    }

    func remove() {
        for path in ["opt/steamcmd", ".fathom-steamcmd"] {
            try? FileManager.default.removeItem(at: Self.root.appendingPathComponent(path))
        }
        phase = .missing
    }

    /// What steamcmd expects of the root beyond its own files.
    private static func prepareRoot() throws {
        let manager = FileManager.default
        for directory in ["root/games", "tmp/dumps", "dev/shm", "dev/pts", "etc/ssl/certs"] {
            try manager.createDirectory(at: root.appendingPathComponent(directory), withIntermediateDirectories: true)
        }
        // The certificate bundle where a Debian-built program looks for it; Alpine keeps the
        // same bundle under another name.
        let bundle = root.appendingPathComponent("etc/ssl/certs/ca-certificates.crt")
        let alpine = root.appendingPathComponent("etc/ssl/cert.pem")
        if !manager.fileExists(atPath: bundle.path), manager.fileExists(atPath: alpine.path) {
            try manager.copyItem(at: alpine, to: bundle)
        }
        // A user for the id the emulator reports (1000). Steam's client looks itself up by
        // uid and quits without a word when there is no such user; Alpine ships only root.
        for (file, entry) in [("etc/passwd", "fathom:x:1000:1000:Fathom:/root:/bin/sh"), ("etc/group", "fathom:x:1000:")] {
            let url = root.appendingPathComponent(file)
            var text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            if !text.contains(":1000:") {
                if !text.isEmpty, !text.hasSuffix("\n") { text += "\n" }
                text += entry + "\n"
                try text.write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    private static func fetch(_ artifact: Artifact) async throws -> Data {
        var request = URLRequest(url: artifact.url)
        request.timeoutInterval = 120
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse).map({ (200..<300).contains($0.statusCode) }) ?? true else {
            throw SteamError("Could not download \(artifact.name) (HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)).")
        }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard digest == artifact.sha256 else {
            throw SteamError("\(artifact.name) did not match its checksum; not installing it.")
        }
        return data
    }

    /// The data.tar.xz member of a .deb, which is an `ar` archive.
    nonisolated private static func debData(_ deb: Data) throws -> Data {
        guard deb.count > 8, deb.prefix(8) == Data("!<arch>\n".utf8) else { throw SteamError("Not a Debian package.") }
        var offset = 8
        while offset + 60 <= deb.count {
            let header = deb[offset..<offset + 60]
            let name = String(decoding: header.prefix(16), as: UTF8.self).trimmingCharacters(in: .whitespaces)
            let sizeText = String(decoding: header[(header.startIndex + 48)..<(header.startIndex + 58)], as: UTF8.self)
                .trimmingCharacters(in: .whitespaces)
            guard let size = Int(sizeText) else { throw SteamError("Malformed Debian package.") }
            let start = offset + 60
            guard start + size <= deb.count else { throw SteamError("Truncated Debian package.") }
            if name.hasPrefix("data.tar.xz") {
                return deb.subdata(in: start..<start + size)
            }
            offset = start + size + (size % 2)
        }
        throw SteamError("The Debian package holds no data.tar.xz.")
    }

    // MARK: - Running

    /// Where a game's files go: inside the guest root, under Fathom's Documents, so they
    /// show in the Files app as well.
    static func installDirectory(for appid: Int) -> URL {
        root.appendingPathComponent("root/games/\(appid)", isDirectory: true)
    }

    static func guestInstallDirectory(for appid: Int) -> String {
        "/root/games/\(appid)"
    }

    /// Whether steamcmd finished installing the app: its manifest says fully installed (4).
    static func isGameInstalled(_ appid: Int) -> Bool {
        let manifest = installDirectory(for: appid).appendingPathComponent("steamapps/appmanifest_\(appid).acf")
        guard let text = try? String(contentsOf: manifest, encoding: .utf8) else { return false }
        return text.range(of: #""StateFlags"\s*"4""#, options: .regularExpression) != nil
    }

    static func installedSize(_ appid: Int) -> UInt64 {
        let directory = installDirectory(for: appid)
        guard let walker = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: [.fileSizeKey]) else { return 0 }
        var total: UInt64 = 0
        for case let url as URL in walker {
            total += UInt64((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        }
        return total
    }

    static let guestProgram = "/opt/steamcmd/linux32/steamcmd"
    static let environment = ["HOME=/root", "USER=root", "LD_LIBRARY_PATH=/opt/steamcmd/linux32"]
    static let workDirectory = "/opt/steamcmd"

    /// steamcmd's script for one download. The account is the one signed in to Fathom, or
    /// anonymous for the free content that allows it; steamcmd asks for the password and the
    /// Steam Guard code itself, in its console, and remembers the sign-in afterwards.
    static func arguments(appid: Int, account: String?) -> [String] {
        ["+@ShutdownOnFailedCommand", "1", "+@NoPromptForPassword", "0",
         "+force_install_dir", guestInstallDirectory(for: appid),
         "+login", account?.isEmpty == false ? account! : "anonymous",
         "+app_update", "\(appid)", "validate", "+quit"]
    }
}

/// gzip and xz, through the system's decompressor.
enum Decompress {
    static func gzip(_ data: Data) throws -> Data {
        guard data.count > 18, data[0] == 0x1f, data[1] == 0x8b, data[2] == 8 else { throw SteamError("Not a gzip file.") }
        let flags = data[3]
        var offset = 10
        if flags & 0x04 != 0 { // extra field
            guard offset + 2 <= data.count else { throw SteamError("Truncated gzip header.") }
            offset += 2 + Int(data[offset]) + Int(data[offset + 1]) << 8
        }
        if flags & 0x08 != 0 { while offset < data.count && data[offset] != 0 { offset += 1 }; offset += 1 } // name
        if flags & 0x10 != 0 { while offset < data.count && data[offset] != 0 { offset += 1 }; offset += 1 } // comment
        if flags & 0x02 != 0 { offset += 2 } // header crc
        guard offset < data.count else { throw SteamError("Truncated gzip header.") }
        return try inflate(data.subdata(in: offset..<data.count - 8), algorithm: COMPRESSION_ZLIB)
    }

    static func xz(_ data: Data) throws -> Data {
        try inflate(data, algorithm: COMPRESSION_LZMA)
    }

    private static func inflate(_ input: Data, algorithm: compression_algorithm) throws -> Data {
        var output = Data()
        let chunk = 1 << 20
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
        defer { buffer.deallocate() }
        var stream = compression_stream(dst_ptr: buffer, dst_size: chunk, src_ptr: buffer, src_size: 0, state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, algorithm) == COMPRESSION_STATUS_OK else {
            throw SteamError("The decompressor could not start.")
        }
        defer { compression_stream_destroy(&stream) }
        try input.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            stream.src_ptr = raw.bindMemory(to: UInt8.self).baseAddress!
            stream.src_size = raw.count
            while true {
                stream.dst_ptr = buffer
                stream.dst_size = chunk
                let status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                output.append(buffer, count: chunk - stream.dst_size)
                if status == COMPRESSION_STATUS_END { break }
                guard status == COMPRESSION_STATUS_OK else { throw SteamError("The archive is corrupt.") }
            }
        }
        return output
    }
}

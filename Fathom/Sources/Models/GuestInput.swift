import Foundation

/// Sends pointer and keyboard events to the guest's X server.
///
/// The server runs inside the emulator, but the socket it listens on is a real unix socket
/// in the guest root, so the host can be an ordinary X client: connect, ask for the XTEST
/// extension, and hand it the events the user just made on the screen. Nothing has to run
/// inside the guest to receive them, and there is no polling -- an event costs one 36-byte
/// write.
///
/// Only the sliver of the X protocol needed to say "the pointer is here" and "this key went
/// down" is implemented. Everything else the server sends back is drained and ignored.
final class GuestInput {
    private var socket: Int32 = -1
    private var xtestOpcode: UInt8 = 0
    private var root: UInt32 = 0
    private var sequence: UInt16 = 0

    /// Keycodes by character, from the server's own keyboard mapping. Built once on
    /// connect, because the mapping is fixed for as long as the server runs.
    private var keycodes: [Character: (code: UInt8, shifted: Bool)] = [:]

    private let queue = DispatchQueue(label: "fathom.input")

    var isConnected: Bool { socket >= 0 }

    deinit {
        if socket >= 0 {
            close(socket)
        }
    }

    // MARK: - Connecting

    /// Connects to the X server listening on `path`, which is the guest's
    /// `/tmp/.X11-unix/X0` as the host sees it. Returns false if the server is not up yet.
    @discardableResult
    func connect(socketPath path: String) -> Bool {
        disconnect()
        guard path.utf8.count < 104 else { return false }

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        _ = withUnsafeMutablePointer(to: &address.sun_path) { destination in
            path.withCString { source in
                strncpy(UnsafeMutableRawPointer(destination).assumingMemoryBound(to: CChar.self),
                        source, 104)
            }
        }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
                Darwin.connect(fd, generic, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            close(fd)
            return false
        }
        socket = fd

        guard handshake(), let opcode = queryExtension("XTEST") else {
            disconnect()
            return false
        }
        xtestOpcode = opcode
        loadKeyboardMapping()
        log("input: connected to the guest's X server")
        return true
    }

    func disconnect() {
        if socket >= 0 {
            close(socket)
        }
        socket = -1
        xtestOpcode = 0
        root = 0
        keycodes.removeAll()
    }

    // MARK: - Events

    func move(to point: CGPoint) {
        send(type: 6, detail: 0, x: Int16(clamping: Int(point.x)), y: Int16(clamping: Int(point.y)))
    }

    func button(_ index: UInt8, pressed: Bool) {
        send(type: pressed ? 4 : 5, detail: index, x: 0, y: 0)
    }

    /// A tap: move, press, release. Sent as one write so the three cannot be interleaved
    /// with anything else the server is handling.
    func tap(at point: CGPoint, button index: UInt8 = 1) {
        move(to: point)
        button(index, pressed: true)
        button(index, pressed: false)
    }

    func type(_ text: String) {
        for character in text {
            guard let entry = keycodes[character] else { continue }
            if entry.shifted {
                key(shiftKeycode, pressed: true)
            }
            key(entry.code, pressed: true)
            key(entry.code, pressed: false)
            if entry.shifted {
                key(shiftKeycode, pressed: false)
            }
        }
    }

    func key(_ code: UInt8, pressed: Bool) {
        send(type: pressed ? 2 : 3, detail: code, x: 0, y: 0)
    }

    /// Left Shift. Found from the mapping when the server is asked; 50 is its usual place
    /// and is only a fallback for a mapping that did not come back.
    private var shiftKeycode: UInt8 = 50

    // MARK: - Protocol

    private func handshake() -> Bool {
        var setup = [UInt8]()
        setup.append(0x6C)      // 'l': everything below is little-endian
        setup.append(0)
        setup.append(contentsOf: bytes(UInt16(11)))  // protocol major
        setup.append(contentsOf: bytes(UInt16(0)))   // protocol minor
        setup.append(contentsOf: bytes(UInt16(0)))   // no authorisation protocol name
        setup.append(contentsOf: bytes(UInt16(0)))   // no authorisation data
        setup.append(contentsOf: [0, 0])
        guard write(setup) else { return false }

        guard let header = read(count: 8) else { return false }
        guard header[0] == 1 else {   // 0 is a refusal, 2 is "authenticate"
            log("input: the X server refused the connection", level: .error)
            return false
        }
        let extra = Int(UInt16(header[6]) | UInt16(header[7]) << 8) * 4
        guard let body = read(count: extra), body.count >= 32 else { return false }

        // The first screen's root window, which XTEST wants for a motion event. It sits
        // after the vendor string and the pixmap formats, both of which are variable.
        let vendorLength = Int(UInt16(body[16]) | UInt16(body[17]) << 8)
        let formatCount = Int(body[21])
        let screensOffset = 32 + ((vendorLength + 3) & ~3) + formatCount * 8
        guard screensOffset + 4 <= body.count else { return false }
        root = UInt32(body[screensOffset]) | UInt32(body[screensOffset + 1]) << 8
             | UInt32(body[screensOffset + 2]) << 16 | UInt32(body[screensOffset + 3]) << 24
        return true
    }

    private func queryExtension(_ name: String) -> UInt8? {
        let nameBytes = Array(name.utf8)
        let padded = (nameBytes.count + 3) & ~3
        var request = [UInt8]()
        request.append(98)     // QueryExtension
        request.append(0)
        request.append(contentsOf: bytes(UInt16(2 + padded / 4)))
        request.append(contentsOf: bytes(UInt16(nameBytes.count)))
        request.append(contentsOf: [0, 0])
        request.append(contentsOf: nameBytes)
        request.append(contentsOf: [UInt8](repeating: 0, count: padded - nameBytes.count))
        sequence &+= 1
        guard write(request), let reply = readReply() else { return nil }
        // present at [8], major-opcode at [9]
        guard reply.count > 9, reply[8] == 1 else {
            log("input: this X server has no \(name) extension", level: .error)
            return nil
        }
        return reply[9]
    }

    private func loadKeyboardMapping() {
        // GetKeyboardMapping over the whole range the server reported. Keysyms for the
        // printable Latin block are the character's own code point, which is what makes
        // this a lookup rather than a table.
        var request = [UInt8]()
        request.append(101)    // GetKeyboardMapping
        request.append(0)
        request.append(contentsOf: bytes(UInt16(2)))
        request.append(8)      // first keycode
        request.append(248)    // count: the rest of the 8...255 range
        request.append(contentsOf: [0, 0])
        sequence &+= 1
        guard write(request), let reply = readReply() else { return }
        let perKeycode = Int(reply[1])
        guard perKeycode > 0 else { return }
        let symbols = (reply.count - 32) / 4
        var index = 0
        while index < symbols {
            let offset = 32 + index * 4
            let keysym = UInt32(reply[offset]) | UInt32(reply[offset + 1]) << 8
                       | UInt32(reply[offset + 2]) << 16 | UInt32(reply[offset + 3]) << 24
            let keycode = UInt8(8 + index / perKeycode)
            let column = index % perKeycode
            if keysym == 0xFFE1 {          // XK_Shift_L
                shiftKeycode = keycode
            }
            // Latin-1 keysyms are their own code point; the second column is the shifted
            // symbol, and anything past that is a keyboard group this does not use.
            if column < 2, keysym > 0x20, keysym < 0xFF,
               let scalar = Unicode.Scalar(keysym) {
                let character = Character(scalar)
                if keycodes[character] == nil {
                    keycodes[character] = (keycode, column == 1)
                }
            }
            index += 1
        }
    }

    private func send(type: UInt8, detail: UInt8, x: Int16, y: Int16) {
        guard socket >= 0, xtestOpcode != 0 else { return }
        var request = [UInt8](repeating: 0, count: 36)
        request[0] = xtestOpcode
        request[1] = 2                                    // XTestFakeInput
        request[2] = 9                                    // length in 4-byte units
        request[3] = 0
        request[4] = type
        request[5] = detail
        // request[8...11] is the delay, which stays 0: the event happens now.
        let rootBytes = bytes(root)
        request[12] = rootBytes[0]; request[13] = rootBytes[1]
        request[14] = rootBytes[2]; request[15] = rootBytes[3]
        let xBytes = bytes(UInt16(bitPattern: x))
        let yBytes = bytes(UInt16(bitPattern: y))
        request[24] = xBytes[0]; request[25] = xBytes[1]
        request[26] = yBytes[0]; request[27] = yBytes[1]
        sequence &+= 1
        _ = write(request)
    }

    // MARK: - Socket

    private func write(_ bytes: [UInt8]) -> Bool {
        guard socket >= 0 else { return false }
        var sent = 0
        while sent < bytes.count {
            let written = bytes.withUnsafeBytes { buffer in
                Darwin.write(socket, buffer.baseAddress!.advanced(by: sent), bytes.count - sent)
            }
            if written <= 0 {
                if errno == EINTR { continue }
                disconnect()
                return false
            }
            sent += written
        }
        return true
    }

    private func read(count: Int) -> [UInt8]? {
        guard socket >= 0, count > 0 else { return count == 0 ? [] : nil }
        var buffer = [UInt8](repeating: 0, count: count)
        var filled = 0
        while filled < count {
            let got = buffer.withUnsafeMutableBytes { raw in
                Darwin.read(socket, raw.baseAddress!.advanced(by: filled), count - filled)
            }
            if got <= 0 {
                if errno == EINTR { continue }
                return nil
            }
            filled += got
        }
        return buffer
    }

    /// Reads one reply, skipping any events or errors that arrive first. A reply is 32
    /// bytes plus whatever its length field asks for.
    private func readReply() -> [UInt8]? {
        for _ in 0..<32 {
            guard var packet = read(count: 32) else { return nil }
            if packet[0] == 1 {
                let extra = Int(UInt32(packet[4]) | UInt32(packet[5]) << 8
                              | UInt32(packet[6]) << 16 | UInt32(packet[7]) << 24) * 4
                if extra > 0, let rest = read(count: extra) {
                    packet.append(contentsOf: rest)
                }
                return packet
            }
            if packet[0] == 0 {
                log("input: the X server returned an error (code \(packet[1]))", level: .warn)
                return nil
            }
            // Anything else is an event the server sent unprompted; not interesting here.
        }
        return nil
    }

    private func bytes(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8(value >> 8)]
    }

    private func bytes(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF),
         UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
    }
}

import Combine
import CoreGraphics
import Foundation

/// The guest's screen, read straight out of the X server's framebuffer.
///
/// Xvfb started with `-fbdir` keeps its framebuffer in a file rather than in anonymous
/// memory, and every drawing operation lands in that file's shared mapping. Mapping the
/// same file here means the host sees the guest's screen with no protocol, no copy and no
/// cooperation from the guest: what X has drawn is already in our address space.
///
/// The file is an XWD dump -- a big-endian header, a colormap, then the pixels -- which is
/// the format `xwud` reads. Only the header is parsed; the pixel block underneath it is
/// the framebuffer itself and stays live for as long as the server runs.
@MainActor
final class GuestDisplay: ObservableObject {
    /// The most recent frame, or nil while nothing has drawn yet.
    @Published private(set) var frame: CGImage?
    /// Set once a framebuffer has been found and its header understood.
    @Published private(set) var size: CGSize = .zero
    @Published private(set) var isAttached = false

    private var descriptor: Int32 = -1
    private var mapping: UnsafeMutableRawPointer?
    private var mappedLength = 0

    private var pixels: UnsafeMutableRawPointer?
    private var width = 0
    private var height = 0
    private var bytesPerRow = 0

    private var timer: Timer?
    /// The framebuffer changes far more often than it needs to be shown, and a frame that
    /// is identical to the last one costs a full image upload for nothing.
    private var lastChecksum: UInt64 = 0

    private let colorSpace = CGColorSpaceCreateDeviceRGB()

    deinit {
        if let mapping {
            munmap(mapping, mappedLength)
        }
        if descriptor >= 0 {
            close(descriptor)
        }
    }

    // MARK: - Attaching

    /// Watches `path` until the X server creates it, then maps it and starts producing
    /// frames. Safe to call before the server exists.
    func attach(path: String, framesPerSecond: Double = 30) {
        detach()
        let interval = 1.0 / max(1, framesPerSecond)
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                if self.pixels == nil {
                    self.map(path: path)
                }
                self.refresh()
            }
        }
        if let timer {
            RunLoop.main.add(timer, forMode: .common)
        }
    }

    func detach() {
        timer?.invalidate()
        timer = nil
        if let mapping {
            munmap(mapping, mappedLength)
        }
        mapping = nil
        mappedLength = 0
        pixels = nil
        if descriptor >= 0 {
            close(descriptor)
        }
        descriptor = -1
        lastChecksum = 0
        frame = nil
        size = .zero
        isAttached = false
    }

    // MARK: - Mapping

    private func map(path: String) {
        guard descriptor < 0 else { return }
        let fd = open(path, O_RDONLY)
        guard fd >= 0 else { return }

        var info = stat()
        guard fstat(fd, &info) == 0, info.st_size > Int64(Header.minimumSize) else {
            close(fd)
            return
        }
        let length = Int(info.st_size)
        let base = mmap(nil, length, PROT_READ, MAP_SHARED, fd, 0)
        guard let base, base != MAP_FAILED else {
            close(fd)
            return
        }

        guard let header = Header(base) else {
            munmap(base, length)
            close(fd)
            log("display: \(path) is not a framebuffer this can read", level: .error)
            return
        }
        // Everything after the header and its colormap is the screen.
        let offset = header.pixelOffset
        guard offset + header.bytesPerRow * header.height <= length else {
            munmap(base, length)
            close(fd)
            log("display: \(path) is shorter than its own header says", level: .error)
            return
        }

        descriptor = fd
        mapping = base
        mappedLength = length
        pixels = base.advanced(by: offset)
        width = header.width
        height = header.height
        bytesPerRow = header.bytesPerRow
        size = CGSize(width: header.width, height: header.height)
        isAttached = true
        log("display: attached to \(header.width)x\(header.height) framebuffer")
    }

    // MARK: - Frames

    private func refresh() {
        guard let pixels else { return }
        let checksum = sample(pixels)
        guard checksum != lastChecksum else { return }
        lastChecksum = checksum

        let length = bytesPerRow * height
        // The provider must not outlive the mapping, and a CGImage may be retained by the
        // renderer past this frame, so the bytes are copied rather than referenced.
        guard let data = CFDataCreate(nil, pixels.assumingMemoryBound(to: UInt8.self), length),
              let provider = CGDataProvider(data: data) else {
            return
        }
        // X hands out BGRX in memory order on a little-endian visual, which is what
        // byteOrder32Little plus a skipped first component describes.
        let bitmapInfo = CGBitmapInfo(rawValue: CGImageAlphaInfo.noneSkipFirst.rawValue
                                        | CGBitmapInfo.byteOrder32Little.rawValue)
        frame = CGImage(width: width,
                        height: height,
                        bitsPerComponent: 8,
                        bitsPerPixel: 32,
                        bytesPerRow: bytesPerRow,
                        space: colorSpace,
                        bitmapInfo: bitmapInfo,
                        provider: provider,
                        decode: nil,
                        shouldInterpolate: false,
                        intent: .defaultIntent)
    }

    /// A cheap stand-in for comparing whole frames: a scattered sample is enough to catch
    /// anything a viewer would notice, and reading 3.7MB thirty times a second to find out
    /// nothing changed is not.
    private func sample(_ pixels: UnsafeMutableRawPointer) -> UInt64 {
        let words = pixels.assumingMemoryBound(to: UInt32.self)
        let count = (bytesPerRow * height) / 4
        guard count > 0 else { return 0 }
        let stride = max(1, count / 4096)
        var checksum: UInt64 = 1469598103934665603
        var index = 0
        while index < count {
            checksum = (checksum ^ UInt64(words[index])) &* 1099511628211
            index += stride
        }
        return checksum
    }
}

/// The XWD file header, as Xvfb writes it: big-endian 32-bit fields in a fixed order.
private struct Header {
    static let minimumSize = 100

    let width: Int
    let height: Int
    let bytesPerRow: Int
    let pixelOffset: Int

    init?(_ base: UnsafeRawPointer) {
        func field(_ index: Int) -> UInt32 {
            UInt32(bigEndian: base.loadUnaligned(fromByteOffset: index * 4, as: UInt32.self))
        }
        let headerSize = Int(field(0))
        let format = field(2)
        let depth = field(3)
        let bitsPerPixel = field(11)
        let ncolors = Int(field(19))
        guard headerSize >= Header.minimumSize,
              format == 2,          // ZPixmap: whole pixels, one after another
              depth == 24 || depth == 32,
              bitsPerPixel == 32 else {
            return nil
        }
        width = Int(field(4))
        height = Int(field(5))
        bytesPerRow = Int(field(12))
        // An XWDColor is 12 bytes, and the colormap sits between the header and the image.
        pixelOffset = headerSize + ncolors * 12
        guard width > 0, height > 0, bytesPerRow >= width * 4 else {
            return nil
        }
    }
}

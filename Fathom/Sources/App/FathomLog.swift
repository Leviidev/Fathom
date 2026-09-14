import Foundation

/// Fathom's log.
///
/// Everything -- the Swift side, and every line the C++ core emits through
/// `fathom_set_log_sink` -- lands here, is mirrored to a file inside the app container,
/// and is readable from Settings. A sideloaded app has no Xcode attached to it, so a log
/// that only exists in the console is a log that does not exist.
final class FathomLog: ObservableObject, @unchecked Sendable {
    static let shared = FathomLog()

    struct Entry: Identifiable {
        let id = UUID()
        let date: Date
        let level: Level
        let message: String
    }

    enum Level: Int, Comparable {
        case debug = 0, info = 1, warn = 2, error = 3

        var label: String {
            switch self {
            case .debug: return "DEBUG"
            case .info: return "INFO"
            case .warn: return "WARN"
            case .error: return "ERROR"
            }
        }

        static func < (lhs: Level, rhs: Level) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    /// The most recent lines, for the in-app viewer. The file keeps everything.
    @Published private(set) var entries: [Entry] = []

    /// Bounded so a chatty guest cannot grow the view without limit; the file is the
    /// complete record either way.
    private let maximumEntries = 2000
    private let queue = DispatchQueue(label: "app.fathom.log")
    private var handle: FileHandle?
    private let formatter: DateFormatter

    var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("fathom.log")
    }

    private init() {
        formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        openFile()
    }

    private func openFile() {
        let url = fileURL
        let manager = FileManager.default
        // Start each launch with a fresh file: the interesting log is almost always the
        // one from the run that just went wrong, and an ever-growing file buries it.
        try? manager.removeItem(at: url)
        manager.createFile(atPath: url.path, contents: nil)
        handle = try? FileHandle(forWritingTo: url)

        let device = ProcessInfo.processInfo
        write(.info, "Fathom \(Bundle.main.shortVersion) (\(Bundle.main.buildVersion))")
        write(.info, "iOS \(device.operatingSystemVersionString), \(device.processorCount) cores")
        write(.info, "host page size \(fathom_host_page_size()) bytes")
    }

    func write(_ level: Level, _ message: String) {
        let entry = Entry(date: Date(), level: level, message: message)
        let line = "\(formatter.string(from: entry.date)) [\(level.label)] \(message)\n"

        queue.async { [weak self] in
            guard let self else { return }
            if let data = line.data(using: .utf8) {
                self.handle?.write(data)
            }
        }

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.entries.append(entry)
            if self.entries.count > self.maximumEntries {
                self.entries.removeFirst(self.entries.count - self.maximumEntries)
            }
        }
    }

    func clear() {
        entries.removeAll()
    }

    /// Hands the C++ core its sink. Called once, at launch, before anything else runs.
    func installCoreSink() {
        fathom_set_log_sink({ _, level, message in
            guard let message else { return }
            let text = String(cString: message)
            let mapped: Level
            switch level {
            case FATHOM_LOG_DEBUG: mapped = .debug
            case FATHOM_LOG_WARN: mapped = .warn
            case FATHOM_LOG_ERROR: mapped = .error
            default: mapped = .info
            }
            FathomLog.shared.write(mapped, text)
        }, nil)
    }

    func setCoreLevel(verbose: Bool) {
        fathom_set_log_level(verbose ? FATHOM_LOG_DEBUG : FATHOM_LOG_INFO)
    }
}

extension Bundle {
    var shortVersion: String { infoDictionary?["CFBundleShortVersionString"] as? String ?? "?" }
    var buildVersion: String { infoDictionary?["CFBundleVersion"] as? String ?? "?" }
}

func log(_ message: String, level: FathomLog.Level = .info) {
    FathomLog.shared.write(level, message)
}

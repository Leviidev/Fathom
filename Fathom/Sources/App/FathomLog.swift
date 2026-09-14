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

    /// The log from the run before this one.
    ///
    /// This exists because of the specific way an emulator fails: the guest faults, the
    /// process dies, iOS relaunches the app, and a log that started fresh on launch has
    /// already thrown away the only record of what happened. The interesting log is
    /// frequently the previous one.
    var previousFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("fathom-previous.log")
    }

    var hasPreviousLog: Bool {
        FileManager.default.fileExists(atPath: previousFileURL.path)
    }

    private init() {
        formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        openFile()
    }

    private func openFile() {
        let url = fileURL
        let manager = FileManager.default

        // Rotate rather than delete. Each launch gets a clean file so one run is easy to
        // read, but the run before it survives -- which is the one that matters when the
        // app died rather than exited.
        try? manager.removeItem(at: previousFileURL)
        try? manager.moveItem(at: url, to: previousFileURL)

        manager.createFile(atPath: url.path, contents: nil)
        handle = try? FileHandle(forWritingTo: url)

        // Installed before anything else runs, so a fault during startup is still
        // recorded. It appends to this same file from inside the signal handler.
        url.path.withCString { fathom_install_crash_handler($0) }

        reportPreviousCrash()

        let device = ProcessInfo.processInfo
        write(.info, "Fathom \(Bundle.main.shortVersion) (\(Bundle.main.buildVersion))")
        write(.info, "iOS \(device.operatingSystemVersionString), \(device.processorCount) cores")
        write(.info, "host page size \(fathom_host_page_size()) bytes")
    }

    /// If the previous run ended in a fatal signal, replay its crash record into this
    /// run's log so it shows up in the viewer. The signal handler can only write raw
    /// bytes to the file, so without this the record exists but is invisible in the app.
    private func reportPreviousCrash() {
        guard let text = try? String(contentsOf: previousFileURL, encoding: .utf8),
              let range = text.range(of: "=== FATHOM CRASH ===") else {
            return
        }
        let record = text[range.lowerBound...].prefix(2000)
        write(.error, "the previous run ended in a crash:")
        for line in record.split(separator: "\n") {
            write(.error, "  " + line)
        }
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

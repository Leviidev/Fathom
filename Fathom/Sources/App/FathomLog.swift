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

    /// Lines are batched rather than published individually.
    ///
    /// With syscall tracing on, a busy guest produces thousands of lines a second, and a
    /// line at a time meant one hop to the main thread and one SwiftUI invalidation each
    /// -- enough to make the whole app stutter while a program was running. They are
    /// accumulated here instead and flushed ten times a second, as one array append and
    /// one file write.
    private let pending = NSLock()
    private var pendingEntries: [Entry] = []
    private var pendingText = ""
    private var flushTimer: DispatchSourceTimer?

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
        startFlushing()
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
        // Shown in the viewer but deliberately not written to the file. Writing it back
        // would make this run's log contain the previous run's replay, which the next
        // launch would then replay in turn -- each log nesting every log before it.
        let record = text[range.lowerBound...].prefix(2000)
        var replayed: [Entry] = [Entry(date: Date(), level: .error, message: "the previous run ended in a crash:")]
        for line in record.split(separator: "\n") {
            replayed.append(Entry(date: Date(), level: .error, message: "  " + line))
        }
        let lines = replayed
        DispatchQueue.main.async { [weak self] in
            self?.entries.append(contentsOf: lines)
        }
    }

    func write(_ level: Level, _ message: String) {
        let entry = Entry(date: Date(), level: level, message: message)
        let line = "\(formatter.string(from: entry.date)) [\(level.label)] \(message)\n"

        pending.lock()
        pendingEntries.append(entry)
        pendingText += line
        pending.unlock()
    }

    private func startFlushing() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
        timer.setEventHandler { [weak self] in self?.flush() }
        timer.resume()
        flushTimer = timer
    }

    private func flush() {
        pending.lock()
        let entries = pendingEntries
        let text = pendingText
        pendingEntries.removeAll(keepingCapacity: true)
        pendingText.removeAll(keepingCapacity: true)
        pending.unlock()

        guard !entries.isEmpty else { return }

        if let data = text.data(using: .utf8) {
            handle?.write(data)
        }

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.entries.append(contentsOf: entries)
            if self.entries.count > self.maximumEntries {
                self.entries.removeFirst(self.entries.count - self.maximumEntries)
            }
        }
    }

    /// Pushes everything out immediately, for the moment before a log is exported.
    func flushNow() {
        queue.sync { self.flush() }
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

import Foundation

/// A single run of a single program.
///
/// FEXCore binds a guest thread to the host thread executing it, so the run happens on
/// a dedicated `Thread` that exists for exactly as long as the run does -- not on a
/// dispatch queue, where the work could be resumed on a different thread.
@MainActor
final class EmulatorSession: ObservableObject {
    enum State: Equatable {
        case idle
        case preparing
        case running
        case finished(exitCode: Int)
        case stopped
        case failed(String)

        var isActive: Bool {
            self == .preparing || self == .running
        }
    }

    struct OutputChunk: Identifiable {
        let id = UUID()
        let isError: Bool
        let text: String
    }

    @Published private(set) var state: State = .idle
    @Published private(set) var output: [OutputChunk] = []
    @Published private(set) var syscallCount: UInt64 = 0
    @Published private(set) var rip: UInt64 = 0
    @Published private(set) var elapsed: TimeInterval = 0

    /// Watchdog state. A guest that stops making syscalls has either wedged in a loop or
    /// died, and those two look identical from outside -- the log simply stops. Sampling
    /// RIP while nothing else is happening tells them apart, and an RIP that never moves
    /// names the exact instruction to disassemble.
    private var lastSyscallCount: UInt64 = 0
    private var lastSyscallChangeAt = Date()
    private var lastStallReportAt: Date?
    private var stallSampleRip: UInt64 = 0
    private var stallSampleRepeats = 0

    private var session: OpaquePointer?
    private var runThread: Thread?
    private var statusTimer: Timer?
    private var startedAt: Date?

    /// Guest writes arrive one `write` at a time and can be very frequent. They are
    /// accumulated here and flushed on a timer, because appending to a @Published array
    /// per write is enough to make the UI unusable on a chatty program.
    private let pendingLock = NSLock()
    // Written from the guest thread and read from the main one, with pendingLock as
    // the only thing keeping them consistent -- which is exactly what this annotation
    // is for, since the actor cannot help across that boundary.
    nonisolated(unsafe) private var pendingOut = ""
    nonisolated(unsafe) private var pendingErr = ""

    deinit {
        // `session` is a plain pointer; the C side is thread-safe to destroy from here
        // and there is no main-actor work involved in freeing it.
        if let session {
            fathom_session_destroy(session)
        }
    }

    var outputText: String {
        output.map(\.text).joined()
    }

    // MARK: - Running

    func run(program: Program, settings: EmulatorSettings, library: ProgramLibrary) {
        guard !state.isActive else { return }

        output.removeAll()
        syscallCount = 0
        rip = 0
        elapsed = 0
        state = .preparing

        guard JITSupport.isJITAvailable else {
            state = .failed("JIT is not enabled. Fathom cannot make memory executable without it, "
                            + "so there is no emulator to run this on. Enable JIT from Settings, then try again.")
            return
        }

        let path = program.url.path
        let guestRoot = ProgramLibrary.guestRootDirectory.path
        let environment = settings.guestEnvironment

        var config = fathom_session_config()
        fathom_session_config_defaults(&config)
        config.multiblock = settings.multiblock
        config.tso_enabled = settings.tsoEnabled
        config.reduced_precision_x87 = settings.reducedPrecisionX87
        config.max_inst_per_block = UInt32(max(0, settings.maxInstPerBlock))
        config.trace_syscalls = settings.traceSyscalls
        config.address_space_size = UInt64(max(256, settings.addressSpaceMB)) * 1024 * 1024
        config.stack_size = UInt64(max(1, settings.stackMB)) * 1024 * 1024

        var errorBuffer = [CChar](repeating: 0, count: 512)

        // The core keeps no copy of these strings during fathom_session_create, so they
        // have to stay alive across the call. Owning them explicitly is clearer here
        // than a deep nest of withCString closures, and there is exactly one exit path.
        let pathString = CString(path)
        let rootString = CString(guestRoot)
        let workString = CString("/")
        let argv = CStringArray([path])
        let envp = CStringArray(environment)
        defer {
            pathString.deallocate()
            rootString.deallocate()
            workString.deallocate()
            argv.deallocate()
            envp.deallocate()
        }

        config.program_path = pathString.pointer
        config.guest_root = rootString.pointer
        config.work_dir = workString.pointer
        config.argv = UnsafePointer(argv.pointer)
        config.argc = argv.count
        config.envp = UnsafePointer(envp.pointer)
        config.envc = envp.count

        let created = fathom_session_create(&config, &errorBuffer, errorBuffer.count)

        guard let created else {
            let message = String(cString: errorBuffer)
            state = .failed(message.isEmpty ? "The program could not be loaded." : message)
            log("run failed: \(message)", level: .error)
            return
        }

        session = created
        installOutputSink(for: created)

        state = .running
        startedAt = Date()
        startStatusTimer()

        let thread = Thread { [weak self] in
            let exitCode = Int(fathom_session_run(created))
            DispatchQueue.main.async {
                self?.finish(exitCode: exitCode, program: program, library: library)
            }
        }
        thread.name = "fathom.guest"
        // FEXCore's dispatcher, the JIT's own frames, and the guest's stack all sit on
        // this thread. 16MB keeps a deeply recursive guest from running the host thread
        // out of stack before the guest notices its own.
        thread.stackSize = 16 * 1024 * 1024
        runThread = thread
        thread.start()

        log("running \(program.name)")
    }

    private func installOutputSink(for session: OpaquePointer) {
        let context = Unmanaged.passUnretained(self).toOpaque()
        fathom_session_set_output_sink(session, { context, fd, bytes, length in
            guard let context, let bytes, length > 0 else { return }
            let owner = Unmanaged<EmulatorSession>.fromOpaque(context).takeUnretainedValue()
            let data = Data(bytes: bytes, count: length)
            let text = String(decoding: data, as: UTF8.self)
            owner.appendPending(text, isError: fd == 2)
        }, context)
    }

    /// Called from the guest thread, so it touches nothing but the lock and the buffers.
    nonisolated private func appendPending(_ text: String, isError: Bool) {
        pendingLock.lock()
        if isError {
            pendingErr += text
        } else {
            pendingOut += text
        }
        pendingLock.unlock()
    }

    private func startStatusTimer() {
        statusTimer?.invalidate()
        statusTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
    }

    private func tick() {
        flushOutput()
        if let session {
            var status = fathom_session_status()
            fathom_session_get_status(session, &status)
            syscallCount = status.syscall_count
            rip = status.rip
            checkForStall()
        }
        if let startedAt {
            elapsed = Date().timeIntervalSince(startedAt)
        }
    }

    private func checkForStall() {
        guard state == .running else { return }

        if syscallCount != lastSyscallCount {
            lastSyscallCount = syscallCount
            lastSyscallChangeAt = Date()
            lastStallReportAt = nil
            stallSampleRepeats = 0
            return
        }

        let stalledFor = Date().timeIntervalSince(lastSyscallChangeAt)
        guard stalledFor >= 2 else { return }

        // Report every two seconds rather than ten times a second.
        if let last = lastStallReportAt, Date().timeIntervalSince(last) < 2 { return }
        lastStallReportAt = Date()

        if rip == stallSampleRip {
            stallSampleRepeats += 1
        } else {
            stallSampleRip = rip
            stallSampleRepeats = 0
        }

        // RIP only settles at syscall boundaries, so an unchanged value here means the
        // guest has not reached one since -- it is running guest code, not wedged in a
        // host call. Either way the address is the place to start disassembling.
        log(String(format: "guest still running: no syscall for %.0fs, last rip=0x%llx, %llu syscalls%@",
                   stalledFor, rip, syscallCount,
                   stallSampleRepeats > 0 ? " (rip unchanged across \(stallSampleRepeats + 1) samples)" : ""),
            level: .warn)
    }

    private func flushOutput() {
        pendingLock.lock()
        let out = pendingOut
        let err = pendingErr
        pendingOut = ""
        pendingErr = ""
        pendingLock.unlock()

        if !out.isEmpty {
            append(out, isError: false)
        }
        if !err.isEmpty {
            append(err, isError: true)
        }
    }

    private func append(_ text: String, isError: Bool) {
        // Coalesced into the previous chunk when it came from the same stream, so the
        // console is a handful of Text views rather than one per write().
        if let last = output.last, last.isError == isError {
            output[output.count - 1] = OutputChunk(isError: isError, text: last.text + text)
        } else {
            output.append(OutputChunk(isError: isError, text: text))
        }
    }

    private func finish(exitCode: Int, program: Program, library: ProgramLibrary) {
        statusTimer?.invalidate()
        statusTimer = nil
        tick()
        flushOutput()

        var status = fathom_session_status()
        if let session {
            fathom_session_get_status(session, &status)
        }

        switch status.state {
        case FATHOM_STATE_EXITED:
            state = .finished(exitCode: exitCode)
            library.recordRun(program, exitCode: exitCode)
        case FATHOM_STATE_STOPPED:
            state = .stopped
        default:
            let message = withUnsafeBytes(of: status.message) {
                String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            state = .failed(message.isEmpty ? "The guest stopped unexpectedly." : message)
        }

        log("run finished: \(state)")
        runThread = nil
        destroySession()
    }

    func stop() {
        guard let session, state.isActive else { return }
        fathom_session_request_stop(session)
    }

    private func destroySession() {
        guard let session else { return }
        fathom_session_destroy(session)
        self.session = nil
    }

    func reset() {
        guard !state.isActive else { return }
        output.removeAll()
        state = .idle
        syscallCount = 0
        rip = 0
        elapsed = 0
    }
}

/// A C string Fathom owns for as long as it needs to hand it to the core.
private struct CString {
    let pointer: UnsafePointer<CChar>

    init(_ value: String) {
        pointer = UnsafePointer(strdup(value)!)
    }

    func deallocate() {
        free(UnsafeMutableRawPointer(mutating: pointer))
    }
}

/// A NULL-terminated argv/envp array Fathom owns, for the same reason.
private struct CStringArray {
    private let strings: [UnsafeMutablePointer<CChar>?]
    let pointer: UnsafeMutablePointer<UnsafePointer<CChar>?>
    let count: Int32

    init(_ values: [String]) {
        strings = values.map { strdup($0) }
        pointer = UnsafeMutablePointer<UnsafePointer<CChar>?>.allocate(capacity: values.count + 1)
        for (index, string) in strings.enumerated() {
            pointer[index] = UnsafePointer(string)
        }
        pointer[values.count] = nil
        count = Int32(values.count)
    }

    func deallocate() {
        strings.forEach { free($0) }
        pointer.deallocate()
    }
}

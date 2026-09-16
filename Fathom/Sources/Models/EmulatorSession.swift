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

    /// The guest's screen, for programs that draw one.
    @Published private(set) var terminal = TerminalEmulator()
    /// True once the guest is drawing a screen or asking for individual keypresses.
    @Published private(set) var isInteractive = false

    /// The guest's graphical screen, for a session that runs an X server. Empty and
    /// detached unless the run was started with `runGraphical`.
    let display = GuestDisplay()
    /// Pointer and keyboard events on their way back to that X server.
    let input = GuestInput()
    private var inputTimer: Timer?

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
        launch(hostPath: program.url.path, argv: [program.url.path], name: program.name,
               settings: settings) { [weak self] exitCode in
            self?.finish(exitCode: exitCode, program: program, library: library)
        }
    }

    /// Runs something that lives inside the guest root filesystem -- /bin/sh, say --
    /// rather than a program imported into the library.
    ///
    /// argv[0] is the guest-visible path, not the host one, because busybox decides
    /// which of its ~300 applets to be from the name it was invoked under: hand it
    /// "/bin/sh" and it is a shell, hand it a container path and it is nothing.
    func runInGuest(path guestPath: String, arguments: [String] = [], settings: EmulatorSettings) {
        let relative = guestPath.hasPrefix("/") ? String(guestPath.dropFirst()) : guestPath
        let hostPath = ProgramLibrary.guestRootDirectory.appendingPathComponent(relative).path
        launch(hostPath: hostPath, argv: [guestPath] + arguments, name: guestPath,
               settings: settings) { [weak self] exitCode in
            self?.finish(exitCode: exitCode, program: nil, library: nil)
        }
    }

    /// Runs something in the guest that draws with X rather than printing.
    ///
    /// The picture and the input both go through the guest root: the X server writes its
    /// framebuffer to a file there and listens on a socket there, and both are ordinary
    /// host files as far as this process is concerned. So there is nothing to connect
    /// until the server inside the guest has started, and both sides simply keep trying.
    func runGraphical(path guestPath: String, arguments: [String] = [],
                      settings: EmulatorSettings) {
        let root = ProgramLibrary.guestRootDirectory
        display.attach(path: root.appendingPathComponent("tmp/fb/Xvfb_screen0").path)
        startConnectingInput(socketPath: root.appendingPathComponent("tmp/.X11-unix/X0").path)
        runInGuest(path: guestPath, arguments: arguments, settings: settings)
    }

    private func startConnectingInput(socketPath: String) {
        inputTimer?.invalidate()
        inputTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] timer in
            MainActor.assumeIsolated {
                guard let self else { return }
                guard self.state.isActive else {
                    timer.invalidate()
                    return
                }
                if self.input.connect(socketPath: socketPath) {
                    timer.invalidate()
                    self.inputTimer = nil
                }
            }
        }
        if let inputTimer {
            RunLoop.main.add(inputTimer, forMode: .common)
        }
    }

    private func launch(hostPath: String, argv: [String], name: String, settings: EmulatorSettings,
                        onFinish: @escaping (Int) -> Void) {
        guard !state.isActive else { return }

        output.removeAll()
        terminal.reset()
        isInteractive = false
        syscallCount = 0
        rip = 0
        elapsed = 0
        state = .preparing

        guard JITSupport.isJITAvailable else {
            state = .failed("JIT is not enabled. Fathom cannot make memory executable without it, "
                            + "so there is no emulator to run this on. Enable JIT from Settings, then try again.")
            return
        }

        let path = hostPath
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
        let argvArray = CStringArray(argv)
        let envp = CStringArray(environment)
        defer {
            pathString.deallocate()
            rootString.deallocate()
            workString.deallocate()
            argvArray.deallocate()
            envp.deallocate()
        }

        config.program_path = pathString.pointer
        config.guest_root = rootString.pointer
        config.work_dir = workString.pointer
        config.argv = UnsafePointer(argvArray.pointer)
        config.argc = argvArray.count
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
                onFinish(exitCode)
            }
        }
        thread.name = "fathom.guest"
        // FEXCore's dispatcher, the JIT's own frames, and the guest's stack all sit on
        // this thread. 16MB keeps a deeply recursive guest from running the host thread
        // out of stack before the guest notices its own.
        thread.stackSize = 16 * 1024 * 1024
        // The guest is the work the user is waiting on; leaving it at default priority
        // lets the UI's own housekeeping compete with it.
        thread.qualityOfService = .userInitiated
        runThread = thread
        thread.start()

        log("running \(name)")
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
            terminal.feed(out)
            append(out, isError: false)
        }
        if !err.isEmpty {
            terminal.feed(err)
            append(err, isError: true)
        }

        if !isInteractive {
            let wantsKeys = session.map { fathom_session_wants_keys($0) } ?? false
            if wantsKeys || terminal.isFullScreen {
                isInteractive = true
                log("guest is drawing a screen; showing the terminal")
            }
        }
    }

    /// Sends a keystroke to the guest. `text` is the bytes a real terminal would send,
    /// so an arrow key is its escape sequence rather than a character.
    func sendKey(_ text: String) {
        guard let session, state == .running else { return }
        var bytes = Array(text.utf8).map { CChar(bitPattern: $0) }
        fathom_session_send_input(session, &bytes, bytes.count)
    }

    /// Chunks are coalesced so the console is a handful of Text views rather than one
    /// per write() -- but only up to a point. Appending to one ever-growing string meant
    /// rebuilding the entire output every flush, which is quadratic in what the program
    /// has printed and is exactly why a talkative guest made the UI crawl.
    private static let maximumChunkBytes = 8 * 1024
    private static let maximumChunks = 200

    private func append(_ text: String, isError: Bool) {
        if let last = output.last, last.isError == isError, last.text.utf8.count < Self.maximumChunkBytes {
            output[output.count - 1] = OutputChunk(isError: isError, text: last.text + text)
        } else {
            output.append(OutputChunk(isError: isError, text: text))
        }

        // Keep the tail. A guest that prints megabytes should not be able to grow the
        // view without limit; the interesting part is almost always the end.
        if output.count > Self.maximumChunks {
            output.removeFirst(output.count - Self.maximumChunks)
        }
    }

    private func finish(exitCode: Int, program: Program?, library: ProgramLibrary?) {
        statusTimer?.invalidate()
        statusTimer = nil
        inputTimer?.invalidate()
        inputTimer = nil
        input.disconnect()
        display.detach()
        tick()
        flushOutput()

        var status = fathom_session_status()
        if let session {
            fathom_session_get_status(session, &status)
        }

        switch status.state {
        case FATHOM_STATE_EXITED:
            state = .finished(exitCode: exitCode)
            if let program, let library {
                library.recordRun(program, exitCode: exitCode)
            }
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

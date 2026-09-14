import SwiftUI

/// The knobs Settings exposes, persisted across launches.
///
/// Everything here is passed into `fathom_session_config` at the moment a program
/// starts, so a change takes effect on the next run rather than mid-flight.
@MainActor
final class EmulatorSettings: ObservableObject {
    @AppStorage("engine.multiblock") var multiblock = true
    // Deliberately a new key rather than a changed default: anyone who already ran the
    // old build has "true" written into UserDefaults, and a changed default would never
    // reach them. Off, because of what a fault costs here -- see the note below.
    //
    // TSO emulation turns every guest load and store into an ARM64 acquire/release
    // instruction, and those fault on an unaligned address where x86 would not care. The
    // fault is recoverable, but recovering it means a signal -- and while StikDebug is
    // attached as a debugger, every signal in this process round-trips through it. One
    // measured fault cost 89 seconds of wall time. Guests are single-threaded here
    // anyway (clone returns ENOSYS), so TSO emulation currently buys nothing at all.
    @AppStorage("engine.tso.v2") var tsoEnabled = false
    @AppStorage("engine.x87Reduced") var reducedPrecisionX87 = false
    @AppStorage("engine.maxInst") var maxInstPerBlock = 0
    @AppStorage("engine.addressSpaceMB") var addressSpaceMB = 2048
    @AppStorage("engine.stackMB") var stackMB = 8

    @AppStorage("debug.traceSyscalls") var traceSyscalls = false
    @AppStorage("debug.verboseLogging") var verboseLogging = false

    @AppStorage("general.autoRequestJIT") var autoRequestJIT = true

    /// The default guest environment. Kept minimal on purpose: a program that needs more
    /// should say so, and a surprising PATH or LANG changes behaviour in ways that are
    /// hard to trace back to a setting.
    var guestEnvironment: [String] {
        ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/", "TERM=xterm-256color", "LANG=C.UTF-8",
         "FATHOM=1"]
    }

    func resetEngineDefaults() {
        multiblock = true
        tsoEnabled = true
        reducedPrecisionX87 = false
        maxInstPerBlock = 0
        addressSpaceMB = 2048
        stackMB = 8
    }
}

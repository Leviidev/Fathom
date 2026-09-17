import SwiftUI

/// The knobs Settings exposes, persisted across launches.
///
/// Everything here is passed into `fathom_session_config` at the moment a program
/// starts, so a change takes effect on the next run rather than mid-flight.
@MainActor
final class EmulatorSettings: ObservableObject {
    @AppStorage("engine.multiblock") var multiblock = true
    // Deliberately a new key rather than a changed default: a changed default never
    // reaches anyone who already ran an older build, because their answer is written into
    // UserDefaults. On, now that guests here have threads and the cost has gone.
    //
    // TSO emulation turns every guest load and store into an ARM64 acquire/release
    // instruction, and those fault on an unaligned address where x86 would not care. That
    // fault is recoverable, but recovering it means a signal, and a signal while StikDebug
    // is attached costs a great deal -- which is why this was off. FEXCore patches each
    // faulting instruction the first time it sees it, so the cost is paid once per
    // instruction rather than once per execution; what made it feel otherwise was
    // compiled code being thrown away constantly, taking the patches with it.
    //
    // What it buys is what a program whose threads share memory is entitled to assume.
    // Steam's web helper is Chromium, and without it GLib's type system comes up
    // half-built in one thread's view.
    @AppStorage("engine.tso.v3") var tsoEnabled = true
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

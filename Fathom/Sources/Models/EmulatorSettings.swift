import SwiftUI

/// The knobs Settings exposes, persisted across launches.
///
/// Everything here is passed into `fathom_session_config` at the moment a program
/// starts, so a change takes effect on the next run rather than mid-flight.
@MainActor
final class EmulatorSettings: ObservableObject {
    @AppStorage("engine.multiblock") var multiblock = true
    @AppStorage("engine.tso") var tsoEnabled = true
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

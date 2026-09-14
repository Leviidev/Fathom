import Foundation
import Security
import UIKit

/// Getting permission to JIT, and knowing whether we have it.
///
/// iOS does not let an ordinary app make memory executable. FEXCore cannot run at all
/// without that, so Fathom depends on an external debugger -- StikDebug -- attaching to
/// the process and servicing the BRK traps FEXCore's allocator issues. Until that
/// happens there is no emulator, only a UI, which is why this is checked up front and
/// requested automatically rather than left for the user to discover.
enum JITStatus: Equatable {
    case enabled
    case unavailable
    case checking

    var summary: String {
        switch self {
        case .enabled: return "JIT enabled"
        case .unavailable: return "JIT not enabled"
        case .checking: return "Checking..."
        }
    }
}

private typealias SecTaskRef = OpaquePointer

@_silgen_name("SecTaskCreateFromSelf")
private func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> SecTaskRef?

@_silgen_name("SecTaskCopyValueForEntitlement")
private func SecTaskCopyValueForEntitlement(
    _ task: SecTaskRef,
    _ entitlement: NSString,
    _ error: NSErrorPointer
) -> CFTypeRef?

@_silgen_name("CFRelease")
private func fathomCFRelease(_ value: CFTypeRef?)

@_silgen_name("csops")
private func fathomCsops(pid: Int32, ops: Int32, useraddr: UnsafeMutableRawPointer?, usersize: Int32) -> Int32

private let kCSDebugged: Int32 = 0x1000_0000

@MainActor
final class JITSupport: ObservableObject {
    static let shared = JITSupport()

    @Published private(set) var status: JITStatus = .checking
    @Published private(set) var lastRequest: Date?

    private init() {
        refresh()
    }

    /// True when this process may make memory executable -- either because it carries
    /// the entitlement outright, or because a debugger is attached to it.
    func refresh() {
        status = Self.isJITAvailable ? .enabled : .unavailable
    }

    static var isJITAvailable: Bool {
        if hasEntitlement("dynamic-codesigning") {
            return true
        }
        var flags: Int32 = 0
        let result = fathomCsops(pid: getpid(), ops: 0, useraddr: &flags,
                                 usersize: Int32(MemoryLayout.size(ofValue: flags)))
        return result == 0 && (flags & kCSDebugged) != 0
    }

    static func hasEntitlement(_ name: String) -> Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        defer { fathomCFRelease(unsafeBitCast(task, to: CFTypeRef.self)) }
        guard let value = SecTaskCopyValueForEntitlement(task, name as NSString, nil) else { return false }
        if let number = value as? NSNumber { return number.boolValue }
        return false
    }

    /// Hands StikDebug the script and asks it to attach. Control leaves the app; when
    /// the user comes back, `refresh()` in the scene-phase handler picks up the new
    /// state without them having to do anything else.
    func requestJIT() {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            log("cannot request JIT: no bundle identifier", level: .error)
            return
        }
        guard let script = Self.universalScript else {
            log("cannot request JIT: universal.js is missing from the app bundle", level: .error)
            return
        }

        // StikDebug decodes script-data as base64, tolerating base64url. base64url is
        // what gets used here deliberately: plain base64's "+", "/" and "=" all mean
        // something else inside a URL query, and a script that arrives one byte wrong
        // fails at the far end with nothing useful to look at.
        let encoded = script.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        guard let url = URL(string: "stikjit://enable-jit?bundle-id=\(bundleID)&script-data=\(encoded)") else {
            log("cannot request JIT: could not build the StikDebug URL", level: .error)
            return
        }

        lastRequest = Date()
        log("asking StikDebug to enable JIT for \(bundleID) (universal.js, \(script.count) bytes)")
        UIApplication.shared.open(url)
    }

    /// Whether StikDebug is installed at all, so the UI can say something useful rather
    /// than opening a URL into nothing.
    var isStikDebugInstalled: Bool {
        guard let url = URL(string: "stikjit://") else { return false }
        return UIApplication.shared.canOpenURL(url)
    }

    /// StikDebug's own Universal JIT Script, shipped in the app bundle as
    /// Resources/universal.js rather than pasted into this file as a base64 blob.
    ///
    /// It is StikDebug's script, not a reimplementation: it handles the whole JIT26
    /// command set (detach, prepare-region, new-breakpoints), and a cut-down script
    /// covering only the one command FEXCore's allocator appears to issue is not
    /// equivalent in practice. Updating it means dropping in a newer universal.js.
    static let universalScript: Data? = {
        guard let url = Bundle.main.url(forResource: "universal", withExtension: "js"),
              let data = try? Data(contentsOf: url) else {
            return nil
        }
        return data
    }()
}

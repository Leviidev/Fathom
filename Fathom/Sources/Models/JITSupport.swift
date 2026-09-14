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

    /// Hands StikDebug the script below and asks it to attach. Control leaves the app;
    /// when the user comes back, `refresh()` in the scene-phase handler picks up the
    /// new state without them having to do anything else.
    func requestJIT() {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            log("cannot request JIT: no bundle identifier", level: .error)
            return
        }
        guard let encoded = Self.script.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string: "stikjit://enable-jit?bundle-id=\(bundleID)&script-data=\(encoded)") else {
            log("cannot request JIT: could not build the StikDebug URL", level: .error)
            return
        }

        lastRequest = Date()
        log("asking StikDebug to enable JIT for \(bundleID)")
        UIApplication.shared.open(url)
    }

    /// Whether StikDebug is installed at all, so the UI can say something useful rather
    /// than opening a URL into nothing.
    var isStikDebugInstalled: Bool {
        guard let url = URL(string: "stikjit://") else { return false }
        return UIApplication.shared.canOpenURL(url)
    }

    /// The JIT script StikDebug runs on Fathom's behalf, base64-encoded exactly as
    /// StikDebug expects in `script-data`.
    ///
    /// It implements one command and only one: BRK #0xf00d with x16=1, the
    /// "prepare region" request, which is the single request FEXCore's iOS allocator
    /// ever issues (see FEXCore's Utils/Allocator.cpp, iOSJITAlloc). Carried over
    /// unchanged from AetherPS4, which drives the same allocator through the same
    /// protocol.
    fileprivate static let script = """
Ly8gQWV0aGVyUFM0IG1pbmltYWwgSklUIHNjcmlwdC4KLy8KLy8gUHVycG9zZS1idWlsdCBmb3IgZXhhY3RseSB3aGF0IHRoaXMgYXBwIG5lZWRzIGFuZCBub3RoaW5nIGVsc2UsIHNvIGV2ZXJ5IGxpbmUgb2YgdGhpcwovLyBzY3JpcHQncyBsb2dpYyBjYW4gYmUgcmVhc29uZWQgYWJvdXQgZGlyZWN0bHkgcmF0aGVyIHRoYW4gdHJ1c3RpbmcgYW4gYWRhcHRlZCAidW5pdmVyc2FsIgovLyBzY3JpcHQncyBsZWdhY3kgYnJhbmNoZXMuIEFldGhlclBTNCdzIG93biBDKysgKHNyYy9jb3JlL2lvcy9pb3Nfaml0X2FsbG9jYXRvci5jcHAsCi8vIEZFWENvcmUncyBVdGlscy9BbGxvY2F0b3IuY3BwKSBvbmx5IGV2ZXIgaXNzdWVzIE9ORSBraW5kIG9mIEJSSyByZXF1ZXN0OgovLyAgIGJyayAjMHhmMDBkLCB4MTY9MSAoSklUMjZQcmVwYXJlUmVnaW9uIGVxdWl2YWxlbnQpLCB3aXRoIHgwID0gYSByZWFsLCBhbHJlYWR5LWFsbG9jYXRlZAovLyAgIGFkZHJlc3MgKG5ldmVyIDApIGFuZCB4MSA9IGl0cyBzaXplIGluIGJ5dGVzLgovLyBJdCBuZXZlciBzZW5kcyBjb21tYW5kIDAgKGRldGFjaCAtLSBJb3NKaXRBbGxvY2F0b3I6OkRldGFjaCgpIGV4aXN0cyBidXQgaXMgbmV2ZXIgY2FsbGVkOwovLyBzZWUgdGhhdCBoZWFkZXIncyBvd24gZG9jIGNvbW1lbnQpIG9yIGNvbW1hbmQgMiAoZHluYW1pYyBzY3JpcHQgbG9hZGluZyAtLSB0aGlzIHNjcmlwdCBJUwovLyBzZW50IGRpcmVjdGx5IHZpYSBzY3JpcHQtZGF0YSBvbiBldmVyeSBsYXVuY2gsIHNvIHRoZXJlJ3Mgbm90aGluZyB0byBsb2FkIGF0IHJ1bnRpbWUpLCBhbmQKLy8gaXQgbmV2ZXIgYXNrcyBmb3IgYSBmcmVzaCBhbGxvY2F0aW9uICh4MCA9PSAwKSBzaW5jZSBpdCBhbHdheXMgYWxyZWFkeSBvd25zIHRoZSBtZW1vcnkgaXQKLy8gd2FudHMgcHJlcGFyZWQuIFNvIHRoaXMgc2NyaXB0IG9ubHkgaW1wbGVtZW50cyB0aGF0IG9uZSBwYXRoLgoKZnVuY3Rpb24gbGl0dGxlRW5kaWFuSGV4U3RyaW5nVG9OdW1iZXIoaGV4U3RyKSB7CiAgICBjb25zdCBieXRlcyA9IFtdOwogICAgZm9yIChsZXQgaSA9IDA7IGkgPCBoZXhTdHIubGVuZ3RoOyBpICs9IDIpIHsKICAgICAgICBieXRlcy5wdXNoKHBhcnNlSW50KGhleFN0ci5zdWJzdHIoaSwgMiksIDE2KSk7CiAgICB9CiAgICBsZXQgbnVtID0gMG47CiAgICBmb3IgKGxldCBpID0gNDsgaSA+PSAwOyBpLS0pIHsKICAgICAgICBudW0gPSAobnVtIDw8IDhuKSB8IEJpZ0ludChieXRlc1tpXSk7CiAgICB9CiAgICByZXR1cm4gbnVtOwp9CgpmdW5jdGlvbiBudW1iZXJUb0xpdHRsZUVuZGlhbkhleFN0cmluZyhudW0pIHsKICAgIGNvbnN0IGJ5dGVzID0gW107CiAgICBmb3IgKGxldCBpID0gMDsgaSA8IDU7IGkrKykgewogICAgICAgIGJ5dGVzLnB1c2goTnVtYmVyKG51bSAmIDB4RkZuKSk7CiAgICAgICAgbnVtID4+PSA4bjsKICAgIH0KICAgIHdoaWxlIChieXRlcy5sZW5ndGggPCA4KSB7CiAgICAgICAgYnl0ZXMucHVzaCgwKTsKICAgIH0KICAgIHJldHVybiBieXRlcy5tYXAoYiA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKS5qb2luKCcnKTsKfQoKZnVuY3Rpb24gbGl0dGxlRW5kaWFuSGV4VG9VMzIoaGV4U3RyKSB7CiAgICByZXR1cm4gcGFyc2VJbnQoaGV4U3RyLm1hdGNoKC8uLi9nKS5yZXZlcnNlKCkuam9pbignJyksIDE2KTsKfQoKZnVuY3Rpb24gZXh0cmFjdEJya0ltbWVkaWF0ZSh1MzIpIHsKICAgIHJldHVybiAodTMyID4+IDUpICYgMHhGRkZGOwp9Cgpjb25zdCBwaWQgPSBnZXRfcGlkKCk7CmNvbnN0IGF0dGFjaFJlc3BvbnNlID0gc2VuZF9jb21tYW5kKGB2QXR0YWNoOyR7cGlkLnRvU3RyaW5nKDE2KX1gKTsKbG9nKGBwaWQgPSAke3BpZH1gKTsKbG9nKGBhdHRhY2hfcmVzcG9uc2UgPSAke2F0dGFjaFJlc3BvbnNlfWApOwoKbGV0IHRvdGFsU2lnbmFscyA9IDA7CndoaWxlICh0cnVlKSB7CiAgICB0b3RhbFNpZ25hbHMrKzsKICAgIHRyeSB7CiAgICAgICAgaGFuZGxlT25lU2lnbmFsKCk7CiAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBOZXZlciBsZXQgb25lIGJhZCBpdGVyYXRpb24gZW5kIHRoZSB3aG9sZSBzY3JpcHQncyBhYmlsaXR5IHRvIHNlcnZpY2UgZXZlcnkKICAgICAgICAvLyByZXF1ZXN0IGZvciB0aGUgcmVzdCBvZiB0aGUgc2Vzc2lvbiAtLSBsb2cgaXQgYW5kIGtlZXAgdGhlIGxvb3AgcnVubmluZy4KICAgICAgICBsb2coYFVuaGFuZGxlZCBleGNlcHRpb24gd2hpbGUgcHJvY2Vzc2luZyBzaWduYWwgJHt0b3RhbFNpZ25hbHN9OiAke2VyciAmJiBlcnIubmFtZX06ICR7ZXJyICYmIGVyci5tZXNzYWdlfWApOwogICAgICAgIGxvZyhlcnIgJiYgZXJyLnN0YWNrKTsKICAgIH0KfQoKZnVuY3Rpb24gaGFuZGxlT25lU2lnbmFsKCkgewogICAgY29uc3QgYnJrUmVzcG9uc2UgPSBzZW5kX2NvbW1hbmQoYGNgKTsKICAgIGxvZyhgYnJrUmVzcG9uc2UgPSAke2Jya1Jlc3BvbnNlfWApOwoKICAgIGxldCB0bXBNYXRjaCA9IC9UWzAtOWEtZl0rdGhyZWFkOig/PHRpZD5bMC05YS1mXSspOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBjb25zdCB0aWQgPSB0bXBNYXRjaCA/IHRtcE1hdGNoLmdyb3Vwc1sndGlkJ10gOiBudWxsOwogICAgdG1wTWF0Y2ggPSAvMjA6KD88cmVnPlswLTlhLWZdezE2fSk7Ly5leGVjKGJya1Jlc3BvbnNlKTsKICAgIGxldCBwYyA9IHRtcE1hdGNoID8gdG1wTWF0Y2guZ3JvdXBzWydyZWcnXSA6IG51bGw7CiAgICB0bXBNYXRjaCA9IC8xMDooPzxyZWc+WzAtOWEtZl17MTZ9KTsvLmV4ZWMoYnJrUmVzcG9uc2UpOwogICAgbGV0IHgxNiA9IHRtcE1hdGNoID8gdG1wTWF0Y2guZ3JvdXBzWydyZWcnXSA6IG51bGw7CiAgICBpZiAoIXRpZCB8fCAhcGMgfHwgIXgxNikgewogICAgICAgIGxvZyhgRmFpbGVkIHRvIGV4dHJhY3QgcmVnaXN0ZXJzOiB0aWQ9JHt0aWR9LCBwYz0ke3BjfSwgeDE2PSR7eDE2fWApOwogICAgICAgIHJldHVybjsKICAgIH0KICAgIHBjID0gbGl0dGxlRW5kaWFuSGV4U3RyaW5nVG9OdW1iZXIocGMpOwogICAgeDE2ID0gbGl0dGxlRW5kaWFuSGV4U3RyaW5nVG9OdW1iZXIoeDE2KTsKCiAgICBjb25zdCBpbnN0cnVjdGlvblJlc3BvbnNlID0gc2VuZF9jb21tYW5kKGBtJHtwYy50b1N0cmluZygxNil9LDRgKTsKICAgIGNvbnN0IGluc3RyVTMyID0gbGl0dGxlRW5kaWFuSGV4VG9VMzIoaW5zdHJ1Y3Rpb25SZXNwb25zZSk7CgogICAgLy8gTm90IGEgQlJLIGluc3RydWN0aW9uIGF0IGFsbCAtLSBzb21lIG90aGVyIHNpZ25hbCBzdG9wcGVkIHRoaXMgdGhyZWFkLiBQYXNzIGl0IHRocm91Z2gKICAgIC8vIChyZS1kZWxpdmVyIHRoZSBzYW1lIHNpZ25hbCBudW1iZXIpIHNvIHRoZSBndWVzdCdzIG93biBoYW5kbGluZyAoaWYgYW55KSBzdGlsbCBydW5zLAogICAgLy8gdGhlbiBrZWVwIHRoZSBsb29wIGdvaW5nLgogICAgaWYgKCgoaW5zdHJVMzIgJiAweEZGRTAwMDFGKSA+Pj4gMCkgIT09IDB4RDQyMDAwMDApIHsKICAgICAgICBjb25zdCBzaWdudW1NYXRjaCA9IC9eVCg/PHNpZz5bYS16MC05O117Mn0pLy5leGVjKGJya1Jlc3BvbnNlKTsKICAgICAgICBjb25zdCBzaWdudW0gPSBzaWdudW1NYXRjaCA/IHNpZ251bU1hdGNoLmdyb3Vwc1snc2lnJ10gOiBudWxsOwogICAgICAgIGlmIChzaWdudW0pIHsKICAgICAgICAgICAgbG9nKGBOb3QgYSBCUksgKGluc3RydWN0aW9uIDB4JHtpbnN0clUzMi50b1N0cmluZygxNil9KTsgY29udGludWluZyB3aXRoIHNpZ25hbCAweCR7c2lnbnVtfWApOwogICAgICAgICAgICBzZW5kX2NvbW1hbmQoYHZDb250O1Mke3NpZ251bX06JHt0aWR9YCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgbG9nKGBOb3QgYSBCUksgKGluc3RydWN0aW9uIDB4JHtpbnN0clUzMi50b1N0cmluZygxNil9KTsgbm8gc2lnbmFsIG51bWJlciB0byBmb3J3YXJkYCk7CiAgICAgICAgfQogICAgICAgIHJldHVybjsKICAgIH0KCiAgICBjb25zdCBicmtJbW1lZGlhdGUgPSBleHRyYWN0QnJrSW1tZWRpYXRlKGluc3RyVTMyKTsKICAgIGlmIChicmtJbW1lZGlhdGUgIT09IDB4ZjAwZCkgewogICAgICAgIGxvZyhgSWdub3JpbmcgQlJLIGltbWVkaWF0ZSAweCR7YnJrSW1tZWRpYXRlLnRvU3RyaW5nKDE2KX0gKHRoaXMgc2NyaXB0IG9ubHkgaGFuZGxlcyAweGYwMGQpYCk7CiAgICAgICAgcmV0dXJuOwogICAgfQogICAgaWYgKHgxNiAhPT0gMW4pIHsKICAgICAgICBsb2coYElnbm9yaW5nIEpJVDI2IGNvbW1hbmQgJHt4MTYudG9TdHJpbmcoMTYpfSAodGhpcyBzY3JpcHQgb25seSBoYW5kbGVzIGNvbW1hbmQgMSwgcHJlcGFyZSByZWdpb24pYCk7CiAgICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRtcE1hdGNoID0gLzAwOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgeDAgPSB0bXBNYXRjaCA/IHRtcE1hdGNoLmdyb3Vwc1sncmVnJ10gOiBudWxsOwogICAgdG1wTWF0Y2ggPSAvMDE6KD88cmVnPlswLTlhLWZdezE2fSk7Ly5leGVjKGJya1Jlc3BvbnNlKTsKICAgIGxldCB4MSA9IHRtcE1hdGNoID8gdG1wTWF0Y2guZ3JvdXBzWydyZWcnXSA6IG51bGw7CiAgICBpZiAoIXgwIHx8ICF4MSkgewogICAgICAgIGxvZyhgRmFpbGVkIHRvIGV4dHJhY3QgcmVnaXN0ZXJzOiB4MD0ke3gwfSwgeDE9JHt4MX1gKTsKICAgICAgICByZXR1cm47CiAgICB9CiAgICB4MCA9IGxpdHRsZUVuZGlhbkhleFN0cmluZ1RvTnVtYmVyKHgwKTsKICAgIHgxID0gbGl0dGxlRW5kaWFuSGV4U3RyaW5nVG9OdW1iZXIoeDEpOwoKICAgIC8vIFN0ZXAgcGFzdCB0aGUgYnJrIGluc3RydWN0aW9uIGl0c2VsZiBiZWZvcmUgZG9pbmcgYW55dGhpbmcgZWxzZSwgc2FtZSBhcyBldmVyeSBvdGhlcgogICAgLy8gY29tbWFuZCBoYW5kbGVyIGluIHRoaXMgcHJvdG9jb2wgLS0gb3RoZXJ3aXNlIHRoZSB0aHJlYWQgd291bGQgcmUtZXhlY3V0ZSB0aGUgc2FtZSBicmsKICAgIC8vIGluIGFuIGluZmluaXRlIGxvb3Agb25jZSByZXN1bWVkLgogICAgY29uc3QgcGNQbHVzNCA9IG51bWJlclRvTGl0dGxlRW5kaWFuSGV4U3RyaW5nKHBjICsgNG4pOwogICAgY29uc3QgcGNQbHVzNFJlc3BvbnNlID0gc2VuZF9jb21tYW5kKGBQMjA9JHtwY1BsdXM0fTt0aHJlYWQ6JHt0aWR9O2ApOwogICAgbG9nKGBwY1BsdXM0UmVzcG9uc2UgPSAke3BjUGx1czRSZXNwb25zZX1gKTsKCiAgICBpZiAoeDAgPT09IDBuICYmIHgxID09PSAwbikgewogICAgICAgIGxvZyhgcHJlcGFyZSByZWdpb24gcmVxdWVzdGVkIHdpdGggeDA9MCwgeDE9MCAtLSBub3RoaW5nIHRvIGRvYCk7CiAgICAgICAgcmV0dXJuOwogICAgfQoKICAgIGNvbnN0IHByZXBhcmVSZXN1bHQgPSBwcmVwYXJlX21lbW9yeV9yZWdpb24oeDAsIHgxKTsKICAgIGxvZyhgcHJlcGFyZV9tZW1vcnlfcmVnaW9uKDB4JHt4MC50b1N0cmluZygxNil9LCAke3gxfSkgPSAke3ByZXBhcmVSZXN1bHR9YCk7CgogICAgY29uc3QgcHV0WDBSZXNwb25zZSA9IHNlbmRfY29tbWFuZChgUDA9JHtudW1iZXJUb0xpdHRsZUVuZGlhbkhleFN0cmluZyh4MCl9O3RocmVhZDoke3RpZH07YCk7CiAgICBsb2coYHB1dFgwUmVzcG9uc2UgPSAke3B1dFgwUmVzcG9uc2V9YCk7Cn0K
"""
}

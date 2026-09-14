import Foundation

/// One x86-64 program in the library.
///
/// The ELF facts (`kind`, `entry`, `interpreter`) are read once at import and cached,
/// because they never change for a given file and re-reading headers to draw a list row
/// is wasteful. They are re-read whenever the program is opened, so a file replaced
/// underneath the app still shows the truth.
struct Program: Identifiable, Codable, Hashable {
    enum Kind: Int, Codable {
        case unknown = 0
        case staticExecutable = 1
        case staticPIE = 2
        case dynamic = 3

        var title: String {
            switch self {
            case .staticExecutable: return "Static"
            case .staticPIE: return "Static PIE"
            case .dynamic: return "Dynamic"
            case .unknown: return "Unrecognised"
            }
        }

        var explanation: String {
            switch self {
            case .staticPIE:
                return "Position-independent and self-contained. This is the shape Fathom runs best."
            case .staticExecutable:
                return "Self-contained, but built to load at a fixed address. iOS reserves the low 4GB of every process, so this usually cannot be placed where it wants to go."
            case .dynamic:
                return "Needs its interpreter and shared libraries from a guest root filesystem, which Fathom does not provide yet."
            case .unknown:
                return "Fathom could not read this as an x86-64 ELF executable."
            }
        }

        var runnable: Bool { self == .staticPIE }
    }

    let id: UUID
    var name: String
    var fileName: String
    var importedAt: Date
    var fileSize: UInt64

    var kind: Kind
    var entry: UInt64
    var imageSize: UInt64
    var interpreter: String
    var inspectionError: String

    var lastRunAt: Date?
    var lastExitCode: Int?

    var url: URL {
        ProgramLibrary.programsDirectory.appendingPathComponent(fileName)
    }

    var subtitle: String {
        var parts = [kind.title]
        if fileSize > 0 {
            parts.append(formatBytes(fileSize))
        }
        return parts.joined(separator: " · ")
    }
}

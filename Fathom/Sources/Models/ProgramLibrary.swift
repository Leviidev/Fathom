import Foundation

/// The library: the programs on disk, and the metadata index over them.
///
/// Files live in Documents/Programs so they are visible in the Files app -- copying a
/// binary in there by hand is a legitimate way to add one, and the library notices on
/// the next refresh rather than insisting everything arrive through the importer.
@MainActor
final class ProgramLibrary: ObservableObject {
    @Published private(set) var programs: [Program] = []
    @Published var lastError: String?

    nonisolated static var documentsDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    nonisolated static var programsDirectory: URL {
        documentsDirectory.appendingPathComponent("Programs", isDirectory: true)
    }

    nonisolated static var guestRootDirectory: URL {
        documentsDirectory.appendingPathComponent("GuestRoot", isDirectory: true)
    }

    private var indexURL: URL {
        Self.documentsDirectory.appendingPathComponent("library.json")
    }

    init() {
        createDirectories()
        load()
        refresh()
    }

    private func createDirectories() {
        for directory in [Self.programsDirectory, Self.guestRootDirectory] {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        // Dynamically linked programs need a root filesystem to find their loader and
        // libraries in. Installing it here means it is in place before any program runs.
        do {
            try GuestRootfs.installIfNeeded()
        } catch {
            log("could not install the guest root filesystem: \(error.localizedDescription)", level: .error)
        }
    }

    // MARK: - Persistence

    private func load() {
        guard let data = try? Data(contentsOf: indexURL) else { return }
        do {
            programs = try JSONDecoder().decode([Program].self, from: data)
        } catch {
            log("could not read the library index: \(error.localizedDescription)", level: .warn)
        }
    }

    private func save() {
        do {
            let data = try JSONEncoder().encode(programs)
            try data.write(to: indexURL, options: .atomic)
        } catch {
            log("could not write the library index: \(error.localizedDescription)", level: .error)
        }
    }

    // MARK: - Contents

    /// Reconciles the index with what is actually on disk, in both directions: entries
    /// whose file has gone are dropped, and files dropped in through the Files app are
    /// adopted.
    func refresh() {
        let manager = FileManager.default
        let onDisk = (try? manager.contentsOfDirectory(at: Self.programsDirectory,
                                                       includingPropertiesForKeys: [.fileSizeKey],
                                                       options: [.skipsHiddenFiles])) ?? []
        let names = Set(onDisk.map(\.lastPathComponent))

        let before = programs.count
        programs.removeAll { !names.contains($0.fileName) }

        let known = Set(programs.map(\.fileName))
        for url in onDisk where !known.contains(url.lastPathComponent) {
            if let program = inspect(url: url, name: url.deletingPathExtension().lastPathComponent) {
                programs.append(program)
                log("adopted \(url.lastPathComponent) found in Programs/")
            }
        }

        programs.sort { $0.importedAt > $1.importedAt }
        if programs.count != before {
            save()
        }
    }

    /// Reads the ELF headers through the emulator core, so the library and the loader
    /// always agree about what a file is.
    private func inspect(url: URL, name: String) -> Program? {
        var info = fathom_program_info()
        let ok = url.path.withCString { fathom_inspect_program($0, &info) }

        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).flatMap { UInt64($0) } ?? 0
        let kind: Program.Kind
        switch info.kind {
        case FATHOM_PROGRAM_STATIC: kind = .staticExecutable
        case FATHOM_PROGRAM_STATIC_PIE: kind = .staticPIE
        case FATHOM_PROGRAM_DYNAMIC: kind = .dynamic
        default: kind = .unknown
        }

        return Program(
            id: UUID(),
            name: name,
            fileName: url.lastPathComponent,
            importedAt: Date(),
            fileSize: size,
            kind: ok ? kind : .unknown,
            entry: info.entry,
            imageSize: info.image_size,
            interpreter: withUnsafeBytes(of: info.interpreter) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) },
            inspectionError: withUnsafeBytes(of: info.error) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) },
            lastRunAt: nil,
            lastExitCode: nil
        )
    }

    // MARK: - Mutation

    func importProgram(from source: URL) {
        // A URL handed over by the document picker is outside the app's container and
        // only readable inside this scope.
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }

        let destination = uniqueDestination(for: source.lastPathComponent)
        do {
            try FileManager.default.copyItem(at: source, to: destination)
        } catch {
            lastError = "Could not import \(source.lastPathComponent): \(error.localizedDescription)"
            log(lastError!, level: .error)
            return
        }

        guard var program = inspect(url: destination, name: source.deletingPathExtension().lastPathComponent) else {
            lastError = "Could not read \(source.lastPathComponent)."
            return
        }
        program.importedAt = Date()
        programs.insert(program, at: 0)
        save()
        log("imported \(program.fileName) (\(program.kind.title))")
    }

    private func uniqueDestination(for fileName: String) -> URL {
        var candidate = Self.programsDirectory.appendingPathComponent(fileName)
        guard FileManager.default.fileExists(atPath: candidate.path) else { return candidate }

        let base = (fileName as NSString).deletingPathExtension
        let ext = (fileName as NSString).pathExtension
        var index = 2
        repeat {
            let suffix = ext.isEmpty ? "\(base) \(index)" : "\(base) \(index).\(ext)"
            candidate = Self.programsDirectory.appendingPathComponent(suffix)
            index += 1
        } while FileManager.default.fileExists(atPath: candidate.path)
        return candidate
    }

    func rename(_ program: Program, to name: String) {
        guard let index = programs.firstIndex(of: program) else { return }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        programs[index].name = trimmed
        save()
    }

    func delete(_ program: Program) {
        try? FileManager.default.removeItem(at: program.url)
        programs.removeAll { $0.id == program.id }
        save()
        log("removed \(program.fileName)")
    }

    func recordRun(_ program: Program, exitCode: Int) {
        guard let index = programs.firstIndex(of: program) else { return }
        programs[index].lastRunAt = Date()
        programs[index].lastExitCode = exitCode
        save()
    }

    /// Re-reads one program's headers from disk, for the detail screen.
    func reinspect(_ program: Program) -> Program {
        guard var fresh = inspect(url: program.url, name: program.name) else { return program }
        fresh = Program(id: program.id, name: program.name, fileName: program.fileName,
                        importedAt: program.importedAt, fileSize: fresh.fileSize, kind: fresh.kind,
                        entry: fresh.entry, imageSize: fresh.imageSize, interpreter: fresh.interpreter,
                        inspectionError: fresh.inspectionError, lastRunAt: program.lastRunAt,
                        lastExitCode: program.lastExitCode)
        if let index = programs.firstIndex(where: { $0.id == program.id }) {
            programs[index] = fresh
            save()
        }
        return fresh
    }

    var totalBytes: UInt64 {
        programs.reduce(0) { $0 + $1.fileSize }
    }
}

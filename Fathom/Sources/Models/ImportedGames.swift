import Foundation

/// A game folder the user pointed Fathom at: wherever it lives (Files, iCloud, an external
/// drive), kept through a bookmark rather than copied, with the .exe that starts it.
struct ImportedGame: Codable, Identifiable, Hashable {
    let id: UUID
    var name: String
    var bookmark: Data
    /// The executable to launch, relative to the folder.
    var executable: String
    /// Every executable found, so the choice can be changed later.
    var candidates: [String]
    /// The Steam store entry it was matched to, for art and details.
    var appid: Int?
    var addedAt: Date
}

@MainActor
final class ImportedGames: ObservableObject {
    static let shared = ImportedGames()

    @Published private(set) var games: [ImportedGame] = []
    @Published var error: String?

    private var indexURL: URL {
        ProgramLibrary.documentsDirectory.appendingPathComponent("imported-games.json")
    }

    private init() {
        if let data = try? Data(contentsOf: indexURL),
           let saved = try? JSONDecoder().decode([ImportedGame].self, from: data) {
            games = saved
        }
    }

    /// Adds a folder. Returns the game when it has more than one executable, so the caller
    /// can ask which one starts it.
    @discardableResult
    func importFolder(_ folder: URL) -> ImportedGame? {
        let scoped = folder.startAccessingSecurityScopedResource()
        defer { if scoped { folder.stopAccessingSecurityScopedResource() } }

        let executables = Self.executables(in: folder)
        guard !executables.isEmpty else {
            error = "\(folder.lastPathComponent) has no .exe or Linux program in it."
            return nil
        }
        guard let bookmark = try? folder.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil) else {
            error = "Fathom could not keep access to \(folder.lastPathComponent)."
            return nil
        }
        let game = ImportedGame(id: UUID(), name: folder.lastPathComponent, bookmark: bookmark,
                                executable: Self.bestGuess(executables, folderName: folder.lastPathComponent),
                                candidates: executables, appid: nil, addedAt: Date())
        games.insert(game, at: 0)
        save()
        log("imported game folder \(game.name) (\(executables.count) executable\(executables.count == 1 ? "" : "s"))")

        let id = game.id, name = game.name
        Task {
            if let match = await GameCatalog.match(name: name), let index = games.firstIndex(where: { $0.id == id }) {
                games[index].appid = match.appid
                games[index].name = match.name
                save()
            }
        }
        return executables.count > 1 ? game : nil
    }

    func setExecutable(_ executable: String, for game: ImportedGame) {
        guard let index = games.firstIndex(where: { $0.id == game.id }) else { return }
        games[index].executable = executable
        save()
    }

    func remove(_ game: ImportedGame) {
        games.removeAll { $0.id == game.id }
        save()
    }

    /// The folder, resolved from its bookmark. The caller brackets its use with security-scoped access.
    func folder(of game: ImportedGame) -> URL? {
        var stale = false
        return try? URL(resolvingBookmarkData: game.bookmark, options: [], relativeTo: nil, bookmarkDataIsStale: &stale)
    }

    private func save() {
        if let data = try? JSONEncoder().encode(games) { try? data.write(to: indexURL, options: .atomic) }
    }

    /// .exe files and ELF programs, up to a few levels down -- games keep their launcher in a
    /// bin/ or Binaries/Win64/ folder as often as at the top.
    private static func executables(in folder: URL) -> [String] {
        guard let walker = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: [.isRegularFileKey],
                                                          options: [.skipsHiddenFiles]) else { return [] }
        var found: [String] = []
        let base = folder.standardizedFileURL.path
        for case let url as URL in walker {
            if walker.level > 4 { walker.skipDescendants(); continue }
            let lower = url.lastPathComponent.lowercased()
            let skip = ["unins", "setup", "crashhandler", "crashreport", "vc_redist", "dxsetup", "dotnet", "ue4prereq", "ueprereq"]
            guard !skip.contains(where: lower.hasPrefix) else { continue }
            if lower.hasSuffix(".exe") || isELF(url) {
                found.append(String(url.standardizedFileURL.path.dropFirst(base.count + 1)))
            }
            if found.count >= 50 { break }
        }
        return found.sorted { $0.count == $1.count ? $0 < $1 : $0.count < $1.count }
    }

    private static func isELF(_ url: URL) -> Bool {
        guard url.pathExtension.isEmpty, let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: 4)) == Data([0x7f, 0x45, 0x4c, 0x46])
    }

    /// The executable named most like the folder, else the shallowest one.
    private static func bestGuess(_ executables: [String], folderName: String) -> String {
        let key = folderName.lowercased().filter(\.isLetter)
        return executables.first { ($0 as NSString).lastPathComponent.lowercased().filter(\.isLetter).hasPrefix(String(key.prefix(5))) }
            ?? executables[0]
    }
}

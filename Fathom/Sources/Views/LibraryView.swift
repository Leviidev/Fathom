import SwiftUI
import UniformTypeIdentifiers

/// Where the library leads.
enum LibraryRoute: Hashable {
    case steam(SteamAccount.OwnedGame)
    case imported(ImportedGame)
}

struct LibraryView: View {
    @EnvironmentObject private var library: ProgramLibrary
    @EnvironmentObject private var jit: JITSupport
    @ObservedObject private var steam = SteamAccount.shared
    @ObservedObject private var imported = ImportedGames.shared
    @AppStorage(Holiday.key) private var holiday = true

    @State private var search = ""
    @State private var importer: Importer?
    @State private var choosingExecutable: ImportedGame?
    @State private var renaming: Program?
    @State private var newName = ""

    enum Importer: Identifiable {
        case folder, program
        var id: Self { self }
    }

    private let columns = [GridItem(.adaptive(minimum: 104, maximum: 150), spacing: 14, alignment: .top)]

    private func matches(_ name: String) -> Bool {
        search.isEmpty || name.localizedCaseInsensitiveContains(search)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 26) {
                    if jit.status != .enabled {
                        JITBanner()
                    }
                    steamSection
                    importedSection
                    linuxSection
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
            }
            .background(Theme.background)
            .searchable(text: $search, prompt: "Search your games")
            .navigationTitle("Library")
            .navigationDestination(for: LibraryRoute.self) { route in
                switch route {
                case .steam(let game): GameDetailView(source: .steam(game))
                case .imported(let game): GameDetailView(source: .imported(game))
                }
            }
            .navigationDestination(for: Program.self) { ProgramDetailView(program: $0) }
            .toolbar {
                if holiday {
                    ToolbarItem(placement: .topBarLeading) { ChristmasTree(size: 28) }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button { importer = .folder } label: { Label("Import Game Folder", systemImage: "folder.badge.plus") }
                        Button { importer = .program } label: { Label("Add Linux Program", systemImage: "terminal") }
                    } label: {
                        Image(systemName: "plus.circle.fill").font(.title3)
                    }
                }
            }
            .refreshable {
                library.refresh()
                await steam.refreshLibrary()
            }
            .fileImporter(isPresented: Binding(get: { importer != nil }, set: { if !$0 { importer = nil } }),
                          allowedContentTypes: importer == .folder ? [.folder] : [.data, .unixExecutable, .executable],
                          allowsMultipleSelection: importer == .program) { result in
                let kind = importer
                importer = nil
                switch result {
                case .success(let urls):
                    if kind == .folder {
                        if let url = urls.first, let game = imported.importFolder(url) { choosingExecutable = game }
                    } else {
                        urls.forEach(library.importProgram(from:))
                    }
                case .failure(let error):
                    library.lastError = error.localizedDescription
                }
            }
            .sheet(item: $choosingExecutable) { game in
                ExecutablePicker(game: game)
            }
            .alert("Rename", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
                TextField("Name", text: $newName)
                Button("Cancel", role: .cancel) { renaming = nil }
                Button("Save") {
                    if let renaming { library.rename(renaming, to: newName) }
                    renaming = nil
                }
            }
            .alert("Import failed", isPresented: Binding(get: { library.lastError != nil || imported.error != nil },
                                                        set: { if !$0 { library.lastError = nil; imported.error = nil } })) {
                Button("OK", role: .cancel) { library.lastError = nil; imported.error = nil }
            } message: {
                Text(library.lastError ?? imported.error ?? "")
            }
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var steamSection: some View {
        let games = steam.games.filter { matches($0.name) }
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "Steam", detail: steam.phase == .signedIn ? "\(steam.games.count) games" : nil,
                          busy: steam.isLoadingLibrary)
            if steam.phase != .signedIn {
                NavigationLink {
                    SteamSignInView()
                } label: {
                    PromptCard(systemImage: "person.crop.circle.badge.plus", title: "Sign in to Steam",
                               message: "See your library here, with art, screenshots and reviews.")
                }
                .buttonStyle(.plain)
            } else if games.isEmpty {
                Text(search.isEmpty ? "No games yet." : "No Steam games match \u{201C}\(search)\u{201D}.")
                    .font(.subheadline).foregroundStyle(.secondary)
            } else {
                LazyVGrid(columns: columns, spacing: 18) {
                    ForEach(games) { game in
                        NavigationLink(value: LibraryRoute.steam(game)) {
                            GameTile(appid: game.appid, name: game.name)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var importedSection: some View {
        let games = imported.games.filter { matches($0.name) }
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "Imported", detail: imported.games.isEmpty ? nil : "\(imported.games.count)")
            if imported.games.isEmpty {
                Button { importer = .folder } label: {
                    PromptCard(systemImage: "folder.badge.plus", title: "Import a game folder",
                               message: "Pick a folder with the game's .exe in it, from Files or a drive.")
                }
                .buttonStyle(.plain)
            } else {
                LazyVGrid(columns: columns, spacing: 18) {
                    ForEach(games) { game in
                        NavigationLink(value: LibraryRoute.imported(game)) {
                            GameTile(appid: game.appid, name: game.name)
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            if game.candidates.count > 1 {
                                Button { choosingExecutable = game } label: { Label("Choose Executable", systemImage: "list.bullet") }
                            }
                            Button(role: .destructive) { imported.remove(game) } label: { Label("Remove", systemImage: "trash") }
                        }
                    }
                }
            }
        }
    }

    private var linuxSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "Linux", detail: nil)
            VStack(spacing: 0) {
                if search.isEmpty {
                    NavigationLink { ShellView() } label: {
                        ToolRow(systemImage: "terminal", title: "Linux Shell", subtitle: "A shell in the bundled root filesystem")
                    }
                    if GuestRootfs.hasSteam {
                        Divider().padding(.leading, 64)
                        NavigationLink { SteamView() } label: {
                            ToolRow(systemImage: "gamecontroller", title: "Steam Client", subtitle: "The Linux Steam client, drawn live")
                        }
                    }
                }
                ForEach(library.programs.filter { matches($0.name) }) { program in
                    Divider().padding(.leading, 64)
                    NavigationLink(value: program) {
                        ToolRow(systemImage: program.kind.runnable ? "cpu" : "exclamationmark.triangle",
                                title: program.name, subtitle: program.subtitle,
                                tint: program.kind.runnable ? Theme.accent : .orange)
                    }
                    .contextMenu {
                        Button { renaming = program; newName = program.name } label: { Label("Rename", systemImage: "pencil") }
                        Button(role: .destructive) { library.delete(program) } label: { Label("Delete", systemImage: "trash") }
                    }
                }
            }
            .buttonStyle(.plain)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.cardCorner))
            .snowCap()
        }
    }
}

// MARK: - Pieces

private struct SectionHeader: View {
    let title: String
    let detail: String?
    var busy = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).font(.title2.weight(.bold))
            if let detail { Text(detail).font(.subheadline).foregroundStyle(.secondary) }
            if busy { ProgressView().controlSize(.small) }
            Spacer()
        }
    }
}

/// A cover in the grid: portrait library art, falling back to the store header, falling
/// back to a lettered tile for games Steam has never heard of.
struct GameTile: View {
    let appid: Int?
    let name: String

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            ZStack {
                Theme.surfaceRaised
                if let appid {
                    RemoteImage(url: GameInfo.art(appid, "library_600x900.jpg")) { lettered }
                } else {
                    lettered
                }
            }
            .aspectRatio(2 / 3, contentMode: .fit)
            .clipShape(RoundedRectangle(cornerRadius: Theme.tileCorner))
            .overlay(RoundedRectangle(cornerRadius: Theme.tileCorner).strokeBorder(.primary.opacity(0.06)))
            .snowCap(height: 8)

            Text(name)
                .font(.caption.weight(.semibold))
                .lineLimit(2)
                .foregroundStyle(.primary)
        }
    }

    private var lettered: some View {
        ZStack {
            Theme.surfaceRaised
            if let appid {
                RemoteImage(url: GameInfo.art(appid, "header.jpg"), contentMode: .fit) { initials }
            } else {
                initials
            }
        }
    }

    private var initials: some View {
        Text(name.split(separator: " ").prefix(2).compactMap(\.first).map(String.init).joined())
            .font(.system(size: 30, weight: .bold, design: .rounded))
            .foregroundStyle(Theme.accent)
    }
}

private struct PromptCard: View {
    let systemImage: String
    let title: String
    let message: String

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: systemImage)
                .font(.title2)
                .foregroundStyle(Theme.accent)
                .frame(width: 44, height: 44)
                .background(Theme.accentSoft, in: RoundedRectangle(cornerRadius: 11))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                Text(message).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
        }
        .padding(14)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.cardCorner))
        .snowCap()
    }
}

private struct ToolRow: View {
    let systemImage: String
    let title: String
    let subtitle: String
    var tint: Color = Theme.accent

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: systemImage)
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(tint)
                .frame(width: 36, height: 36)
                .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.medium)).lineLimit(1)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }
}

/// Which .exe starts a game whose folder holds several.
private struct ExecutablePicker: View {
    let game: ImportedGame
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List(game.candidates, id: \.self) { candidate in
                Button {
                    ImportedGames.shared.setExecutable(candidate, for: game)
                    dismiss()
                } label: {
                    HStack {
                        Text(candidate).font(.technical(13)).foregroundStyle(.primary)
                        Spacer()
                        if candidate == (ImportedGames.shared.games.first { $0.id == game.id }?.executable ?? game.executable) {
                            Image(systemName: "checkmark").foregroundStyle(Theme.accent)
                        }
                    }
                }
            }
            .navigationTitle("Which one starts the game?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        .presentationDetents([.medium, .large])
    }
}

/// Shown above the library whenever the emulator cannot actually run anything, because
/// an empty library and a JIT-less app look identical otherwise.
struct JITBanner: View {
    @EnvironmentObject private var jit: JITSupport

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                Label("JIT is not enabled", systemImage: "bolt.slash")
                    .font(.headline)
                    .foregroundStyle(.orange)
                Text("iOS will not let Fathom make memory executable on its own, and the emulator cannot run a single instruction without it. StikDebug grants that permission by attaching to Fathom.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                HStack {
                    Button("Enable with StikDebug") {
                        jit.requestJIT()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)

                    Button("Re-check") {
                        jit.refresh()
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.top, 2)
            }
        }
        .padding(.vertical, 4)
    }
}

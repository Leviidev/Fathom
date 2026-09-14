import SwiftUI
import UniformTypeIdentifiers

struct LibraryView: View {
    @EnvironmentObject private var library: ProgramLibrary
    @EnvironmentObject private var jit: JITSupport

    @State private var isImporting = false
    @State private var search = ""
    @State private var renaming: Program?
    @State private var newName = ""

    private var filtered: [Program] {
        guard !search.isEmpty else { return library.programs }
        return library.programs.filter { $0.name.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        NavigationStack {
            Group {
                if library.programs.isEmpty {
                    ScrollView {
                        VStack(spacing: 20) {
                            if jit.status != .enabled {
                                JITBanner()
                                    .padding(.horizontal)
                            }
                            EmptyState(
                                title: "No programs yet",
                                message: "Add an x86-64 Linux executable to run it here. Statically linked, position-independent builds work best — try building with -static-pie.",
                                systemImage: "tray.and.arrow.down",
                                actionTitle: "Add a Program",
                                action: { isImporting = true }
                            )
                        }
                        .padding(.top, 24)
                    }
                } else {
                    List {
                        if jit.status != .enabled {
                            Section {
                                JITBanner()
                                    .listRowInsets(EdgeInsets())
                                    .listRowBackground(Color.clear)
                            }
                        }

                        Section {
                            ForEach(filtered) { program in
                                NavigationLink(value: program) {
                                    ProgramRow(program: program)
                                }
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) {
                                        library.delete(program)
                                    } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                    Button {
                                        renaming = program
                                        newName = program.name
                                    } label: {
                                        Label("Rename", systemImage: "pencil")
                                    }
                                    .tint(Theme.accent)
                                }
                            }
                        } footer: {
                            Text("\(library.programs.count) program\(library.programs.count == 1 ? "" : "s") · \(formatBytes(library.totalBytes))")
                        }
                    }
                    .listStyle(.insetGrouped)
                    .searchable(text: $search, prompt: "Search programs")
                }
            }
            .navigationTitle("Library")
            .navigationDestination(for: Program.self) { program in
                ProgramDetailView(program: program)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        isImporting = true
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                }
            }
            .refreshable {
                library.refresh()
            }
            .fileImporter(isPresented: $isImporting,
                          allowedContentTypes: [.data, .unixExecutable, .executable],
                          allowsMultipleSelection: true) { result in
                switch result {
                case .success(let urls):
                    urls.forEach(library.importProgram(from:))
                case .failure(let error):
                    library.lastError = error.localizedDescription
                }
            }
            .alert("Rename", isPresented: Binding(get: { renaming != nil },
                                                  set: { if !$0 { renaming = nil } })) {
                TextField("Name", text: $newName)
                Button("Cancel", role: .cancel) { renaming = nil }
                Button("Save") {
                    if let renaming { library.rename(renaming, to: newName) }
                    renaming = nil
                }
            }
            .alert("Import failed", isPresented: Binding(get: { library.lastError != nil },
                                                        set: { if !$0 { library.lastError = nil } })) {
                Button("OK", role: .cancel) { library.lastError = nil }
            } message: {
                Text(library.lastError ?? "")
            }
        }
    }
}

private struct ProgramRow: View {
    let program: Program

    var body: some View {
        HStack(spacing: 14) {
            RoundedRectangle(cornerRadius: 10)
                .fill(Theme.accentSoft)
                .frame(width: 42, height: 42)
                .overlay {
                    Image(systemName: program.kind.runnable ? "cpu" : "exclamationmark.triangle")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(program.kind.runnable ? Theme.accent : Color.orange)
                }

            VStack(alignment: .leading, spacing: 3) {
                Text(program.name)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                Text(program.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            if let code = program.lastExitCode {
                Text(code == 0 ? "exit 0" : "exit \(code)")
                    .font(.technical(11))
                    .foregroundStyle(code == 0 ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.orange))
            }
        }
        .padding(.vertical, 4)
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

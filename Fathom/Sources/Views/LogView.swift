import SwiftUI

struct LogView: View {
    @EnvironmentObject private var logStore: FathomLog
    @State private var isSharing = false
    @State private var minimumLevel: FathomLog.Level = .info

    private var filtered: [FathomLog.Entry] {
        logStore.entries.filter { $0.level >= minimumLevel }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Level", selection: $minimumLevel) {
                Text("Debug").tag(FathomLog.Level.debug)
                Text("Info").tag(FathomLog.Level.info)
                Text("Warnings").tag(FathomLog.Level.warn)
                Text("Errors").tag(FathomLog.Level.error)
            }
            .pickerStyle(.segmented)
            .padding()

            if filtered.isEmpty {
                EmptyState(title: "Nothing logged",
                           message: "Lines appear here as Fathom and the emulator core do work.",
                           systemImage: "doc.text")
                Spacer()
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(filtered) { entry in
                                HStack(alignment: .top, spacing: 8) {
                                    Text(entry.level.label)
                                        .font(.technical(10, weight: .semibold))
                                        .foregroundStyle(colour(for: entry.level))
                                        .frame(width: 44, alignment: .leading)
                                    Text(entry.message)
                                        .font(.technical(11))
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .padding(.horizontal)
                                .id(entry.id)
                            }
                        }
                        .padding(.vertical, 8)
                    }
                    .onChange(of: filtered.count) { _, _ in
                        if let last = filtered.last {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
        }
        .navigationTitle("Log")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button {
                        isSharing = true
                    } label: {
                        Label("Export log file", systemImage: "square.and.arrow.up")
                    }
                    Button {
                        UIPasteboard.general.string = filtered.map { "[\($0.level.label)] \($0.message)" }
                            .joined(separator: "\n")
                    } label: {
                        Label("Copy visible", systemImage: "doc.on.doc")
                    }
                    Button(role: .destructive) {
                        logStore.clear()
                    } label: {
                        Label("Clear view", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .sheet(isPresented: $isSharing) {
            ShareSheet(items: [logStore.fileURL])
        }
    }

    private func colour(for level: FathomLog.Level) -> Color {
        switch level {
        case .debug: return .secondary
        case .info: return Theme.accent
        case .warn: return .orange
        case .error: return .red
        }
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

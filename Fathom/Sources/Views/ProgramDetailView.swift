import SwiftUI

struct ProgramDetailView: View {
    let program: Program

    @EnvironmentObject private var library: ProgramLibrary
    @EnvironmentObject private var settings: EmulatorSettings
    @EnvironmentObject private var jit: JITSupport
    @StateObject private var session = EmulatorSession()

    @State private var inspected: Program?

    private var current: Program { inspected ?? program }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                header
                if session.state == .idle {
                    details
                } else {
                    ConsoleView(session: session, program: current)
                }
            }
            .padding()
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle(current.name)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            inspected = library.reinspect(program)
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if session.state.isActive {
                    Button("Stop", role: .destructive) { session.stop() }
                } else if session.state != .idle {
                    Button("Done") { session.reset() }
                }
            }
        }
    }

    private var header: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 14) {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Theme.accentSoft)
                        .frame(width: 52, height: 52)
                        .overlay {
                            Image(systemName: "cpu")
                                .font(.system(size: 22, weight: .medium))
                                .foregroundStyle(Theme.accent)
                        }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(current.name)
                            .font(.title3.weight(.semibold))
                        Text(current.fileName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                }

                statusPills

                if !current.kind.runnable {
                    Text(current.kind.explanation)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                runButton
            }
        }
    }

    private var statusPills: some View {
        HStack(spacing: 8) {
            StatusPill(text: current.kind.title,
                       systemImage: current.kind.runnable ? "checkmark.seal" : "exclamationmark.triangle",
                       tint: current.kind.runnable ? Theme.accent : .orange)
            StatusPill(text: jit.status == .enabled ? "JIT ready" : "No JIT",
                       systemImage: jit.status == .enabled ? "bolt.fill" : "bolt.slash",
                       tint: jit.status == .enabled ? .green : .orange)
            Spacer()
        }
    }

    @ViewBuilder
    private var runButton: some View {
        let blocked = !current.kind.runnable || jit.status != .enabled

        Button {
            session.run(program: current, settings: settings, library: library)
        } label: {
            Label(session.state.isActive ? "Running" : "Run", systemImage: "play.fill")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .tint(Theme.accent)
        .controlSize(.large)
        .disabled(blocked || session.state.isActive)

        if blocked {
            Text(jit.status != .enabled
                 ? "Enable JIT from Settings before running anything."
                 : "Fathom cannot run this program on this device.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var details: some View {
        VStack(spacing: 16) {
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Program")
                        .font(.subheadline.weight(.semibold))
                    DetailRow(label: "Architecture", value: "x86-64", mono: false)
                    DetailRow(label: "Type", value: current.kind.title, mono: false)
                    DetailRow(label: "Entry point", value: formatHex(current.entry))
                    DetailRow(label: "Image size", value: formatBytes(current.imageSize))
                    DetailRow(label: "File size", value: formatBytes(current.fileSize))
                    if !current.interpreter.isEmpty {
                        DetailRow(label: "Interpreter", value: current.interpreter)
                    }
                    DetailRow(label: "Imported", value: current.importedAt.formatted(date: .abbreviated, time: .shortened), mono: false)
                    if let lastRun = current.lastRunAt {
                        DetailRow(label: "Last run", value: lastRun.formatted(date: .abbreviated, time: .shortened), mono: false)
                    }
                }
            }

            if !current.inspectionError.isEmpty {
                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Note", systemImage: "info.circle")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.orange)
                        Text(current.inspectionError)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Text("This run will use")
                        .font(.subheadline.weight(.semibold))
                    DetailRow(label: "Address space", value: "\(settings.addressSpaceMB) MB", mono: false)
                    DetailRow(label: "Guest stack", value: "\(settings.stackMB) MB", mono: false)
                    DetailRow(label: "Multiblock", value: settings.multiblock ? "On" : "Off", mono: false)
                    DetailRow(label: "TSO emulation", value: settings.tsoEnabled ? "On" : "Off", mono: false)
                    if settings.traceSyscalls {
                        DetailRow(label: "Syscall tracing", value: "On", mono: false)
                    }
                }
            }
        }
    }
}

import SwiftUI

/// What the guest is doing right now: its output, and the few numbers that show it is
/// making progress rather than wedged.
struct ConsoleView: View {
    @ObservedObject var session: EmulatorSession

    var body: some View {
        VStack(spacing: 16) {
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        stateLabel
                        Spacer()
                        Text(String(format: "%.1fs", session.elapsed))
                            .font(.technical(12))
                            .foregroundStyle(.secondary)
                    }

                    HStack(spacing: 20) {
                        metric("Syscalls", value: "\(session.syscallCount)")
                        metric("RIP", value: formatHex(session.rip))
                        Spacer()
                    }
                }
            }

            if case .failed(let message) = session.state {
                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Could not run", systemImage: "xmark.octagon")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.red)
                        Text(message)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            }

            if session.isInteractive {
                TerminalView(terminal: session.terminal) { key in
                    session.sendKey(key)
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(session.isInteractive ? "Raw output" : "Output")
                            .font(.subheadline.weight(.semibold))
                        Spacer()
                        if !session.output.isEmpty {
                            Button {
                                UIPasteboard.general.string = session.outputText
                            } label: {
                                Image(systemName: "doc.on.doc")
                            }
                            .font(.caption)
                        }
                    }

                    if session.isInteractive {
                        Text("The program is drawing to the screen above. Its raw byte stream is hidden here because it is mostly escape sequences.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 8)
                    } else if session.output.isEmpty {
                        Text(session.state.isActive
                             ? "Waiting for the program to write something."
                             : "The program produced no output.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 8)
                    } else {
                        ScrollViewReader { proxy in
                            ScrollView {
                                VStack(alignment: .leading, spacing: 0) {
                                    ForEach(session.output) { chunk in
                                        Text(chunk.text)
                                            .font(.technical(12))
                                            .foregroundStyle(chunk.isError ? .orange : .primary)
                                            .textSelection(.enabled)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                    Color.clear.frame(height: 1).id("bottom")
                                }
                            }
                            .frame(maxHeight: 340)
                            .onChange(of: session.output.count) { _, _ in
                                withAnimation { proxy.scrollTo("bottom", anchor: .bottom) }
                            }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var stateLabel: some View {
        switch session.state {
        case .preparing:
            Label("Loading", systemImage: "hourglass")
                .foregroundStyle(.secondary)
        case .running:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Running").foregroundStyle(Theme.accent)
            }
        case .finished(let code):
            Label(code == 0 ? "Finished" : "Exited with status \(code)",
                  systemImage: code == 0 ? "checkmark.circle" : "exclamationmark.circle")
                .foregroundStyle(code == 0 ? .green : .orange)
        case .stopped:
            Label("Stopped", systemImage: "stop.circle")
                .foregroundStyle(.secondary)
        case .failed:
            Label("Failed", systemImage: "xmark.octagon")
                .foregroundStyle(.red)
        case .idle:
            Label("Ready", systemImage: "circle")
                .foregroundStyle(.secondary)
        }
    }

    private func metric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.technical(13, weight: .medium))
        }
    }
}

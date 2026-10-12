import SwiftUI

/// Downloading one game through steamcmd, with the console it runs in: the first sign-in
/// asks for the password and a Steam Guard code there, and steamcmd remembers it after.
struct DownloadView: View {
    let appid: Int
    let name: String

    @EnvironmentObject private var settings: EmulatorSettings
    @EnvironmentObject private var jit: JITSupport
    @ObservedObject private var steamcmd = SteamCmd.shared
    @ObservedObject private var steam = SteamAccount.shared
    @StateObject private var session = EmulatorSession()
    @Environment(\.dismiss) private var dismiss
    @State private var restarts = 0

    private var progress: (fraction: Double, done: UInt64, total: UInt64)? {
        // " Update state (0x61) downloading, progress: 12.34 (123 / 456)"
        let text = session.outputText
        guard let range = text.range(of: #"progress: ([0-9.]+) \((\d+) / (\d+)\)"#, options: [.regularExpression, .backwards]) else { return nil }
        let parts = text[range].split(whereSeparator: { !$0.isNumber && $0 != "." })
        guard parts.count >= 3, let percent = Double(parts[0]), let done = UInt64(parts[1]), let total = UInt64(parts[2]) else { return nil }
        return (percent / 100, done, total)
    }

    private var succeeded: Bool { session.outputText.contains("fully installed") }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if jit.status != .enabled {
                    JITBanner()
                } else {
                    switch steamcmd.phase {
                    case .ready:
                        downloadCard
                        if session.state != .idle {
                            ConsoleView(session: session, prefersKeyboard: true, alwaysInteractive: true)
                        }
                    case .missing, .failed:
                        installCard
                    case .installing(let step, let fraction):
                        Card {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("Setting up the downloader").font(.headline)
                                ProgressView(value: fraction) { Text(step).font(.caption).foregroundStyle(.secondary) }
                            }
                        }
                    }
                }
            }
            .padding()
        }
        .background(Theme.background)
        .navigationTitle("Download")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if session.state.isActive {
                    Button("Stop", role: .destructive) { session.stop() }
                }
            }
        }
        .onDisappear { if session.state.isActive { session.stop() } }
        // steamcmd updates itself on its first run and exits with 42 to ask for a relaunch,
        // which its shell script would do; here the screen does it.
        .onChange(of: session.state) { _, state in
            if case .finished(let code) = state, code == 42, restarts < 3 {
                restarts += 1
                session.reset()
                start()
            }
        }
    }

    private func start() {
        session.runInGuest(path: SteamCmd.guestProgram,
                           arguments: SteamCmd.arguments(appid: appid, account: steam.accountName),
                           settings: settings, environment: SteamCmd.environment,
                           workDirectory: SteamCmd.workDirectory)
    }

    private var installCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                Label("One-time setup", systemImage: "arrow.down.circle")
                    .font(.headline)
                Text("Fathom downloads games with Valve's own steamcmd, running inside the emulator. It is fetched once, about 5 MB, together with the 32-bit C library it needs.")
                    .font(.subheadline).foregroundStyle(.secondary)
                if case .failed(let message) = steamcmd.phase {
                    Text(message).font(.footnote).foregroundStyle(.orange)
                }
                Button("Set Up Downloader") { Task { await steamcmd.install() } }
                    .buttonStyle(.borderedProminent).tint(Theme.accent)
            }
        }
    }

    private var downloadCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    RemoteImage(url: GameInfo.art(appid, "header.jpg")) { Theme.surfaceRaised }
                        .frame(width: 92, height: 43)
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(name).font(.headline).lineLimit(1)
                        Text(steam.accountName.map { "As \($0)" } ?? "Anonymously (free content only)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                if let progress {
                    ProgressView(value: progress.fraction) {
                        Text("\(formatBytes(progress.done)) of \(formatBytes(progress.total))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else if succeeded {
                    Label("Installed", systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.subheadline.weight(.semibold))
                } else if session.state.isActive {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(session.outputText.contains("password") ? "Steam wants your password \u{2014} type it below." :
                                session.outputText.contains("Steam Guard") || session.outputText.contains("Two-factor") ? "Enter your Steam Guard code below." :
                                "Signing in to Steam\u{2026}")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                if session.state == .idle {
                    Button {
                        restarts = 0
                        start()
                    } label: {
                        Label(SteamCmd.isGameInstalled(appid) ? "Verify and Update" : "Download", systemImage: "arrow.down.to.line")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent).tint(Theme.accent).controlSize(.large)
                    Text("Files go to Fathom \u{203A} GuestRoot \u{203A} root \u{203A} games \u{203A} \(appid) in the Files app.")
                        .font(.caption2).foregroundStyle(.secondary)
                } else if !session.state.isActive {
                    Button(succeeded ? "Done" : "Try Again") {
                        if succeeded { dismiss() } else { session.reset() }
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
    }
}

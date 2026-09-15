// ShellView.swift -- a shell running inside the guest root filesystem.
//
// This is the first thing Fathom runs that it did not import. /bin/sh comes out of the
// Alpine root filesystem bundled with the app, and it is dynamically linked, so opening
// it exercises the whole chain at once: the ELF loader reads the interpreter busybox
// asks for, finds it inside the guest root, maps it, and enters it rather than the
// program -- and the interpreter then resolves busybox's own libraries from that same
// root, through the syscall layer.

import SwiftUI

struct ShellView: View {
    @EnvironmentObject private var settings: EmulatorSettings
    @EnvironmentObject private var jit: JITSupport
    @StateObject private var session = EmulatorSession()

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if jit.status != .enabled {
                    JITBanner()
                } else if session.state == .idle {
                    idle
                } else {
                    ConsoleView(session: session, prefersKeyboard: true)
                }
            }
            .padding()
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Linux Shell")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if session.state.isActive {
                    Button("Stop", role: .destructive) { session.stop() }
                } else if session.state != .idle {
                    Button("Restart") {
                        session.reset()
                        start()
                    }
                }
            }
        }
        .onAppear(perform: start)
    }

    private var idle: some View {
        VStack(spacing: 12) {
            Image(systemName: "terminal")
                .font(.system(size: 40))
                .foregroundStyle(Theme.accent)
            Text(GuestRootfs.isInstalled ? "Starting a shell…" : "The root filesystem is still being installed.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }

    private func start() {
        guard session.state == .idle, jit.status == .enabled else { return }
        // argv[0] decides which busybox applet this is, so it has to be the guest path.
        session.runInGuest(path: "/bin/sh", settings: settings)
    }
}

import SwiftUI

/// Steam, drawn.
///
/// The session runs `fathom-steam`, which brings up an X server inside the guest and then
/// the client on top of it. Everything on screen here is the X server's own framebuffer;
/// everything the user does goes back to it as an X event.
struct SteamView: View {
    @EnvironmentObject private var settings: EmulatorSettings
    @EnvironmentObject private var jit: JITSupport
    @StateObject private var session = EmulatorSession()
    @State private var showsLog = false

    var body: some View {
        Group {
            if jit.status != .enabled {
                ScrollView { JITBanner().padding() }
            } else {
                DisplayView(display: session.display,
                            onPoint: { point in session.input.move(to: point) },
                            onClick: { point, pressed in
                                session.input.move(to: point)
                                session.input.button(1, pressed: pressed)
                            })
                .ignoresSafeArea(edges: .bottom)
            }
        }
        .navigationTitle("Steam")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showsLog = true
                } label: {
                    Image(systemName: "text.alignleft")
                }
            }
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
        .sheet(isPresented: $showsLog) {
            NavigationStack {
                ConsoleView(session: session, prefersKeyboard: false)
                    .padding()
                    .navigationTitle("Steam output")
                    .navigationBarTitleDisplayMode(.inline)
            }
        }
        .onAppear(perform: start)
    }

    private func start() {
        guard session.state == .idle, jit.status == .enabled else { return }
        session.runGraphical(path: "/usr/local/bin/fathom-steam", settings: settings)
    }
}

import SwiftUI

@main
struct FathomApp: App {
    @StateObject private var library = ProgramLibrary()
    @StateObject private var settings = EmulatorSettings()
    @StateObject private var jit = JITSupport.shared
    @StateObject private var logStore = FathomLog.shared

    @Environment(\.scenePhase) private var scenePhase

    init() {
        FathomLog.shared.installCoreSink()
        log("Fathom starting on FEXCore \(String(cString: fathom_runtime_fex_revision()))")
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(library)
                .environmentObject(settings)
                .environmentObject(jit)
                .environmentObject(logStore)
                .tint(Theme.accent)
                .onAppear {
                    FathomLog.shared.setCoreLevel(verbose: settings.verboseLogging)
                }
        }
        .onChange(of: scenePhase) { _, phase in
            // Coming back from StikDebug is the moment JIT status changes, and there is
            // no notification for it -- the app is simply foregrounded again.
            if phase == .active {
                jit.refresh()
                library.refresh()
            }
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var settings: EmulatorSettings
    @EnvironmentObject private var jit: JITSupport
    @State private var selection: Tab = .library
    @State private var hasRequestedJIT = false

    enum Tab: Hashable {
        case library, settings
    }

    var body: some View {
        TabView(selection: $selection) {
            LibraryView()
                .tabItem { Label("Library", systemImage: "square.stack.3d.up") }
                .tag(Tab.library)

            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(Tab.settings)
        }
        .task {
            // Asking once, automatically, on the first launch where JIT is missing: the
            // app is useless without it, and making the user find the button first is
            // a worse first run than simply handing off to StikDebug.
            guard settings.autoRequestJIT, !hasRequestedJIT, jit.status == .unavailable else { return }
            hasRequestedJIT = true
            jit.requestJIT()
        }
    }
}

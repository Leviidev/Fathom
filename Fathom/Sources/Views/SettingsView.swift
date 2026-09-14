import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var settings: EmulatorSettings
    @EnvironmentObject private var library: ProgramLibrary
    @EnvironmentObject private var jit: JITSupport

    var body: some View {
        NavigationStack {
            Form {
                jitSection
                emulationSection
                memorySection
                diagnosticsSection
                storageSection
                aboutSection
            }
            .navigationTitle("Settings")
        }
    }

    // MARK: - JIT

    private var jitSection: some View {
        Section {
            HStack {
                Label("Status", systemImage: jit.status == .enabled ? "bolt.fill" : "bolt.slash")
                Spacer()
                Text(jit.status.summary)
                    .foregroundStyle(jit.status == .enabled ? .green : .orange)
            }

            if jit.status != .enabled {
                Button("Enable with StikDebug") {
                    jit.requestJIT()
                }
                if !jit.isStikDebugInstalled {
                    Text("StikDebug does not appear to be installed. Fathom needs it, or another debugger that implements the same protocol, to be allowed to generate code.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            Button("Re-check") { jit.refresh() }

            Toggle("Ask automatically at launch", isOn: $settings.autoRequestJIT)
        } header: {
            Text("JIT")
        } footer: {
            Text("Fathom translates x86-64 into ARM64 as it runs, which means writing code into memory and executing it. iOS only permits that while a debugger is attached, so this has to be granted once per launch.")
        }
    }

    // MARK: - Emulation

    private var emulationSection: some View {
        Section {
            Toggle("Multiblock compilation", isOn: $settings.multiblock)
            Toggle("TSO memory ordering", isOn: $settings.tsoEnabled)
            Toggle("Reduced-precision x87", isOn: $settings.reducedPrecisionX87)

            Picker("Max instructions per block", selection: $settings.maxInstPerBlock) {
                Text("Default").tag(0)
                Text("200").tag(200)
                Text("1000").tag(1000)
                Text("5000").tag(5000)
                Text("20000").tag(20000)
            }
        } header: {
            Text("Emulation")
        } footer: {
            Text("TSO emulation makes x86's stronger memory ordering hold on ARM. Turning it off is faster and is safe for a single-threaded program, but can break anything that relies on ordering between threads. Reduced-precision x87 trades exact 80-bit floating point for speed.")
        }
    }

    private var memorySection: some View {
        Section {
            Picker("Guest address space", selection: $settings.addressSpaceMB) {
                Text("512 MB").tag(512)
                Text("1 GB").tag(1024)
                Text("2 GB").tag(2048)
                Text("4 GB").tag(4096)
            }
            Picker("Guest stack", selection: $settings.stackMB) {
                Text("1 MB").tag(1)
                Text("8 MB").tag(8)
                Text("32 MB").tag(32)
                Text("64 MB").tag(64)
            }
            Button("Reset emulation defaults") {
                settings.resetEngineDefaults()
            }
        } header: {
            Text("Memory")
        } footer: {
            Text("The address space is reserved, not allocated: pages only count against the app's memory limit once the guest writes to them. Fathom requests the increased-memory-limit entitlement so a guest can use more than the usual ceiling.")
        }
    }

    // MARK: - Diagnostics

    private var diagnosticsSection: some View {
        Section {
            Toggle("Verbose logging", isOn: $settings.verboseLogging)
                .onChange(of: settings.verboseLogging) { _, value in
                    FathomLog.shared.setCoreLevel(verbose: value)
                }
            Toggle("Trace guest syscalls", isOn: $settings.traceSyscalls)

            NavigationLink {
                LogView()
            } label: {
                Label("Log", systemImage: "doc.text")
            }

            NavigationLink {
                DiagnosticsView()
            } label: {
                Label("Device probe", systemImage: "stethoscope")
            }
        } header: {
            Text("Diagnostics")
        } footer: {
            Text("Syscall tracing writes a line for every call the guest makes. It is genuinely useful when a program stops early for no obvious reason, and genuinely slow otherwise.")
        }
    }

    // MARK: - Storage

    private var storageSection: some View {
        Section {
            HStack {
                Text("Programs")
                Spacer()
                Text("\(library.programs.count) · \(formatBytes(library.totalBytes))")
                    .foregroundStyle(.secondary)
            }
            Button("Rescan Programs folder") {
                library.refresh()
            }
        } header: {
            Text("Storage")
        } footer: {
            Text("Programs live in Fathom's Documents folder and are visible in the Files app, so you can add or remove them there too. Rescan picks up anything added that way.")
        }
    }

    // MARK: - About

    private var aboutSection: some View {
        Section {
            DetailRow(label: "Version", value: "\(Bundle.main.shortVersion) (\(Bundle.main.buildVersion))")
            DetailRow(label: "CPU core", value: "FEXCore")
            DetailRow(label: "FEX build", value: String(cString: fathom_runtime_fex_revision()))
            DetailRow(label: "Host page size", value: "\(fathom_host_page_size()) bytes")
        } header: {
            Text("About")
        } footer: {
            Text("Fathom runs x86-64 Linux programs on ARM64 using FEXCore, the dynamic recompiler from the FEX-Emu project.")
        }
    }
}

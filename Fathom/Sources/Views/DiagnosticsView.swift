import SwiftUI

/// What this device actually permits, measured rather than assumed.
///
/// The interesting one is the lowest address that can be mapped: it is what decides
/// whether a non-PIE guest can ever be loaded, and it is a property of the device and
/// OS version rather than something that can be looked up.
struct DiagnosticsView: View {
    @State private var diagnostics: fathom_diagnostics?
    @State private var isProbing = false

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if let diagnostics {
                    results(diagnostics)
                } else {
                    Card {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Nothing measured yet")
                                .font(.subheadline.weight(.semibold))
                            Text("The probe asks the kernel for a JIT mapping, for the largest address-space reservation it will grant, and for the lowest address it will place a mapping at. Nothing is written and nothing persists.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Button {
                    runProbe()
                } label: {
                    Label(isProbing ? "Probing..." : "Run probe", systemImage: "stethoscope")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.accent)
                .controlSize(.large)
                .disabled(isProbing)
            }
            .padding()
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Device probe")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func results(_ diagnostics: fathom_diagnostics) -> some View {
        VStack(spacing: 16) {
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Code generation")
                        .font(.subheadline.weight(.semibold))
                    DetailRow(label: "Executable mapping", value: diagnostics.jit_available ? "granted" : "refused", mono: false)
                    DetailRow(label: "Debugger attached", value: diagnostics.debugger_attached ? "yes" : "no", mono: false)
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Address space")
                        .font(.subheadline.weight(.semibold))
                    DetailRow(label: "Largest reservation", value: formatBytes(diagnostics.largest_reservation))
                    DetailRow(label: "Lowest mappable", value: formatHex(diagnostics.lowest_mappable))
                    DetailRow(label: "Host page size", value: "\(fathom_host_page_size()) bytes")
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 8) {
                    Text("What this means")
                        .font(.subheadline.weight(.semibold))
                    Text(interpretation(diagnostics))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func interpretation(_ diagnostics: fathom_diagnostics) -> String {
        var notes: [String] = []
        if diagnostics.jit_available {
            notes.append("Fathom can generate code, so the emulator can run.")
        } else {
            notes.append("Fathom cannot make memory executable, so no program will run until JIT is enabled.")
        }

        if diagnostics.lowest_mappable == 0 {
            notes.append("No fixed mapping succeeded at any address tried, which is unusual — position-independent programs should still load, since they are placed wherever the kernel allows.")
        } else if diagnostics.lowest_mappable <= 0x400000 {
            notes.append("Mappings are permitted down to \(formatHex(diagnostics.lowest_mappable)), low enough for a classic non-PIE Linux binary to load at its link address.")
        } else {
            notes.append("The lowest address available is \(formatHex(diagnostics.lowest_mappable)), above the 0x400000 a non-PIE Linux binary is normally linked at. Position-independent programs are unaffected; non-PIE ones cannot be placed.")
        }
        return notes.joined(separator: " ")
    }

    private func runProbe() {
        isProbing = true
        DispatchQueue.global(qos: .userInitiated).async {
            var result = fathom_diagnostics()
            fathom_probe_device(&result)
            DispatchQueue.main.async {
                diagnostics = result
                isProbing = false
            }
        }
    }
}

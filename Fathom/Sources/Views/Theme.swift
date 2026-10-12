import SwiftUI

/// Fathom's visual vocabulary, in one place so every screen agrees.
///
/// Purple, on solid surfaces: no gradient washes and no glass. The surfaces are the
/// system's grouped backgrounds pushed a little toward violet, so the app reads as one
/// colour family without fighting the content -- game art carries the colour.
enum Theme {
    static let accent = Color(light: (0.45, 0.27, 0.86), dark: (0.66, 0.52, 1.00))
    static let accentSoft = accent.opacity(0.14)
    /// The screen behind everything.
    static let background = Color(light: (0.96, 0.95, 0.99), dark: (0.06, 0.05, 0.10))
    /// Cards, rows and tiles that sit on the background.
    static let surface = Color(light: (1.00, 1.00, 1.00), dark: (0.12, 0.10, 0.18))
    static let surfaceRaised = Color(light: (0.92, 0.90, 0.98), dark: (0.17, 0.14, 0.25))

    static let cardCorner: CGFloat = 14
    static let tileCorner: CGFloat = 12
    static let rowSpacing: CGFloat = 12
}

extension Color {
    /// A colour with its own light and dark values, resolved by the system as the scheme changes.
    init(light: (Double, Double, Double), dark: (Double, Double, Double)) {
        self.init(uiColor: UIColor { traits in
            let c = traits.userInterfaceStyle == .dark ? dark : light
            return UIColor(red: c.0, green: c.1, blue: c.2, alpha: 1)
        })
    }
}

/// Values that are technical rather than prose -- addresses, sizes, counts -- are set in
/// a monospaced face so digits line up between rows and never reflow as they change.
extension Font {
    static func technical(_ size: CGFloat = 13, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}

/// The app's one container shape. Grouped-background cards on a plain background read
/// more calmly than nested materials, and stay crisp in dark mode.
struct Card<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.cardCorner))
    }
}

/// A label and a value on one line. Used everywhere technical detail is listed.
struct DetailRow: View {
    let label: String
    let value: String
    var mono: Bool = true

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 16)
            Text(value)
                .font(mono ? .technical() : .body)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .font(.subheadline)
    }
}

/// A small status pill. `tint` carries the meaning, the text carries the detail.
struct StatusPill: View {
    let text: String
    let systemImage: String
    let tint: Color

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(tint.opacity(0.15), in: Capsule())
            .foregroundStyle(tint)
    }
}

/// Shown when a list has nothing in it yet. Deliberately explains the next action
/// rather than just stating the absence.
struct EmptyState: View {
    let title: String
    let message: String
    let systemImage: String
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: systemImage)
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(Theme.accent)
            Text(title)
                .font(.headline)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 320)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .padding(.top, 4)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity)
    }
}

extension ByteCountFormatter {
    static let fathom: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()
}

func formatBytes(_ bytes: UInt64) -> String {
    ByteCountFormatter.fathom.string(fromByteCount: Int64(bytes))
}

func formatHex(_ value: UInt64) -> String {
    value == 0 ? "0" : "0x" + String(value, radix: 16)
}

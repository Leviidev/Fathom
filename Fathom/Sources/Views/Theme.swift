import SwiftUI

/// Fathom's visual vocabulary, in one place so every screen agrees.
enum Theme {
    /// A deep teal, chosen to read as "depth" and to stay legible on both schemes.
    static let accent = Color(red: 0.11, green: 0.60, blue: 0.62)
    static let accentSoft = Color(red: 0.11, green: 0.60, blue: 0.62).opacity(0.14)

    static let cardCorner: CGFloat = 14
    static let rowSpacing: CGFloat = 12
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
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: Theme.cardCorner))
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

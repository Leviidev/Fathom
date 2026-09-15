import SwiftUI
import UIKit

/// Draws the terminal grid, and the controls a guest program needs to be played with.
struct TerminalView: View {
    let terminal: TerminalEmulator
    let onKey: (String) -> Void

    /// A shell wants the full keyboard; the games want the compact keypad, which does not
    /// cover half the screen. Either can be switched to once running.
    var prefersKeyboard: Bool = false

    @State private var usingKeyboard: Bool?
    @State private var controlHeld = false

    private var keyboardShown: Bool { usingKeyboard ?? prefersKeyboard }

    var body: some View {
        VStack(spacing: 14) {
            screen
            if keyboardShown {
                SpecialKeysRow(onKey: send, controlHeld: $controlHeld)
                // Zero height: it exists to hold the keyboard and catch keys, not to be
                // seen. The system keyboard it raises is the visible part.
                TerminalKeyboard(isActive: true, onKey: send)
                    .frame(height: 0)
            } else {
                KeypadView(onKey: onKey)
            }
            Button {
                usingKeyboard = !keyboardShown
            } label: {
                Label(keyboardShown ? "Use keypad" : "Use keyboard",
                      systemImage: keyboardShown ? "gamecontroller" : "keyboard")
                    .font(.footnote)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
        }
    }

    /// Applies the control modifier, which a phone keyboard has no key for. Ctrl+A is
    /// simply 'A' with the top bits cleared, which is also why Ctrl+[ is escape.
    private func send(_ key: String) {
        if controlHeld, key.count == 1, let scalar = key.unicodeScalars.first,
           scalar.value >= 0x3f, scalar.value <= 0x7f {
            controlHeld = false
            onKey(String(UnicodeScalar(scalar.value & 0x1f)!))
            return
        }
        onKey(key)
    }

    private var screen: some View {
        GeometryReader { geometry in
            let metrics = Self.metrics(forWidth: geometry.size.width - 20, columns: terminal.columns)

            Text(screenText)
                .font(.system(size: metrics.pointSize, design: .monospaced))
                .lineSpacing(0)
                // Every one of these matters. A terminal row is a fixed number of cells
                // and must occupy exactly one line: allowed to wrap, an 80-column row
                // becomes two visual lines, everything below it shifts, and the grid
                // turns into the scrambled mess this replaced.
                .lineLimit(terminal.rows)
                .fixedSize(horizontal: true, vertical: true)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .padding(10)
                .background(Color(white: 0.08), in: RoundedRectangle(cornerRadius: 10))
                .clipped()
        }
        .frame(height: Self.height(forWidth: screenWidth, columns: terminal.columns, rows: terminal.rows))
    }

    /// Width available to the terminal. Read once here rather than threaded through the
    /// GeometryReader, because the height has to be known before layout to avoid the
    /// reader collapsing to zero.
    private var screenWidth: CGFloat {
        UIScreen.main.bounds.width - 32
    }

    /// The whole screen as one attributed string, rows separated by newlines.
    ///
    /// One Text rather than one per row: 24 separate views each measuring themselves
    /// independently is both slower and the reason rows could drift out of alignment
    /// with each other.
    private var screenText: AttributedString {
        var result = AttributedString()
        for row in 0..<terminal.rows {
            result.append(line(row))
            if row < terminal.rows - 1 {
                result.append(AttributedString("\n"))
            }
        }
        return result
    }

    /// Measures the real advance width of the monospaced face instead of assuming a
    /// ratio. The assumed 0.6 em was close enough to look right and wrong enough to make
    /// rows overflow and wrap.
    private static func metrics(forWidth width: CGFloat, columns: Int) -> (pointSize: CGFloat, advance: CGFloat) {
        let reference: CGFloat = 20
        let font = UIFont.monospacedSystemFont(ofSize: reference, weight: .regular)
        let advance = ("0" as NSString).size(withAttributes: [.font: font]).width
        guard advance > 0, width > 0 else { return (8, 5) }

        let pointSize = max(4, floor((width / CGFloat(columns)) / advance * reference * 2) / 2)
        return (pointSize, advance / reference * pointSize)
    }

    private static func height(forWidth width: CGFloat, columns: Int, rows: Int) -> CGFloat {
        let metrics = metrics(forWidth: width - 20, columns: columns)
        let font = UIFont.monospacedSystemFont(ofSize: metrics.pointSize, weight: .regular)
        return ceil(font.lineHeight * CGFloat(rows)) + 20
    }

    /// One row, built as runs of identical styling so a line is a handful of attributed
    /// spans rather than one per cell.
    private func line(_ row: Int) -> AttributedString {
        var result = AttributedString()
        var run = ""
        var style: TerminalEmulator.Cell?

        func flush() {
            guard !run.isEmpty, let style else { return }
            var piece = AttributedString(run)
            piece.foregroundColor = style.foregroundColour
            if let background = style.backgroundColour {
                piece.backgroundColor = background
            }
            if style.bold {
                piece.inlinePresentationIntent = .stronglyEmphasized
            }
            result.append(piece)
            run = ""
        }

        for column in 0..<terminal.columns {
            let cell = terminal.cell(row: row, column: column)
            if style == nil || cell.colour != style!.colour || cell.background != style!.background
                || cell.bold != style!.bold || cell.reverse != style!.reverse {
                flush()
                style = cell
            }
            run.append(cell.character)
        }
        flush()
        return result
    }
}

/// The on-screen keys. Arrows plus the handful of keys a terminal game actually reads.
struct KeypadView: View {
    let onKey: (String) -> Void

    // What a terminal sends for each key. Arrows are escape sequences, not characters,
    // which is why a program can tell them apart from typed letters at all.
    private enum Key {
        static let up = "\u{1b}[A"
        static let down = "\u{1b}[B"
        static let right = "\u{1b}[C"
        static let left = "\u{1b}[D"
        static let enter = "\r"
        static let space = " "
        static let escape = "\u{1b}"
    }

    var body: some View {
        HStack(alignment: .center, spacing: 28) {
            dpad
            Spacer(minLength: 0)
            actions
        }
        .padding(.horizontal, 4)
    }

    private var dpad: some View {
        VStack(spacing: 6) {
            key("chevron.up", send: Key.up)
            HStack(spacing: 6) {
                key("chevron.left", send: Key.left)
                Color.clear.frame(width: 52, height: 52)
                key("chevron.right", send: Key.right)
            }
            key("chevron.down", send: Key.down)
        }
    }

    private var actions: some View {
        VStack(spacing: 10) {
            textKey("Enter", send: Key.enter)
            HStack(spacing: 10) {
                textKey("Space", send: Key.space)
                textKey("Esc", send: Key.escape)
            }
            HStack(spacing: 10) {
                textKey("Q", send: "q")
                textKey("R", send: "r")
            }
        }
    }

    private func key(_ symbol: String, send: String) -> some View {
        Button {
            onKey(send)
        } label: {
            Image(systemName: symbol)
                .font(.system(size: 20, weight: .semibold))
                .frame(width: 52, height: 52)
                .background(Theme.accentSoft, in: RoundedRectangle(cornerRadius: 12))
                .foregroundStyle(Theme.accent)
        }
        .buttonStyle(.plain)
        // Repeats while held, so a game's cursor moves the way it would on a keyboard.
        .onLongPressGesture(minimumDuration: 0.3, perform: {}, onPressingChanged: { pressing in
            if pressing { onKey(send) }
        })
    }

    private func textKey(_ title: String, send: String) -> some View {
        Button {
            onKey(send)
        } label: {
            Text(title)
                .font(.system(size: 14, weight: .semibold, design: .rounded))
                .frame(minWidth: 62, minHeight: 40)
                .background(Color(.secondarySystemFill), in: RoundedRectangle(cornerRadius: 10))
                .foregroundStyle(.primary)
        }
        .buttonStyle(.plain)
    }
}

import SwiftUI

/// Draws the terminal grid, and the controls a guest program needs to be played with.
struct TerminalView: View {
    let terminal: TerminalEmulator
    let onKey: (String) -> Void

    var body: some View {
        VStack(spacing: 14) {
            screen
            KeypadView(onKey: onKey)
        }
    }

    private var screen: some View {
        GeometryReader { geometry in
            // A monospaced face advances about 0.6 em per character, so the point size
            // that makes exactly `columns` fit follows directly from the width. The grid
            // is sized to the terminal rather than the terminal to the screen, because a
            // program that asked for 80 columns has laid itself out for 80.
            let pointSize = max(5, (geometry.size.width - 16) / (CGFloat(terminal.columns) * 0.6))

            VStack(alignment: .leading, spacing: 0) {
                ForEach(0..<terminal.rows, id: \.self) { row in
                    Text(line(row))
                        .font(.system(size: pointSize, weight: .regular, design: .monospaced))
                        .lineSpacing(0)
                        .fixedSize()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(8)
            .background(Color(white: 0.08), in: RoundedRectangle(cornerRadius: 10))
        }
        .aspectRatio(CGFloat(terminal.columns) * 0.6 / CGFloat(terminal.rows) * 0.92, contentMode: .fit)
    }

    /// One row, built as a single attributed string so each line is one Text rather than
    /// one per cell -- 80 views a row, 24 rows, ten times a second is not affordable.
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

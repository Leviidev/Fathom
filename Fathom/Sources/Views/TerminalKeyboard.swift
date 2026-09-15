// TerminalKeyboard.swift -- typing into the guest.
//
// The keypad next door was built for the two games: four arrows, Enter, Space. A shell
// needs letters, and there is no sense drawing eighty keys by hand when iOS already has
// a keyboard.
//
// This is not a text field. A text field would want to own a string, autocorrect it, and
// hand back edits; a terminal wants individual keystrokes the moment they happen, and
// sends them to a program that is keeping its own idea of the line. UIKeyInput is the
// small protocol underneath UIKit's text machinery that gives exactly that: insertText
// and deleteBackward, nothing else. A hardware keyboard, if one is attached, arrives
// through the same path.

import SwiftUI
import UIKit

/// An invisible view that holds the keyboard and reports keystrokes.
final class KeyInputView: UIView, UIKeyInput {
    var onKey: ((String) -> Void)?

    override var canBecomeFirstResponder: Bool { true }

    // Terminals want the raw key, so every helpful thing iOS would otherwise do to the
    // text on its way through has to be turned off.
    var keyboardType: UIKeyboardType = .asciiCapable
    var autocorrectionType: UITextAutocorrectionType = .no
    var autocapitalizationType: UITextAutocapitalizationType = .none
    var spellCheckingType: UITextSpellCheckingType = .no
    var smartQuotesType: UITextSmartQuotesType = .no
    var smartDashesType: UITextSmartDashesType = .no
    var smartInsertDeleteType: UITextSmartInsertDeleteType = .no
    var returnKeyType: UIReturnKeyType = .default
    var enablesReturnKeyAutomatically: Bool = false
    var isSecureTextEntry: Bool = false
    var textContentType: UITextContentType!

    /// Always true: the delete key must keep firing even though nothing is stored here,
    /// because the line being edited lives in the guest, not in this view.
    var hasText: Bool { true }

    func insertText(_ text: String) {
        // Return arrives as a newline; a terminal sends carriage return.
        onKey?(text == "\n" ? "\r" : text)
    }

    func deleteBackward() {
        // DEL rather than backspace: it is what a terminal sends, and what readline and
        // busybox's line editor expect to see.
        onKey?("\u{7f}")
    }
}

struct TerminalKeyboard: UIViewRepresentable {
    let isActive: Bool
    let onKey: (String) -> Void

    func makeUIView(context: Context) -> KeyInputView {
        let view = KeyInputView()
        view.onKey = onKey
        view.isOpaque = false
        view.backgroundColor = .clear
        return view
    }

    func updateUIView(_ view: KeyInputView, context: Context) {
        view.onKey = onKey
        if isActive, !view.isFirstResponder {
            view.becomeFirstResponder()
        } else if !isActive, view.isFirstResponder {
            view.resignFirstResponder()
        }
    }
}

/// The keys a terminal needs that a phone keyboard does not have.
struct SpecialKeysRow: View {
    let onKey: (String) -> Void
    @Binding var controlHeld: Bool

    private enum Key {
        static let up = "\u{1b}[A"
        static let down = "\u{1b}[B"
        static let right = "\u{1b}[C"
        static let left = "\u{1b}[D"
        static let escape = "\u{1b}"
        static let tab = "\t"
    }

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                cap("esc") { onKey(Key.escape) }
                cap("tab") { onKey(Key.tab) }
                Toggle("ctrl", isOn: $controlHeld)
                    .toggleStyle(.button)
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                cap("^C") { onKey("\u{03}") }
                cap("^D") { onKey("\u{04}") }
                Divider().frame(height: 22)
                cap("←") { onKey(Key.left) }
                cap("↓") { onKey(Key.down) }
                cap("↑") { onKey(Key.up) }
                cap("→") { onKey(Key.right) }
            }
            .padding(.horizontal, 4)
        }
    }

    private func cap(_ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .frame(minWidth: 34)
                .padding(.vertical, 7)
                .padding(.horizontal, 6)
                .background(Color(.tertiarySystemFill), in: RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .foregroundStyle(.primary)
    }
}

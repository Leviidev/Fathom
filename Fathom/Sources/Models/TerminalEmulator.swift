import SwiftUI

/// A small VT100/ANSI terminal.
///
/// A full-screen terminal program does not print a transcript -- it draws, by moving the
/// cursor around and overwriting cells. Fed to a scrolling text view, its escape
/// sequences show up as garbage. So the bytes the guest writes are interpreted here into
/// a character grid, which is what actually gets drawn.
///
/// The subset implemented is the one such programs really use: cursor movement and
/// positioning, erasing, colours, and hiding the cursor. Anything unrecognised is
/// swallowed rather than printed, because a stray escape sequence on screen is worse
/// than a missing effect.
struct TerminalEmulator {
    struct Cell: Equatable {
        var character: Character = " "
        var colour: UInt8 = 7      // ANSI 0-7, plus 8-15 for the bright variants.
        var background: UInt8 = 0
        var bold = false
        /// Reverse video. How a full-screen program marks a selection when it has no
        /// cursor to move -- tic-tac-toe uses it for the square you are on, so without
        /// this there is no way to tell where you are.
        var reverse = false
    }

    private(set) var columns: Int
    private(set) var rows: Int
    private(set) var cells: [Cell]
    private(set) var cursorRow = 0
    private(set) var cursorColumn = 0
    private(set) var cursorVisible = true

    /// True once the guest has emitted any escape sequence, which is the signal that it
    /// is drawing a screen rather than printing lines.
    private(set) var isFullScreen = false

    private var current = Cell()
    private var savedRow = 0
    private var savedColumn = 0

    // Escape-sequence parser state.
    private enum State {
        case text
        case escape
        case csi
    }
    private var state: State = .text
    private var parameters = ""

    init(columns: Int = 80, rows: Int = 24) {
        self.columns = columns
        self.rows = rows
        cells = Array(repeating: Cell(), count: columns * rows)
    }

    mutating func reset() {
        cells = Array(repeating: Cell(), count: columns * rows)
        cursorRow = 0
        cursorColumn = 0
        cursorVisible = true
        isFullScreen = false
        current = Cell()
        state = .text
        parameters = ""
    }

    func cell(row: Int, column: Int) -> Cell {
        cells[row * columns + column]
    }

    // MARK: - Feeding

    mutating func feed(_ text: String) {
        for character in text {
            feed(character)
        }
    }

    private mutating func feed(_ character: Character) {
        switch state {
        case .text:
            handleText(character)
        case .escape:
            if character == "[" {
                state = .csi
                parameters = ""
            } else {
                // Escapes other than CSI (charset selection, keypad modes) are accepted
                // and ignored; none of them change what is on screen.
                state = .text
            }
        case .csi:
            if character.isLetter {
                applyCSI(command: character, parameters: parameters)
                state = .text
                parameters = ""
            } else {
                parameters.append(character)
            }
        }
    }

    private mutating func handleText(_ character: Character) {
        switch character {
        case "\u{1b}":
            state = .escape
            isFullScreen = true
        case "\n":
            newline()
        case "\r":
            cursorColumn = 0
        case "\u{8}":
            cursorColumn = max(0, cursorColumn - 1)
        case "\t":
            cursorColumn = min(columns - 1, (cursorColumn / 8 + 1) * 8)
        case "\u{7}":
            break // Bell.
        default:
            put(character)
        }
    }

    private mutating func put(_ character: Character) {
        if cursorColumn >= columns {
            cursorColumn = 0
            newline()
        }
        var cell = current
        cell.character = character
        cells[cursorRow * columns + cursorColumn] = cell
        cursorColumn += 1
    }

    private mutating func newline() {
        cursorRow += 1
        if cursorRow >= rows {
            scrollUp()
            cursorRow = rows - 1
        }
    }

    private mutating func scrollUp() {
        cells.removeFirst(columns)
        cells.append(contentsOf: Array(repeating: Cell(), count: columns))
    }

    // MARK: - Control sequences

    private mutating func applyCSI(command: Character, parameters: String) {
        // "?" introduces the private modes, of which only cursor visibility matters here.
        if parameters.hasPrefix("?") {
            let mode = String(parameters.dropFirst())
            if mode == "25" {
                cursorVisible = command == "h"
            }
            return
        }

        let values = parameters.split(separator: ";").map { Int($0) ?? 0 }
        func value(_ index: Int, _ fallback: Int) -> Int {
            index < values.count && values[index] != 0 ? values[index] : fallback
        }

        switch command {
        case "H", "f":
            // Rows and columns are 1-based in the sequence and 0-based here.
            cursorRow = min(rows - 1, max(0, value(0, 1) - 1))
            cursorColumn = min(columns - 1, max(0, value(1, 1) - 1))
        case "A":
            cursorRow = max(0, cursorRow - value(0, 1))
        case "B":
            cursorRow = min(rows - 1, cursorRow + value(0, 1))
        case "C":
            cursorColumn = min(columns - 1, cursorColumn + value(0, 1))
        case "D":
            cursorColumn = max(0, cursorColumn - value(0, 1))
        case "G":
            cursorColumn = min(columns - 1, max(0, value(0, 1) - 1))
        case "J":
            eraseDisplay(mode: values.first ?? 0)
        case "K":
            eraseLine(mode: values.first ?? 0)
        case "m":
            applyGraphics(values.isEmpty ? [0] : values)
        case "s":
            savedRow = cursorRow
            savedColumn = cursorColumn
        case "u":
            cursorRow = savedRow
            cursorColumn = savedColumn
        default:
            break
        }
    }

    private mutating func eraseDisplay(mode: Int) {
        let position = cursorRow * columns + cursorColumn
        switch mode {
        case 0:
            for index in position..<cells.count { cells[index] = Cell(character: " ", colour: current.colour, background: current.background) }
        case 1:
            for index in 0...min(position, cells.count - 1) { cells[index] = Cell(character: " ", colour: current.colour, background: current.background) }
        default:
            cells = Array(repeating: Cell(character: " ", colour: current.colour, background: current.background),
                          count: columns * rows)
        }
    }

    private mutating func eraseLine(mode: Int) {
        let start = cursorRow * columns
        switch mode {
        case 0:
            for column in cursorColumn..<columns { cells[start + column] = Cell(character: " ", colour: current.colour, background: current.background) }
        case 1:
            for column in 0...cursorColumn { cells[start + column] = Cell(character: " ", colour: current.colour, background: current.background) }
        default:
            for column in 0..<columns { cells[start + column] = Cell(character: " ", colour: current.colour, background: current.background) }
        }
    }

    private mutating func applyGraphics(_ values: [Int]) {
        for value in values {
            switch value {
            case 0:
                current = Cell()
            case 1:
                current.bold = true
            case 7:
                current.reverse = true
            case 22:
                current.bold = false
            case 27:
                current.reverse = false
            case 30...37:
                current.colour = UInt8(value - 30)
            case 39:
                current.colour = 7
            case 40...47:
                current.background = UInt8(value - 40)
            case 49:
                current.background = 0
            case 90...97:
                current.colour = UInt8(value - 90 + 8)
            case 100...107:
                current.background = UInt8(value - 100 + 8)
            default:
                break
            }
        }
    }
}

extension TerminalEmulator.Cell {
    /// The classic 16-colour palette, adjusted so it stays readable on both schemes
    /// rather than matching any particular terminal exactly.
    static let palette: [Color] = [
        Color(white: 0.20),                                   // black
        Color(red: 0.80, green: 0.25, blue: 0.25),            // red
        Color(red: 0.25, green: 0.70, blue: 0.35),            // green
        Color(red: 0.80, green: 0.65, blue: 0.20),            // yellow
        Color(red: 0.30, green: 0.55, blue: 0.85),            // blue
        Color(red: 0.70, green: 0.40, blue: 0.80),            // magenta
        Color(red: 0.20, green: 0.68, blue: 0.70),            // cyan
        Color(white: 0.85),                                   // white
        Color(white: 0.45),                                   // bright black
        Color(red: 0.95, green: 0.42, blue: 0.40),
        Color(red: 0.40, green: 0.85, blue: 0.50),
        Color(red: 0.95, green: 0.80, blue: 0.35),
        Color(red: 0.45, green: 0.70, blue: 0.95),
        Color(red: 0.85, green: 0.55, blue: 0.95),
        Color(red: 0.35, green: 0.85, blue: 0.88),
        Color(white: 1.0),
    ]

    var foregroundColour: Color {
        reverse ? Self.palette[Int(background) % 16] : Self.palette[Int(colour) % 16]
    }

    var backgroundColour: Color? {
        if reverse {
            return Self.palette[Int(colour) % 16]
        }
        return background == 0 ? nil : Self.palette[Int(background) % 16]
    }
}

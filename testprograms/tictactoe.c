// tictactoe -- arrow keys to move, Enter to place, against a bot that cannot be beaten.
//
// Written for Fathom: it puts the terminal in raw mode (which is what tells Fathom to
// show its keypad), draws with ANSI escape sequences, and reads arrow keys as the
// three-byte sequences a terminal sends.
//
// The opponent plays full minimax over the game tree. Tic-tac-toe is small enough that
// this is exact rather than heuristic, so perfect play from both sides always draws --
// the most you can get is a draw, and the bot punishes any mistake immediately.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define EMPTY 0
#define HUMAN 1   // X
#define BOT   2   // O

static struct termios saved_termios;

static void raw_mode(void) {
    struct termios raw;
    tcgetattr(STDIN_FILENO, &saved_termios);
    raw = saved_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

static void restore_mode(void) {
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    printf("\x1b[?25h");  // Show the cursor again.
    fflush(stdout);
}

// --- Game rules ---------------------------------------------------------------------

static const int lines[8][3] = {
    {0,1,2},{3,4,5},{6,7,8},   // rows
    {0,3,6},{1,4,7},{2,5,8},   // columns
    {0,4,8},{2,4,6},           // diagonals
};

static int winner(const int *board) {
    for (int i = 0; i < 8; i++) {
        const int a = board[lines[i][0]], b = board[lines[i][1]], c = board[lines[i][2]];
        if (a != EMPTY && a == b && b == c) {
            return a;
        }
    }
    return EMPTY;
}

static int full(const int *board) {
    for (int i = 0; i < 9; i++) {
        if (board[i] == EMPTY) return 0;
    }
    return 1;
}

/// Score from the bot's point of view. Depth is subtracted so it prefers winning sooner
/// and losing later, which is what makes it look like it is actually trying.
static int minimax(int *board, int player, int depth) {
    const int w = winner(board);
    if (w == BOT) return 10 - depth;
    if (w == HUMAN) return depth - 10;
    if (full(board)) return 0;

    int best = player == BOT ? -1000 : 1000;
    for (int i = 0; i < 9; i++) {
        if (board[i] != EMPTY) continue;
        board[i] = player;
        const int score = minimax(board, player == BOT ? HUMAN : BOT, depth + 1);
        board[i] = EMPTY;
        if (player == BOT) {
            if (score > best) best = score;
        } else {
            if (score < best) best = score;
        }
    }
    return best;
}

static int best_move(int *board) {
    int best_score = -1000;
    int move = -1;
    for (int i = 0; i < 9; i++) {
        if (board[i] != EMPTY) continue;
        board[i] = BOT;
        const int score = minimax(board, HUMAN, 0);
        board[i] = EMPTY;
        if (score > best_score) {
            best_score = score;
            move = i;
        }
    }
    return move;
}

// --- Drawing ------------------------------------------------------------------------

static void draw(const int *board, int cursor, const char *message, int wins, int losses, int draws) {
    printf("\x1b[2J\x1b[H\x1b[?25l");   // Clear, home, hide cursor.

    printf("\x1b[1m  TIC TAC TOE\x1b[0m   \x1b[90mrunning on Fathom\x1b[0m\n");
    printf("  \x1b[90m------------------------------------\x1b[0m\n\n");

    for (int row = 0; row < 3; row++) {
        for (int line = 0; line < 3; line++) {
            printf("      ");
            for (int column = 0; column < 3; column++) {
                const int index = row * 3 + column;
                const int value = board[index];
                const int selected = index == cursor;

                // Each cell is three lines tall so the board reads as a board rather
                // than as three characters in a row.
                const char *glyph = "   ";
                if (line == 1) {
                    glyph = value == HUMAN ? " X " : value == BOT ? " O " : "   ";
                }

                if (selected) {
                    printf("\x1b[7m");   // Reverse video marks where you are.
                }
                if (value == HUMAN) {
                    printf("\x1b[36m");
                } else if (value == BOT) {
                    printf("\x1b[33m");
                }
                printf("%s", glyph);
                printf("\x1b[0m");

                if (column < 2) printf("\x1b[90m|\x1b[0m");
            }
            printf("\n");
        }
        if (row < 2) {
            printf("      \x1b[90m-----------\x1b[0m\n");
        }
    }

    printf("\n  %s\n", message);
    printf("\n  \x1b[90mYou %d   Bot %d   Drawn %d\x1b[0m\n", wins, losses, draws);
    printf("\n  \x1b[90marrows move   Enter places   R restarts   Q quits\x1b[0m\n");
    fflush(stdout);
}

// --- Input --------------------------------------------------------------------------

enum { KEY_UP = 1000, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_ENTER, KEY_OTHER };

static int read_key(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return KEY_OTHER;

    if (c == '\x1b') {
        char sequence[2];
        if (read(STDIN_FILENO, &sequence[0], 1) != 1) return KEY_OTHER;
        if (read(STDIN_FILENO, &sequence[1], 1) != 1) return KEY_OTHER;
        if (sequence[0] == '[') {
            switch (sequence[1]) {
            case 'A': return KEY_UP;
            case 'B': return KEY_DOWN;
            case 'C': return KEY_RIGHT;
            case 'D': return KEY_LEFT;
            }
        }
        return KEY_OTHER;
    }
    if (c == '\r' || c == '\n' || c == ' ') return KEY_ENTER;
    return (unsigned char)c;
}

int main(void) {
    int board[9];
    int cursor = 4;
    int wins = 0, losses = 0, draws = 0;
    char message[128];

    raw_mode();
    memset(board, 0, sizeof(board));
    strcpy(message, "Your move. You are \x1b[36mX\x1b[0m.");

    for (;;) {
        draw(board, cursor, message, wins, losses, draws);

        const int key = read_key();
        if (key == 'q' || key == 'Q') {
            break;
        }
        if (key == 'r' || key == 'R') {
            memset(board, 0, sizeof(board));
            cursor = 4;
            strcpy(message, "New game. Your move.");
            continue;
        }

        switch (key) {
        case KEY_UP:    cursor = (cursor + 6) % 9; continue;
        case KEY_DOWN:  cursor = (cursor + 3) % 9; continue;
        case KEY_LEFT:  cursor = (cursor / 3) * 3 + (cursor % 3 + 2) % 3; continue;
        case KEY_RIGHT: cursor = (cursor / 3) * 3 + (cursor % 3 + 1) % 3; continue;
        case KEY_ENTER: break;
        default: continue;
        }

        if (winner(board) != EMPTY || full(board)) {
            strcpy(message, "Game over. Press R for another.");
            continue;
        }
        if (board[cursor] != EMPTY) {
            strcpy(message, "That square is taken.");
            continue;
        }

        board[cursor] = HUMAN;

        if (winner(board) == HUMAN) {
            wins++;
            strcpy(message, "\x1b[32mYou win.\x1b[0m Press R to play again.");
            continue;
        }
        if (full(board)) {
            draws++;
            strcpy(message, "A draw. Press R to play again.");
            continue;
        }

        const int reply = best_move(board);
        if (reply >= 0) {
            board[reply] = BOT;
        }

        if (winner(board) == BOT) {
            losses++;
            strcpy(message, "\x1b[31mThe bot wins.\x1b[0m Press R to play again.");
        } else if (full(board)) {
            draws++;
            strcpy(message, "A draw -- the best anyone gets. Press R.");
        } else {
            strcpy(message, "Your move.");
        }
    }

    restore_mode();
    printf("\x1b[2J\x1b[H");
    printf("Final: you %d, bot %d, drawn %d.\n", wins, losses, draws);
    return 0;
}

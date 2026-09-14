// 2048 -- arrows slide the board, matching tiles merge.
//
// Included alongside tictactoe because it is the purest arrow-key game there is: every
// input is a direction, there is no cursor, and the whole board changes at once. Good
// for seeing whether Fathom's input path and screen drawing hold up under something
// that redraws constantly.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SIZE 4

static struct termios saved_termios;
static unsigned long long rng_state;

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
    printf("\x1b[?25h");
    fflush(stdout);
}

// A small xorshift, so the game does not depend on the quality of the guest's rand().
static unsigned long long next_random(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void spawn(int board[SIZE][SIZE]) {
    int empty[SIZE * SIZE][2];
    int count = 0;
    for (int r = 0; r < SIZE; r++) {
        for (int c = 0; c < SIZE; c++) {
            if (board[r][c] == 0) {
                empty[count][0] = r;
                empty[count][1] = c;
                count++;
            }
        }
    }
    if (count == 0) return;
    const int pick = (int)(next_random() % (unsigned long long)count);
    board[empty[pick][0]][empty[pick][1]] = (next_random() % 10 == 0) ? 4 : 2;
}

/// Slides and merges one row toward index 0. Returns non-zero if anything moved, and
/// adds whatever was merged to *score.
static int slide_row(int *row, int *score) {
    int changed = 0;
    int packed[SIZE];
    int count = 0;

    for (int i = 0; i < SIZE; i++) {
        if (row[i] != 0) packed[count++] = row[i];
    }
    for (int i = count; i < SIZE; i++) packed[i] = 0;

    for (int i = 0; i + 1 < SIZE; i++) {
        if (packed[i] != 0 && packed[i] == packed[i + 1]) {
            packed[i] *= 2;
            *score += packed[i];
            for (int j = i + 1; j + 1 < SIZE; j++) packed[j] = packed[j + 1];
            packed[SIZE - 1] = 0;
        }
    }
    for (int i = 0; i < SIZE; i++) {
        if (row[i] != packed[i]) changed = 1;
        row[i] = packed[i];
    }
    return changed;
}

// Each direction is the same slide with the board read in a different order, which is
// shorter and far less error-prone than four near-identical loops.
static int move_board(int board[SIZE][SIZE], int direction, int *score) {
    int changed = 0;
    int row[SIZE];

    for (int line = 0; line < SIZE; line++) {
        for (int i = 0; i < SIZE; i++) {
            switch (direction) {
            case 0: row[i] = board[line][i]; break;              // left
            case 1: row[i] = board[line][SIZE - 1 - i]; break;   // right
            case 2: row[i] = board[i][line]; break;              // up
            default: row[i] = board[SIZE - 1 - i][line]; break;  // down
            }
        }
        changed |= slide_row(row, score);
        for (int i = 0; i < SIZE; i++) {
            switch (direction) {
            case 0: board[line][i] = row[i]; break;
            case 1: board[line][SIZE - 1 - i] = row[i]; break;
            case 2: board[i][line] = row[i]; break;
            default: board[SIZE - 1 - i][line] = row[i]; break;
            }
        }
    }
    return changed;
}

static int can_move(int board[SIZE][SIZE]) {
    for (int r = 0; r < SIZE; r++) {
        for (int c = 0; c < SIZE; c++) {
            if (board[r][c] == 0) return 1;
            if (c + 1 < SIZE && board[r][c] == board[r][c + 1]) return 1;
            if (r + 1 < SIZE && board[r][c] == board[r + 1][c]) return 1;
        }
    }
    return 0;
}

static int colour_for(int value) {
    switch (value) {
    case 2: return 37;
    case 4: return 36;
    case 8: return 32;
    case 16: return 33;
    case 32: return 35;
    case 64: return 31;
    case 128: return 94;
    case 256: return 96;
    case 512: return 92;
    case 1024: return 93;
    default: return 91;
    }
}

static void draw(int board[SIZE][SIZE], int score, int best, const char *message) {
    printf("\x1b[2J\x1b[H\x1b[?25l");
    printf("\x1b[1m  2048\x1b[0m   \x1b[90mrunning on Fathom\x1b[0m\n");
    printf("  \x1b[90m----------------------------------\x1b[0m\n\n");
    printf("      Score \x1b[1m%-8d\x1b[0m Best \x1b[1m%d\x1b[0m\n\n", score, best);

    for (int r = 0; r < SIZE; r++) {
        printf("      \x1b[90m+------+------+------+------+\x1b[0m\n");
        printf("      \x1b[90m|\x1b[0m");
        for (int c = 0; c < SIZE; c++) {
            if (board[r][c] == 0) {
                printf("      ");
            } else {
                printf("\x1b[%dm\x1b[1m%5d \x1b[0m", colour_for(board[r][c]), board[r][c]);
            }
            printf("\x1b[90m|\x1b[0m");
        }
        printf("\n");
    }
    printf("      \x1b[90m+------+------+------+------+\x1b[0m\n");

    printf("\n  %s\n", message);
    printf("\n  \x1b[90marrows slide   R restarts   Q quits\x1b[0m\n");
    fflush(stdout);
}

enum { KEY_UP = 1000, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_OTHER };

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
    return (unsigned char)c;
}

int main(void) {
    int board[SIZE][SIZE];
    int score = 0, best = 0;
    char message[128];

    rng_state = (unsigned long long)time(NULL) ^ 0x9E3779B97F4A7C15ULL;
    if (rng_state == 0) rng_state = 1;

    raw_mode();
    memset(board, 0, sizeof(board));
    spawn(board);
    spawn(board);
    strcpy(message, "Slide with the arrow keys.");

    for (;;) {
        draw(board, score, best, message);

        const int key = read_key();
        if (key == 'q' || key == 'Q') break;
        if (key == 'r' || key == 'R') {
            memset(board, 0, sizeof(board));
            score = 0;
            spawn(board);
            spawn(board);
            strcpy(message, "New game.");
            continue;
        }

        int direction;
        switch (key) {
        case KEY_LEFT:  direction = 0; break;
        case KEY_RIGHT: direction = 1; break;
        case KEY_UP:    direction = 2; break;
        case KEY_DOWN:  direction = 3; break;
        default: continue;
        }

        if (move_board(board, direction, &score)) {
            spawn(board);
            if (score > best) best = score;
            strcpy(message, "Slide with the arrow keys.");
        } else {
            strcpy(message, "Nothing moves that way.");
        }

        if (!can_move(board)) {
            strcpy(message, "\x1b[31mNo moves left.\x1b[0m Press R to start again.");
        }
    }

    restore_mode();
    printf("\x1b[2J\x1b[H");
    printf("Final score: %d (best %d).\n", score, best);
    return 0;
}

/* local_keylogger_term.c
   Safe demo: captures keystrokes entered into this program's terminal session only.
   Compile:
     gcc -o local_keylogger_term local_keylogger_term.c
   Run:
     ./local_keylogger_term
   Press Ctrl-C to exit.
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

static struct termios orig_term;
static volatile sig_atomic_t keep_running = 1;

void restore_term(void) {
    tcsetattr(STDIN_FILENO, TCSANOW, &orig_term);
}

void int_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

int main(void) {
    // Save original terminal attributes
    if (tcgetattr(STDIN_FILENO, &orig_term) < 0) {
        perror("tcgetattr");
        return 1;
    }
    atexit(restore_term);
    signal(SIGINT, int_handler);

    // Put terminal into raw-ish mode (non-canonical, no echo)
    struct termios raw = orig_term;
    raw.c_lflag &= ~(ECHO | ICANON); // turn off echo and canonical mode
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) {
        perror("tcsetattr");
        return 1;
    }

    printf("Safe terminal keystroke capture demo.\n");
    printf("Type; characters will be logged to local_key_events_term.log. Press Ctrl-C to quit.\n");

    FILE *f = fopen("local_key_events_term.log", "a");
    if (!f) {
        perror("fopen");
        return 1;
    }

    while (keep_running) {
        unsigned char ch;
        ssize_t r = read(STDIN_FILENO, &ch, 1);
        if (r <= 0) continue;
        time_t t = time(NULL);
        char ts[32];
        struct tm *tm = gmtime(&t);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);

        // Log printable hex + char if printable
        if (ch >= 32 && ch <= 126) {
            fprintf(f, "%s  0x%02x  '%c'\n", ts, ch, ch);
        } else {
            fprintf(f, "%s  0x%02x  (nonprint)\n", ts, ch);
        }
        fflush(f);
    }

    fclose(f);
    printf("\nExiting — log written to local_key_events_term.log\n");
    return 0;
}

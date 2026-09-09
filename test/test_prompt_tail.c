// The awaiting-input corroboration gate: output_tail_is_prompt + the probe's
// hint level decide whether a quiet command is "waiting for you" or just busy.
//
// This is what keeps macOS usable: XNU exposes no wait channel (no
// /proc/<pid>/syscall, kp_eproc.e_wmesg is empty), so bridge_pty_probe_blocked
// can only answer 2 ("asleep, holding a pty fd") for everything except an
// echo-off transition. Without corroboration every command that outlived a
// couple of poll ticks — sleep, curl, npm install waiting on the registry —
// got parked as STEP_AWAITING_INPUT and Ctrl-C'd by the backend.
//
// Includes main.c (Noise send shimmed, entry point renamed) so the real
// send_output_bytes → otail_append path fills the buffer under test.
// Build+run: make test-prompt-tail

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w; (void)pt; (void)pt_len;
    return 0;  // frames are irrelevant here; only s->otail matters
}

static int failures;

// Feed `text` through the real emission path in chunks, so a prompt split
// across PTY reads is judged exactly as it would be live.
static void feed(session_t *s, const char *text, size_t chunk) {
    size_t len = strlen(text);
    for (size_t off = 0; off < len; off += chunk) {
        size_t n = len - off < chunk ? len - off : chunk;
        otail_append(s, (const uint8_t *)text + off, n);
    }
}

static void check(const char *label, const char *text, int expect) {
    for (size_t chunk = 1; chunk <= 64; chunk *= 8) {  // 1, 8, 64: split anywhere
        session_t s = {0};
        feed(&s, text, chunk);
        int got = output_tail_is_prompt(&s);
        if (got != expect) {
            fprintf(stderr, "FAIL [%s] chunk=%zu: got %d, want %d\n", label, chunk, got, expect);
            failures++;
            return;
        }
    }
    printf("ok   [%s] → %d\n", label, expect);
}

int main(void) {
    // Waiting on the user: cursor parked on an unfinished question.
    // 2 = the line asks for a secret; that is the only passwordPrompt signal a
    // RUN step has (its PTY spawns with ECHO already off, so the probe's
    // echo-off transition can never fire).
    check("sudo password",   "[sudo] password for six: ", 2);
    check("npm proceed",     "Need to install the following packages:\n  cowsay@1.6.0\nOk to proceed? (y) ", 1);
    check("yes/no words",    "Do you want to continue [Y/n]? ", 1);
    check("bare colon",      "Username: ", 1);
    check("angle prompt",    "sqlite> ", 1);
    check("overwrite",       "File exists. Overwrite [y/N]", 1);
    check("no trailing sp",  "Enter passphrase:", 2);

    // Busy, not waiting: every line properly terminated.
    check("npm registry",    "npm http fetch GET 200 https://registry.npmjs.org/zod 319ms\n", 0);
    check("build log",       "added 296 packages in 25s\n", 0);
    check("nothing yet",     "", 0);
    check("blank line",      "Installing...\n\n", 0);
    check("cr terminated",   "Downloading 42%\r", 0);
    check("plain word",      "Compiling bridge", 0);
    check("trailing comma",  "Fetching a, b,", 0);

    // A progress bar redraws in place: unterminated, but not a question.
    // ')' would otherwise read as prompt punctuation.
    char bar[512];
    snprintf(bar, sizeof bar, "%s(45%%)", "############################################"
             "############################################################"
             "############################################################"
             "############################################################");
    check("progress bar", bar, 0);

    // Longer than the retained window: only the final line can decide, and it
    // must survive the ring buffer's eviction intact.
    char flood[8192];
    size_t n = 0;
    for (int i = 0; i < 200; i++)
        n += (size_t)snprintf(flood + n, sizeof flood - n, "line %d of noise\n", i);
    snprintf(flood + n, sizeof flood - n, "Password: ");
    check("prompt after flood", flood, 2);

    // Same flood, but ending on a complete line: still not a prompt.
    n = 0;
    for (int i = 0; i < 200; i++)
        n += (size_t)snprintf(flood + n, sizeof flood - n, "line %d of noise\n", i);
    check("flood, no prompt", flood, 0);

    // Past the head limit the bytes are only kept for the truncation tail and
    // never re-emitted live, so the prompt tail must be fed where every step
    // byte passes (ob_append), not from the live emission path alone.
    {
        edge_t *e = calloc(1, sizeof *e);
        session_t *s = calloc(1, sizeof *s);
        ob_resolve(&s->ob, "safe", 4);
        char line[64];
        memset(line, 'x', sizeof line - 2); line[sizeof line - 2] = '\n'; line[sizeof line - 1] = 0;
        for (int i = 0; i < 400; i++) ob_append(e, s, (const uint8_t *)line, strlen(line));
        ob_append(e, s, (const uint8_t *)"Continue? [y/N] ", 16);
        if (!s->ob.truncated) { fprintf(stderr, "FAIL [setup: head limit not reached]\n"); failures++; }
        else if (output_tail_is_prompt(s) != 1) { fprintf(stderr, "FAIL [prompt past head limit invisible]\n"); failures++; }
        else printf("ok   [prompt past head limit] → 1\n");
        free(s); free(e);
    }

    if (failures) { fprintf(stderr, "%d case(s) failed\n", failures); return 1; }
    printf("all prompt-tail cases passed\n");
    return 0;
}

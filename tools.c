// bridge_scan_tools: run each catalog entry's versionCmd + statusCmd via
// `sh -c`, collect {installed, version, statusOutput, authenticated}, emit a
// single `installed_tools` JSON message. Sequential; per-command timeout.
//
// Simplicity rules:
//   - shell does the heavy lifting (every cmd is already `sh -c`-ready)
//   - each cmd runs with a wall-clock deadline via fork + waitpid + kill
//   - no parallelism, no threads — runs once at connect, ~30 tools × ~300ms
//   - "installed" = versionCmd exited 0 with non-empty stdout,
//                   OR (no versionCmd AND statusCmd exited 0)
//   - "authenticated" = statusCmd exited 0 (absent statusCmd ⇒ true)

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "tools.h"
#include "util.h"   // b64_decode

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define VERSION_TIMEOUT_MS 5000
#define STATUS_TIMEOUT_MS  10000
#define OUT_CAP            200   // trim captured output (matches edge scanner)
#define VERSION_CAP        100

// Run a shell command with a deadline. Captures up to `cap` bytes of combined
// stdout+stderr into `out` (NUL-terminated, trimmed of trailing whitespace).
// Returns the child exit code (0 = success), or -1 on spawn/timeout failure.
static int run_shell(const char *cmd, int timeout_ms, char *out, size_t cap) {
    if (cap) out[0] = '\0';

    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) {
        // Child: redirect stdout+stderr to pipe, detach from controlling TTY.
        dup2(pipefd[1], 1);
        dup2(pipefd[1], 2);
        close(pipefd[0]); close(pipefd[1]);
        // New process group so we can kill the whole shell pipeline on timeout.
        setpgid(0, 0);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);

    size_t used = 0;
    int exit_code = -1;
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);

    for (;;) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - t0.tv_sec) * 1000 +
                       (now.tv_nsec - t0.tv_nsec) / 1000000;
        int remaining = timeout_ms - (int)elapsed;
        if (remaining < 0) remaining = 0;

        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
        int pr = poll(&pfd, 1, remaining);
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
            if (used + 1 < cap) {
                ssize_t n = read(pipefd[0], out + used, cap - 1 - used);
                if (n > 0) { used += (size_t)n; out[used] = '\0'; continue; }
                if (n == 0) break; // EOF
                if (n < 0 && errno != EAGAIN) break;
            } else {
                // buffer full — drain and discard
                char scratch[256];
                ssize_t n = read(pipefd[0], scratch, sizeof(scratch));
                if (n <= 0 && errno != EAGAIN) break;
            }
        }
        int wr = waitpid(pid, &exit_code, WNOHANG);
        if (wr == pid) break;
        if (remaining == 0) {
            // timeout — kill the whole process group, fall back to direct pid; reap
            if (kill(-pid, SIGKILL) != 0) kill(pid, SIGKILL);
            waitpid(pid, &exit_code, 0);
            close(pipefd[0]);
            return -1;
        }
    }

    // Final drain
    for (;;) {
        if (used + 1 >= cap) break;
        ssize_t n = read(pipefd[0], out + used, cap - 1 - used);
        if (n <= 0) break;
        used += (size_t)n;
        out[used] = '\0';
    }
    close(pipefd[0]);

    // If waitpid wasn't reached above, reap now.
    if (exit_code == -1) waitpid(pid, &exit_code, 0);

    // Trim trailing whitespace.
    while (used > 0 && (out[used - 1] == '\n' || out[used - 1] == '\r' ||
                        out[used - 1] == ' '  || out[used - 1] == '\t')) {
        out[--used] = '\0';
    }

    if (WIFEXITED(exit_code)) return WEXITSTATUS(exit_code);
    return -1;
}

// Append a JSON-escaped string (enclosed in quotes) to `out`.
// Returns 0 on success, -1 on overflow.
static int json_append_quoted(char *out, size_t cap, size_t *used, const char *s) {
    size_t u = *used;
    if (u + 1 >= cap) return -1;
    out[u++] = '"';
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *esc = NULL;
        char esc_buf[8];
        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            default:
                if (c < 0x20) {
                    snprintf(esc_buf, sizeof(esc_buf), "\\u%04x", c);
                    esc = esc_buf;
                }
                break;
        }
        if (esc) {
            size_t el = strlen(esc);
            if (u + el >= cap) return -1;
            memcpy(out + u, esc, el); u += el;
        } else {
            if (u + 1 >= cap) return -1;
            out[u++] = (char)c;
        }
    }
    if (u + 1 >= cap) return -1;
    out[u++] = '"';
    *used = u;
    return 0;
}

#define APPEND_LIT(lit) do { \
    size_t _l = sizeof(lit) - 1; \
    if (used + _l >= out_cap) return -1; \
    memcpy(out + used, (lit), _l); used += _l; \
} while (0)

int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap) {
    size_t used = 0;
    APPEND_LIT("{\"type\":\"installed_tools\",\"data\":{");

    int first = 1;
    const char *p = entries;
    const char *end = entries + entries_len;
    char key[64];
    char version_b64[512], status_b64[512];
    char version_cmd[512], status_cmd[512];
    char version_out[VERSION_CAP + 1], status_out[OUT_CAP + 1];

    while (p < end) {
        // Parse one line: "<key>\t<b64_version>\t<b64_status>\n"
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        const char *t1 = memchr(p, '\t', (size_t)(line_end - p));
        if (!t1) { p = line_end + 1; continue; }
        const char *t2 = memchr(t1 + 1, '\t', (size_t)(line_end - (t1 + 1)));
        if (!t2) { p = line_end + 1; continue; }

        size_t kl = (size_t)(t1 - p);
        size_t vl = (size_t)(t2 - (t1 + 1));
        size_t sl = (size_t)(line_end - (t2 + 1));
        if (kl == 0 || kl >= sizeof(key) ||
            vl >= sizeof(version_b64) || sl >= sizeof(status_b64)) {
            p = line_end + 1; continue;
        }
        memcpy(key, p, kl); key[kl] = '\0';
        memcpy(version_b64, t1 + 1, vl); version_b64[vl] = '\0';
        memcpy(status_b64,  t2 + 1, sl); status_b64[sl]  = '\0';

        long dl;
        int have_v = 0, have_s = 0;
        if (vl > 0) {
            dl = b64_decode(version_b64, vl, (uint8_t *)version_cmd);
            if (dl > 0 && (size_t)dl < sizeof(version_cmd)) {
                version_cmd[dl] = '\0'; have_v = 1;
            }
        }
        if (sl > 0) {
            dl = b64_decode(status_b64, sl, (uint8_t *)status_cmd);
            if (dl > 0 && (size_t)dl < sizeof(status_cmd)) {
                status_cmd[dl] = '\0'; have_s = 1;
            }
        }

        int v_exit = -1, s_exit = -1;
        version_out[0] = '\0'; status_out[0] = '\0';
        if (have_v) v_exit = run_shell(version_cmd, VERSION_TIMEOUT_MS, version_out, sizeof(version_out));
        if (have_s) s_exit = run_shell(status_cmd,  STATUS_TIMEOUT_MS,  status_out,  sizeof(status_out));

        // Installed heuristic (matches spirit of edge scanner):
        //   prefer versionCmd success; else fall back to statusCmd exit 0.
        int installed = (have_v && v_exit == 0 && version_out[0] != '\0') ||
                        (!have_v && have_s && s_exit == 0);
        // authenticated: statusCmd exit 0; if no statusCmd, treat as true when installed.
        int authed = have_s ? (s_exit == 0) : installed;

        if (!first) APPEND_LIT(",");
        first = 0;
        if (json_append_quoted(out, out_cap, &used, key) != 0) return -1;
        APPEND_LIT(":{\"installed\":");
        if (installed) APPEND_LIT("true"); else APPEND_LIT("false");
        if (installed && have_v && v_exit == 0 && version_out[0] != '\0') {
            // Clamp version to VERSION_CAP chars.
            if (strlen(version_out) > VERSION_CAP) version_out[VERSION_CAP] = '\0';
            APPEND_LIT(",\"version\":");
            if (json_append_quoted(out, out_cap, &used, version_out) != 0) return -1;
        }
        if (installed && have_s) {
            APPEND_LIT(",\"authenticated\":");
            if (authed) APPEND_LIT("true"); else APPEND_LIT("false");
            if (status_out[0] != '\0') {
                APPEND_LIT(",\"statusOutput\":");
                if (json_append_quoted(out, out_cap, &used, status_out) != 0) return -1;
            }
        }
        APPEND_LIT("}");

        p = line_end + 1;
    }

    APPEND_LIT("}}");
    if (used >= out_cap) return -1;
    out[used] = '\0';
    return (int)used;
}

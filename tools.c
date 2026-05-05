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
#include "mongoose.h"   // mg_base64_decode

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <poll.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#define VERSION_TIMEOUT_MS 5000
#define STATUS_TIMEOUT_MS  10000
#define OUT_CAP            200   // trim captured output (matches edge scanner)
#define VERSION_CAP        100

// Run a shell command with a deadline. Captures up to `cap` bytes of combined
// stdout+stderr into `out` (NUL-terminated, trimmed of trailing whitespace).
// Returns the child exit code (0 = success), or -1 on spawn/timeout failure.
#ifdef _WIN32
// Locate a POSIX-ish shell. Catalog commands assume `sh -c` semantics, so on
// Windows we run them through bash.exe (Git Bash / MSYS2 / WSL). $BRIDGE_SHELL
// overrides; otherwise let CreateProcess search PATH for "bash.exe".
static const char *win_shell(void) {
    static char buf[MAX_PATH];
    static int  resolved = 0;
    if (resolved) return buf[0] ? buf : NULL;
    resolved = 1;
    const char *env = getenv("BRIDGE_SHELL");
    if (env && *env) { snprintf(buf, sizeof(buf), "%s", env); return buf; }
    if (SearchPathA(NULL, "bash.exe", NULL, sizeof(buf), buf, NULL) > 0) return buf;
    const char *fallbacks[] = {
        "C:\\Program Files\\Git\\bin\\bash.exe",
        "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
        NULL,
    };
    for (int i = 0; fallbacks[i]; i++) {
        if (GetFileAttributesA(fallbacks[i]) != INVALID_FILE_ATTRIBUTES) {
            snprintf(buf, sizeof(buf), "%s", fallbacks[i]);
            return buf;
        }
    }
    buf[0] = '\0';
    return NULL;
}

static int run_shell(const char *cmd, int timeout_ms, char *out, size_t cap) {
    if (cap) out[0] = '\0';
    const char *sh = win_shell();
    if (!sh) return -1;

    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = TRUE };
    HANDLE r = NULL, w = NULL;
    if (!CreatePipe(&r, &w, &sa, 0)) return -1;
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);

    char cmdline[2048];
    // Quote shell path; pass `cmd` as a single argument to `-c`.
    int n = snprintf(cmdline, sizeof(cmdline), "\"%s\" -c \"%s\"", sh, cmd);
    if (n <= 0 || (size_t)n >= sizeof(cmdline)) { CloseHandle(r); CloseHandle(w); return -1; }

    STARTUPINFOA si = { .cb = sizeof(si), .dwFlags = STARTF_USESTDHANDLES,
                        .hStdOutput = w, .hStdError = w, .hStdInput = NULL };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(r); CloseHandle(w);
        return -1;
    }
    CloseHandle(w);  // child holds the only writer now

    DWORD start = GetTickCount();
    size_t used = 0;
    int timed_out = 0;

    for (;;) {
        DWORD elapsed = GetTickCount() - start;
        DWORD remaining = (DWORD)timeout_ms > elapsed ? (DWORD)timeout_ms - elapsed : 0;
        DWORD avail = 0;
        // PeekNamedPipe avoids blocking; ReadFile would block until child closes.
        if (PeekNamedPipe(r, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            if (used + 1 < cap) {
                DWORD got = 0;
                DWORD want = (DWORD)(cap - 1 - used);
                if (avail < want) want = avail;
                if (ReadFile(r, out + used, want, &got, NULL) && got > 0) {
                    used += got; out[used] = '\0';
                    continue;
                }
            } else {
                char scratch[256]; DWORD got = 0;
                ReadFile(r, scratch, sizeof(scratch), &got, NULL);
            }
        }
        DWORD wr = WaitForSingleObject(pi.hProcess, 50);
        if (wr == WAIT_OBJECT_0) break;
        if (remaining == 0) { timed_out = 1; break; }
    }

    if (timed_out) TerminateProcess(pi.hProcess, 1);

    // Final drain.
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(r, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
        if (used + 1 >= cap) {
            char scratch[256]; DWORD got = 0;
            if (!ReadFile(r, scratch, sizeof(scratch), &got, NULL) || got == 0) break;
        } else {
            DWORD got = 0;
            DWORD want = (DWORD)(cap - 1 - used);
            if (avail < want) want = avail;
            if (!ReadFile(r, out + used, want, &got, NULL) || got == 0) break;
            used += got; out[used] = '\0';
        }
    }

    DWORD exit_code = 1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CloseHandle(r);

    while (used > 0 && (out[used-1] == '\n' || out[used-1] == '\r' ||
                        out[used-1] == ' '  || out[used-1] == '\t')) {
        out[--used] = '\0';
    }
    for (size_t i = 0; i < used; i++) {
        if ((unsigned char)out[i] < 0x20) out[i] = ' ';
    }

    return timed_out ? -1 : (int)exit_code;
}
#else
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

    // Sanitize: replace control bytes (incl. ANSI ESC) with space. mg_print_esc
    // only escapes \b\f\n\r\t\\\" — raw 0x00–0x1f would otherwise produce
    // invalid JSON when embedded as a string value.
    for (size_t i = 0; i < used; i++) {
        if ((unsigned char)out[i] < 0x20) out[i] = ' ';
    }

    if (WIFEXITED(exit_code)) return WEXITSTATUS(exit_code);
    return -1;
}
#endif

// Append `fmt` (mg_snprintf-style) at *used; advance *used. -1 on overflow.
static int j_append(char *out, size_t cap, size_t *used, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    size_t avail = cap > *used ? cap - *used : 0;
    size_t n = mg_vsnprintf(out + *used, avail, fmt, &ap);
    va_end(ap);
    if (n >= avail) return -1;
    *used += n;
    return 0;
}

// Decode one catalog line: "<key>\t<b64_versionCmd>\t<b64_statusCmd>".
// Returns 1 on success, 0 if the line is malformed/oversized.
static int parse_entry(const char *line, size_t line_len,
                       char *key, size_t key_cap,
                       char *vcmd, size_t vcmd_cap, int *have_v,
                       char *scmd, size_t scmd_cap, int *have_s) {
    *have_v = *have_s = 0;
    const char *t1 = memchr(line, '\t', line_len);
    if (!t1) return 0;
    const char *t2 = memchr(t1 + 1, '\t', (size_t)(line + line_len - (t1 + 1)));
    if (!t2) return 0;

    size_t kl = (size_t)(t1 - line);
    size_t vl = (size_t)(t2 - (t1 + 1));
    size_t sl = (size_t)(line + line_len - (t2 + 1));
    if (kl == 0 || kl >= key_cap) return 0;
    memcpy(key, line, kl); key[kl] = '\0';

    size_t dl;
    if (vl > 0 && vl < vcmd_cap * 2) {
        dl = mg_base64_decode(t1 + 1, vl, vcmd, vcmd_cap);
        if (dl > 0 && dl < vcmd_cap) { vcmd[dl] = '\0'; *have_v = 1; }
    }
    if (sl > 0 && sl < scmd_cap * 2) {
        dl = mg_base64_decode(t2 + 1, sl, scmd, scmd_cap);
        if (dl > 0 && dl < scmd_cap) { scmd[dl] = '\0'; *have_s = 1; }
    }
    return 1;
}

// Run versionCmd + statusCmd for a single entry and append its JSON object
// (`,"key":{...}` or `"key":{...}` if `first`) to `out`. Returns 0 ok, -1 overflow.
static int probe_and_append(const char *key,
                            const char *vcmd, int have_v,
                            const char *scmd, int have_s,
                            int first, char *out, size_t out_cap, size_t *used) {
    char version_out[VERSION_CAP + 1] = {0};
    char status_out[OUT_CAP + 1] = {0};
    int v_exit = -1, s_exit = -1;
    if (have_v) v_exit = run_shell(vcmd, VERSION_TIMEOUT_MS, version_out, sizeof(version_out));
    if (have_s) s_exit = run_shell(scmd, STATUS_TIMEOUT_MS,  status_out,  sizeof(status_out));

    int installed = (have_v && v_exit == 0 && version_out[0] != '\0') ||
                    (!have_v && have_s && s_exit == 0);
    int authed = have_s ? (s_exit == 0) : installed;

    if (j_append(out, out_cap, used, "%s%m:{%m:%s",
                 first ? "" : ",",
                 MG_ESC(key),
                 MG_ESC("installed"), installed ? "true" : "false") < 0) return -1;
    if (installed && have_v && v_exit == 0 && version_out[0] != '\0') {
        if (strlen(version_out) > VERSION_CAP) version_out[VERSION_CAP] = '\0';
        if (j_append(out, out_cap, used, ",%m:%m",
                     MG_ESC("version"), MG_ESC(version_out)) < 0) return -1;
    }
    if (installed && have_s) {
        if (j_append(out, out_cap, used, ",%m:%s",
                     MG_ESC("authenticated"), authed ? "true" : "false") < 0) return -1;
        if (status_out[0] != '\0') {
            if (j_append(out, out_cap, used, ",%m:%m",
                         MG_ESC("statusOutput"), MG_ESC(status_out)) < 0) return -1;
        }
    }
    if (j_append(out, out_cap, used, "}") < 0) return -1;
    return 0;
}

int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap) {
    size_t used = 0;
    if (j_append(out, out_cap, &used, "{%m:%m,%m:{",
                 MG_ESC("type"), MG_ESC("installed_tools"),
                 MG_ESC("data")) < 0) return -1;

    int first = 1;
    const char *p = entries, *end = entries + entries_len;
    char key[64], vcmd[512], scmd[512];

    while (p < end) {
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        int have_v, have_s;
        if (parse_entry(p, (size_t)(line_end - p),
                        key, sizeof(key),
                        vcmd, sizeof(vcmd), &have_v,
                        scmd, sizeof(scmd), &have_s)) {
            if (probe_and_append(key, vcmd, have_v, scmd, have_s,
                                 first, out, out_cap, &used) < 0) return -1;
            first = 0;
        }
        p = line_end + 1;
    }

    if (j_append(out, out_cap, &used, "}}") < 0) return -1;
    if (used >= out_cap) return -1;
    out[used] = '\0';
    return (int)used;
}

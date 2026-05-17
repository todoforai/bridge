// bridge_scan_tools: run each catalog entry's versionCmd + statusCmd via
// `sh -c`, collect {installed, version, statusOutput, authenticated}, emit a
// single JSON object keyed by tool name. Per-command timeout.
//
// Simplicity rules:
//   - shell does the heavy lifting (every cmd is already `sh -c`-ready)
//   - each cmd runs with a wall-clock deadline via fork + waitpid + kill
//   - POSIX: pthread pool of PARALLEL_WORKERS drains a shared job queue
//     (fork-from-thread is safe; child only calls async-signal-safe libc).
//     Windows path stays serial.
//   - "installed" = versionCmd exited 0 with non-empty stdout,
//                   OR (no versionCmd AND statusCmd exited 0)
//   - "authenticated" = statusCmd exited 0 (absent statusCmd ⇒ true)

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "tools.h"
#include "json.h"

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
#  include <pthread.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#define PARALLEL_WORKERS 16

#define VERSION_TIMEOUT_MS 5000
#define STATUS_TIMEOUT_MS  10000
#define INSTALL_TIMEOUT_MS 180000 // 3 min for package managers (npm/pip/bun)
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
        // Make ~/.local/bin visible to probes/installs so a tool just dropped
        // there by an earlier install step is found on the re-probe in the
        // same scan_tools call (Ubuntu's ~/.profile only adds it at login).
        const char *home = getenv("HOME");
        if (home && *home) {
            const char *old = getenv("PATH");
            char path_buf[2048];
            snprintf(path_buf, sizeof path_buf, "%s/.local/bin:%s", home, old ? old : "/usr/local/bin:/usr/bin:/bin");
            setenv("PATH", path_buf, 1);
        }
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
                else if (n == 0) break; // EOF
                else if (errno != EAGAIN) break;
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

    // Sanitize: replace control bytes (incl. ANSI ESC) with space — keeps the
    // value JSON-safe even if json_emit_str's own escape table grows later.
    for (size_t i = 0; i < used; i++) {
        if ((unsigned char)out[i] < 0x20) out[i] = ' ';
    }

    if (WIFEXITED(exit_code)) return WEXITSTATUS(exit_code);
    return -1;
}
#endif



// Decode one catalog line: "<key>\t<b64_versionCmd>\t<b64_statusCmd>[\t<b64_installCmd>]".
// The 4th field is optional; when present and the tool is missing, scan_tools
// runs it and re-probes. Returns 1 on success, 0 if malformed/oversized.
static int parse_entry(const char *line, size_t line_len,
                       char *key, size_t key_cap,
                       char *vcmd, size_t vcmd_cap, int *have_v,
                       char *scmd, size_t scmd_cap, int *have_s,
                       char *icmd, size_t icmd_cap, int *have_i) {
    *have_v = *have_s = *have_i = 0;
    const char *t1 = memchr(line, '\t', line_len);
    if (!t1) return 0;
    const char *t2 = memchr(t1 + 1, '\t', (size_t)(line + line_len - (t1 + 1)));
    if (!t2) return 0;
    // Optional 3rd tab separating statusCmd from installCmd.
    const char *t3 = memchr(t2 + 1, '\t', (size_t)(line + line_len - (t2 + 1)));
    const char *s_end = t3 ? t3 : line + line_len;

    size_t kl = (size_t)(t1 - line);
    size_t vl = (size_t)(t2 - (t1 + 1));
    size_t sl = (size_t)(s_end - (t2 + 1));
    size_t il = t3 ? (size_t)(line + line_len - (t3 + 1)) : 0;
    if (kl == 0 || kl >= key_cap) return 0;
    memcpy(key, line, kl); key[kl] = '\0';

    size_t dl;
    if (vl > 0 && vl < vcmd_cap * 2) {
        dl = b64_decode(t1 + 1, vl, vcmd, vcmd_cap - 1);
        if (dl > 0 && dl < vcmd_cap) { vcmd[dl] = '\0'; *have_v = 1; }
    }
    if (sl > 0 && sl < scmd_cap * 2) {
        dl = b64_decode(t2 + 1, sl, scmd, scmd_cap - 1);
        if (dl > 0 && dl < scmd_cap) { scmd[dl] = '\0'; *have_s = 1; }
    }
    if (il > 0 && il < icmd_cap * 2) {
        dl = b64_decode(t3 + 1, il, icmd, icmd_cap - 1);
        if (dl > 0 && dl < icmd_cap) { icmd[dl] = '\0'; *have_i = 1; }
    }
    return 1;
}

// One catalog entry: input cmds + post-probe results.
typedef struct {
    char key[64];
    char vcmd[512], scmd[512], icmd[1024];
    int  have_v, have_s, have_i;
    char version_out[VERSION_CAP + 1];
    char status_out[OUT_CAP + 1];
    int  v_exit, s_exit;
    int  installed, authed, installed_now;
} probe_t;

// Run versionCmd + statusCmd. If missing and installCmd is present, run it
// once and re-probe. Pure: no shared state.
static void probe_run(probe_t *p) {
    p->v_exit = p->s_exit = -1;
    if (p->have_v) p->v_exit = run_shell(p->vcmd, VERSION_TIMEOUT_MS, p->version_out, sizeof(p->version_out));
    if (p->have_s) p->s_exit = run_shell(p->scmd, STATUS_TIMEOUT_MS,  p->status_out,  sizeof(p->status_out));
    p->installed = (p->have_v && p->v_exit == 0 && p->version_out[0] != '\0') ||
                   (!p->have_v && p->have_s && p->s_exit == 0);

    if (!p->installed && p->have_i) {
        char sink[OUT_CAP + 1];
        run_shell(p->icmd, INSTALL_TIMEOUT_MS, sink, sizeof(sink));
        if (p->have_v) p->v_exit = run_shell(p->vcmd, VERSION_TIMEOUT_MS, p->version_out, sizeof(p->version_out));
        if (p->have_s) p->s_exit = run_shell(p->scmd, STATUS_TIMEOUT_MS,  p->status_out,  sizeof(p->status_out));
        p->installed = (p->have_v && p->v_exit == 0 && p->version_out[0] != '\0') ||
                       (!p->have_v && p->have_s && p->s_exit == 0);
        p->installed_now = p->installed;
    }
    p->authed = p->have_s ? (p->s_exit == 0) : p->installed;
}

// Append one probe's JSON object to `out`. Returns 0 ok, -1 overflow.
static int probe_append_json(const probe_t *p, int first,
                             char *out, size_t out_cap, size_t *used) {
    if (!first && json_emit_raw(out, out_cap, used, ",", 1) < 0) return -1;
    if (json_emit_str(out, out_cap, used, p->key, -1) < 0) return -1;
    if (json_emit_raw(out, out_cap, used, ":{", 2) < 0) return -1;
    if (json_emit_str(out, out_cap, used, "installed", -1) < 0) return -1;
    if (json_emit_raw(out, out_cap, used, ":", 1) < 0) return -1;
    const char *bv = p->installed ? "true" : "false";
    if (json_emit_raw(out, out_cap, used, bv, strlen(bv)) < 0) return -1;
    if (p->installed && p->have_v && p->v_exit == 0 && p->version_out[0] != '\0') {
        if (json_emit_raw(out, out_cap, used, ",", 1) < 0) return -1;
        if (json_emit_str(out, out_cap, used, "version", -1) < 0) return -1;
        if (json_emit_raw(out, out_cap, used, ":", 1) < 0) return -1;
        if (json_emit_str(out, out_cap, used, p->version_out, -1) < 0) return -1;
    }
    if (p->installed_now) {
        if (json_emit_raw(out, out_cap, used, ",", 1) < 0) return -1;
        if (json_emit_str(out, out_cap, used, "installedNow", -1) < 0) return -1;
        if (json_emit_raw(out, out_cap, used, ":true", 5) < 0) return -1;
    }
    if (p->installed && p->have_s) {
        if (json_emit_raw(out, out_cap, used, ",", 1) < 0) return -1;
        if (json_emit_str(out, out_cap, used, "authenticated", -1) < 0) return -1;
        if (json_emit_raw(out, out_cap, used, ":", 1) < 0) return -1;
        const char *ba = p->authed ? "true" : "false";
        if (json_emit_raw(out, out_cap, used, ba, strlen(ba)) < 0) return -1;
        if (p->status_out[0] != '\0') {
            if (json_emit_raw(out, out_cap, used, ",", 1) < 0) return -1;
            if (json_emit_str(out, out_cap, used, "statusOutput", -1) < 0) return -1;
            if (json_emit_raw(out, out_cap, used, ":", 1) < 0) return -1;
            if (json_emit_str(out, out_cap, used, p->status_out, -1) < 0) return -1;
        }
    }
    if (json_emit_raw(out, out_cap, used, "}", 1) < 0) return -1;
    return 0;
}

#ifndef _WIN32
// Shared job queue: workers pop the next index until exhausted.
typedef struct {
    probe_t *probes;
    int      n;
    int      next;
    pthread_mutex_t mu;
} job_pool_t;

static void *worker_main(void *arg) {
    job_pool_t *jp = arg;
    for (;;) {
        pthread_mutex_lock(&jp->mu);
        int i = jp->next < jp->n ? jp->next++ : -1;
        pthread_mutex_unlock(&jp->mu);
        if (i < 0) return NULL;
        probe_run(&jp->probes[i]);
    }
}
#endif

// Parse all catalog lines into a heap-allocated probe_t[]. *out_n receives count.
// Returns NULL on alloc failure. Skips malformed lines.
static probe_t *parse_catalog(const char *entries, size_t entries_len, int *out_n) {
    // Upper bound: number of newlines + 1.
    int cap = 1;
    for (size_t i = 0; i < entries_len; i++) if (entries[i] == '\n') cap++;
    probe_t *probes = calloc((size_t)cap, sizeof(*probes));
    if (!probes) { *out_n = 0; return NULL; }

    int n = 0;
    const char *p = entries, *end = entries + entries_len;
    while (p < end && n < cap) {
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;
        probe_t *e = &probes[n];
        if (parse_entry(p, (size_t)(line_end - p),
                        e->key, sizeof(e->key),
                        e->vcmd, sizeof(e->vcmd), &e->have_v,
                        e->scmd, sizeof(e->scmd), &e->have_s,
                        e->icmd, sizeof(e->icmd), &e->have_i)) {
            n++;
        }
        p = line_end + 1;
    }
    *out_n = n;
    return probes;
}

int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap,
                      bridge_scan_stats_t *stats) {
    if (stats) {
        stats->installed = stats->authenticated = stats->installed_now = 0;
        stats->installed_now_names[0] = '\0';
    }

    int n = 0;
    probe_t *probes = parse_catalog(entries, entries_len, &n);
    if (!probes) return -1;

#ifdef _WIN32
    for (int i = 0; i < n; i++) probe_run(&probes[i]);
#else
    int nworkers = n < PARALLEL_WORKERS ? n : PARALLEL_WORKERS;
    if (nworkers <= 1) {
        for (int i = 0; i < n; i++) probe_run(&probes[i]);
    } else {
        job_pool_t jp = { .probes = probes, .n = n, .next = 0 };
        pthread_mutex_init(&jp.mu, NULL);
        pthread_t tids[PARALLEL_WORKERS];
        int started = 0;
        for (int i = 0; i < nworkers; i++) {
            if (pthread_create(&tids[i], NULL, worker_main, &jp) == 0) started++;
        }
        // If thread creation partially failed, drain remainder on this thread.
        if (started < nworkers) worker_main(&jp);
        for (int i = 0; i < started; i++) pthread_join(tids[i], NULL);
        pthread_mutex_destroy(&jp.mu);
    }
#endif

    // Assemble JSON object (just the {<key>:{...},...} dict, no envelope).
    size_t used = 0;
    if (json_emit_raw(out, out_cap, &used, "{", 1) < 0) { free(probes); return -1; }

    for (int i = 0; i < n; i++) {
        probe_t *p = &probes[i];
        if (stats) {
            if (p->installed)              stats->installed++;
            if (p->installed && p->authed) stats->authenticated++;
            if (p->installed_now) {
                stats->installed_now++;
                size_t cur = strlen(stats->installed_now_names);
                size_t need = (cur ? 2 : 0) + strlen(p->key);
                if (cur + need + 1 < sizeof(stats->installed_now_names)) {
                    if (cur) { stats->installed_now_names[cur++] = ','; stats->installed_now_names[cur++] = ' '; }
                    strcpy(stats->installed_now_names + cur, p->key);
                }
            }
        }
        if (probe_append_json(p, i == 0, out, out_cap, &used) < 0) {
            free(probes); return -1;
        }
    }

    free(probes);
    if (json_emit_raw(out, out_cap, &used, "}", 1) < 0) return -1;
    if (used >= out_cap) return -1;
    out[used] = '\0';
    return (int)used;
}

// bridge_scan_tools: run each catalog entry's versionCmd + statusCmd via
// `sh -c`, collect {installed, version, statusOutput, authenticated}, emit a
// single JSON object keyed by tool name. Per-command timeout.
//
// Simplicity rules:
//   - shell does the heavy lifting (every cmd is already `sh -c`-ready)
//   - each cmd runs with a wall-clock deadline via fork + waitpid + kill
//   - POSIX: pthread pool of PARALLEL_WORKERS drains a shared job queue.
//     The PATH is exported once up front so the fork children only call
//     async-signal-safe libc (dup2/setpgid/execl) — anything else could
//     deadlock on a lock another probe thread held at fork time.
//     Windows path stays serial.
//   - "installed" = versionCmd exited 0 with non-empty stdout,
//                   OR (no versionCmd AND statusCmd exited 0)
//   - "authenticated" = statusCmd exited 0 (absent statusCmd ⇒ true)

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "tools.h"
#include "json.h"
#include "env_path.h"
#ifdef _WIN32
#  include "pty.h"   // bridge_pty_resolve_shell — the one shell resolver
#endif

#include <ctype.h>
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
#define OUT_CAP            2048  // trim captured output — multi-account tools (e.g. zele whoami) need >200B
#define VERSION_CAP        100

// Run a shell command with a deadline. Captures up to `cap` bytes of combined
// stdout+stderr into `out` (NUL-terminated, trimmed of trailing whitespace).
// Returns the child exit code (0 = success), or -1 on spawn/timeout failure.
#ifdef _WIN32
// Locate a POSIX-ish shell via the one shared resolver (pty_win.c), so tool
// probing, identity and RUN always agree. Catalog commands assume `sh -c`
// semantics, so a cmd.exe resolution means "no usable shell" here.
static const char *win_shell(void) {
    const char *sh = bridge_pty_resolve_shell(NULL);
    if (!sh || !*sh) return NULL;
    const char *base = sh + strlen(sh);
    while (base > sh && base[-1] != '\\' && base[-1] != '/') base--;
    if (_stricmp(base, "cmd.exe") == 0 || _stricmp(base, "cmd") == 0) return NULL;
    return sh;
}

static int run_shell(const char *cmd, int timeout_ms, char *out, size_t cap) {
    if (cap) out[0] = '\0';
    bridge_prepend_tools_path_win();
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
    // Strip ANSI/control bytes but keep \n \r \t (see Linux branch).
    for (size_t i = 0; i < used; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') out[i] = ' ';
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
        // Between fork() and exec() in a threaded process, only async-signal-
        // safe calls are legal: another probe thread can hold the malloc or
        // environ lock at the instant we fork, and the child inherits it
        // locked with no thread left to release it. So everything unsafe
        // (building PATH, setenv) happens once in the parent — see
        // bridge_scan_tools — and this child only rearranges fds and execs.
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

    // Strip ANSI/control bytes but keep \n \r \t — json_emit_str escapes them
    // properly, and the UI (whitespace-pre-wrap) renders multi-line output.
    for (size_t i = 0; i < used; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') out[i] = ' ';
    }

    if (WIFEXITED(exit_code)) return WEXITSTATUS(exit_code);
    return -1;
}
#endif



// Decode one catalog line: "<key>\t<b64_versionCmd>\t<b64_statusCmd>".
// Any trailing tab-separated fields are ignored. Returns 1 on success,
// 0 if malformed/oversized.
static int parse_entry(const char *line, size_t line_len,
                       char *key, size_t key_cap,
                       char *vcmd, size_t vcmd_cap, int *have_v,
                       char *scmd, size_t scmd_cap, int *have_s) {
    *have_v = *have_s = 0;
    const char *t1 = memchr(line, '\t', line_len);
    if (!t1) return 0;
    const char *t2 = memchr(t1 + 1, '\t', (size_t)(line + line_len - (t1 + 1)));
    if (!t2) return 0;
    // statusCmd runs to the next tab (if any) or end of line.
    const char *t3 = memchr(t2 + 1, '\t', (size_t)(line + line_len - (t2 + 1)));
    const char *s_end = t3 ? t3 : line + line_len;

    size_t kl = (size_t)(t1 - line);
    size_t vl = (size_t)(t2 - (t1 + 1));
    size_t sl = (size_t)(s_end - (t2 + 1));
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
    return 1;
}

// ── User custom tools (~/.todoforai/custom_tools.json) ──────────────────────
// Same file format as the edge client: {"<name>": {"enabled"?, "description"?,
// "label"?}}. Hides catalog tools (enabled:false), overrides description/label,
// and advertises non-catalog binaries (probed via `command -v`). Missing or
// malformed file ⇒ no customs (silent).

// CUSTOM_MAX × (DESC+LABEL, JSON-escaped ≤ 2×) must leave room for the
// catalog states in the 64 KiB result buffer (MAX_MSG in main.c).
#define CUSTOM_MAX       32
#define CUSTOM_FILE_CAP  65536
#define CUSTOM_DESC_CAP  600
#define CUSTOM_LABEL_CAP 128

typedef struct {
    char key[64];
    int  enabled;                     // 0 = hidden
    char desc[CUSTOM_DESC_CAP];      // "" = none
    char label[CUSTOM_LABEL_CAP];    // "" = none
    int  matched;                     // set when a catalog probe claimed it
} custom_tool_t;

// Names are interpolated into `command -v <name>` — restrict to plain
// binary-name tokens (alnum start, then alnum/_/./-, max 63 = key buf - 1).
static int custom_name_safe(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 63) return 0;
    if (!isalnum((unsigned char)s[0])) return 0;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_' && c != '.' && c != '-') return 0;
    }
    return 1;
}

// Read $HOME/.todoforai/custom_tools.json (≤ CUSTOM_FILE_CAP). Heap-allocated
// custom_tool_t[]; *out_n receives count. NULL when absent/unreadable/empty.
static custom_tool_t *load_custom_tools(int *out_n) {
    *out_n = 0;
#ifdef _WIN32
    // USERPROFILE first — matches the edge's os.homedir(); Git/MSYS may set
    // HOME elsewhere.
    const char *home = getenv("USERPROFILE");
    if (!home || !*home) home = getenv("HOME");
#else
    const char *home = getenv("HOME");
#endif
    if (!home || !*home) return NULL;

    char path[1024];
    int pn = snprintf(path, sizeof(path), "%s/.todoforai/custom_tools.json", home);
    if (pn <= 0 || (size_t)pn >= sizeof(path)) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(CUSTOM_FILE_CAP);
    if (!buf) { fclose(f); return NULL; }
    size_t len = fread(buf, 1, CUSTOM_FILE_CAP, f);
    fclose(f);
    if (len == 0 || len >= CUSTOM_FILE_CAP) { free(buf); return NULL; } // empty or oversized

    custom_tool_t *customs = calloc(CUSTOM_MAX, sizeof(*customs));
    if (!customs) { free(buf); return NULL; }

    int n = 0;
    size_t pos = 0;
    const char *k, *v; size_t kl, vl; json_type_t vt;
    while (n < CUSTOM_MAX &&
           json_obj_iter(buf, len, &pos, &k, &kl, &v, &vl, &vt)) {
        if (vt != JT_OBJ) continue;
        custom_tool_t *c = &customs[n];
        if (json_unescape_span(k, kl, c->key, sizeof(c->key)) <= 0) continue;
        if (!custom_name_safe(c->key)) continue;
        // Duplicate key: last value wins (JSON.parse semantics, edge parity).
        custom_tool_t *slot = c;
        for (int i = 0; i < n; i++) {
            if (strcmp(customs[i].key, c->key) == 0) { slot = &customs[i]; break; }
        }
        slot->enabled = 1;
        slot->desc[0] = slot->label[0] = '\0';
        json_get_bool(v, vl, "enabled", &slot->enabled);
        size_t dl;
        json_get_str_decoded(v, vl, "description", slot->desc,  sizeof(slot->desc),  &dl);
        json_get_str_decoded(v, vl, "label",       slot->label, sizeof(slot->label), &dl);
        if (slot == c) n++;
    }
    // All-or-nothing (edge JSON.parse parity): a malformed file must not be
    // partially applied. After a full iteration, only `}` + whitespace may
    // remain; `pos` past the last value only moves via well-formed pairs.
    if (n > 0 && n < CUSTOM_MAX) {
        const char *p = buf + pos, *e = buf + len;
        while (p < e && (*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) p++;
        int ok = (p < e && *p == '}');
        if (ok) { p++; while (p < e && (*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) p++; ok = (p == e); }
        if (!ok) n = 0;
    }
    free(buf);
    if (n == 0) { free(customs); return NULL; }
    *out_n = n;
    return customs;
}

// One catalog entry: input cmds + post-probe results.
typedef struct {
    char key[64];
    char vcmd[512], scmd[512];
    int  have_v, have_s;
    char version_out[VERSION_CAP + 1];
    char status_out[OUT_CAP + 1];
    int  v_exit, s_exit;
    int  installed, authed;
    int  synthetic;             // non-catalog custom (command -v presence probe)
    const custom_tool_t *cust;  // user override for this key, or NULL
} probe_t;

// Run versionCmd + statusCmd. Pure: no shared state.
static void probe_run(probe_t *p) {
    p->v_exit = p->s_exit = -1;
    if (p->have_v) p->v_exit = run_shell(p->vcmd, VERSION_TIMEOUT_MS, p->version_out, sizeof(p->version_out));
    if (p->have_s) p->s_exit = run_shell(p->scmd, STATUS_TIMEOUT_MS,  p->status_out,  sizeof(p->status_out));
    p->installed = (p->have_v && p->v_exit == 0 && p->version_out[0] != '\0') ||
                   (!p->have_v && p->have_s && p->s_exit == 0);
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
    // User overrides from custom_tools.json (description/label) ride on the
    // state — same shape the edge's applyCustomTools produces.
    if (p->installed && p->cust) {
        if (p->cust->desc[0] != '\0') {
            if (json_emit_raw(out, out_cap, used, ",", 1) < 0) return -1;
            if (json_emit_str(out, out_cap, used, "description", -1) < 0) return -1;
            if (json_emit_raw(out, out_cap, used, ":", 1) < 0) return -1;
            if (json_emit_str(out, out_cap, used, p->cust->desc, -1) < 0) return -1;
        }
        if (p->cust->label[0] != '\0') {
            if (json_emit_raw(out, out_cap, used, ",", 1) < 0) return -1;
            if (json_emit_str(out, out_cap, used, "label", -1) < 0) return -1;
            if (json_emit_raw(out, out_cap, used, ":", 1) < 0) return -1;
            if (json_emit_str(out, out_cap, used, p->cust->label, -1) < 0) return -1;
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

// Parse all catalog lines into a heap-allocated probe_t[], folding in user
// custom tools: disabled customs drop their catalog probe, matching customs
// attach description/label overrides, and non-catalog customs get a synthetic
// `command -v <name>` presence probe appended. *out_n receives count.
// Returns NULL on alloc failure. Skips malformed lines.
static probe_t *parse_catalog(const char *entries, size_t entries_len, int *out_n,
                              custom_tool_t *customs, int n_cust) {
    // Upper bound: number of newlines + 1, plus one slot per custom tool.
    int cap = 1 + n_cust;
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
                        e->scmd, sizeof(e->scmd), &e->have_s)) {
            int drop = 0;
            for (int c = 0; c < n_cust; c++) {
                if (strcmp(customs[c].key, e->key) != 0) continue;
                customs[c].matched = 1;
                if (customs[c].enabled) e->cust = &customs[c];
                else drop = 1;  // hidden catalog tool — don't probe
                break;
            }
            if (!drop) n++;
        }
        p = line_end + 1;
    }
    // Non-catalog customs: synthesize a `command -v <name>` presence probe
    // (exit 0 + non-empty stdout ⇒ installed; no statusCmd ⇒ authenticated).
    for (int c = 0; c < n_cust && n < cap; c++) {
        if (customs[c].matched || !customs[c].enabled) continue;
        probe_t *e = &probes[n];
        snprintf(e->key,  sizeof(e->key),  "%s", customs[c].key);
        snprintf(e->vcmd, sizeof(e->vcmd), "command -v %s", customs[c].key);
        e->have_v = 1;
        e->synthetic = 1;
        e->cust = &customs[c];
        n++;
    }
    *out_n = n;
    return probes;
}

int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap,
                      bridge_scan_stats_t *stats) {
    if (stats) {
        stats->installed = stats->authenticated = stats->auth_applicable = 0;
    }

    int n_cust = 0;
    custom_tool_t *customs = load_custom_tools(&n_cust);

    int n = 0;
    probe_t *probes = parse_catalog(entries, entries_len, &n, customs, n_cust);
    if (!probes) { free(customs); return -1; }

#ifdef _WIN32
    for (int i = 0; i < n; i++) probe_run(&probes[i]);
#else
    // Export the tools PATH once, here, while we're still single-threaded:
    // every probe wants the same value, and doing it in each fork child would
    // mean calling malloc/setenv after a fork from a threaded process (see
    // run_shell). Children inherit it for free. The scan runs in its own
    // process (jobs.c), so this cannot disturb the bridge's own environment.
    {
        char *tools_path = bridge_build_tools_path();
        if (tools_path) { setenv("PATH", tools_path, 1); free(tools_path); }
    }
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
    if (json_emit_raw(out, out_cap, &used, "{", 1) < 0) { free(probes); free(customs); return -1; }

    int emitted = 0;
    for (int i = 0; i < n; i++) {
        probe_t *p = &probes[i];
        // Non-catalog customs are only advertised when actually found on
        // PATH (edge parity): a missing binary is not a tool, drop it.
        if (p->synthetic && !p->installed) continue;
        if (stats) {
            if (p->installed)                            stats->installed++;
            // Auth only applies to tools that define a statusCmd (`have_s`).
            // Tools without one have no auth concept — don't count them as
            // authenticated (that would make the banner read N/N spuriously).
            if (p->installed && p->have_s) {
                stats->auth_applicable++;
                if (p->authed) stats->authenticated++;
            }
        }
        if (probe_append_json(p, emitted == 0, out, out_cap, &used) < 0) {
            free(probes); free(customs); return -1;
        }
        emitted++;
    }

    free(probes);
    free(customs);
    if (json_emit_raw(out, out_cap, &used, "}", 1) < 0) return -1;
    if (used >= out_cap) return -1;
    out[used] = '\0';
    return (int)used;
}

// bridge_scan_tools: run each catalog entry's versionCmd + statusCmd via
// `sh -c`, collect {installed, version, statusOutput, authenticated}, emit a
// single JSON object keyed by tool name. Per-command timeout.
//
// Simplicity rules:
//   - shell does the heavy lifting (every cmd is already `sh -c`-ready)
//   - each cmd runs with a wall-clock deadline via fork + waitpid + kill
//   - a pool of PARALLEL_WORKERS threads drains a shared job queue on every
//     platform (pthreads / _beginthreadex). POSIX: the PATH is exported once
//     up front so the fork children only call async-signal-safe libc
//     (dup2/setpgid/execl) — anything else could deadlock on a lock another
//     probe thread held at fork time. Windows: the shell is resolved once up
//     front (bridge_pty_resolve_shell returns a static buffer).
//   - "installed" = versionCmd exited 0 with non-empty stdout,
//                   OR (no versionCmd AND statusCmd exited 0),
//                   OR the binary is on PATH and its versionCmd never
//                     returned an exit status (deadline / spawn failure)
//   - "authenticated" = statusCmd exited 0 (absent statusCmd ⇒ true)

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "tools.h"
#include "policy.h"
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
#  include <process.h>
#else
#  include <fcntl.h>
#  include <poll.h>
#  include <pthread.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#define PARALLEL_WORKERS 16

// A cold node/bun CLI needs ~2 s just to print its version, and 16 probe
// threads sharing a CPU push that past 8 s (measured: 16×`canva --version`
// = 8.2 s wall on an M-series Mac), so 5 s lost their version strings.
// Not raised further: a probe that times out here AND on its status check
// holds a worker for VERSION+STATUS ms, and 88 catalog entries over 16
// workers must still fit the scan's 230 s budget. Overshooting is no longer
// fatal anyway — the presence fallback in probe_run keeps such a tool
// "installed", it just loses the version string until the next scan.
#define VERSION_TIMEOUT_MS 10000
#define STATUS_TIMEOUT_MS  10000
#define OUT_CAP            2048  // trim captured output — multi-account tools (e.g. zele whoami) need >200B
#define VERSION_CAP        100
#define PRESENCE_FP_CAP    512

int bridge_win_quote_arg(const char *arg, char *out, size_t cap) {
    size_t o = 0;
#define PUT(c) do { if (o + 1 >= cap) return -1; out[o++] = (c); } while (0)
    PUT('"');
    for (const char *p = arg;; p++) {
        size_t bs = 0;
        while (*p == '\\') { bs++; p++; }
        // Backslashes are literal unless they precede a `"` (escaped) or the
        // closing quote we add: then each must be doubled.
        size_t reps = (*p == '"' || *p == '\0') ? bs * 2 : bs;
        for (size_t i = 0; i < reps; i++) PUT('\\');
        if (*p == '\0') break;
        if (*p == '"') PUT('\\');
        PUT(*p);
    }
    PUT('"');
#undef PUT
    out[o] = '\0';
    return (int)o;
}

// Run a shell command with a deadline. Captures up to `cap` bytes of combined
// stdout+stderr into `out` (NUL-terminated, trimmed of trailing whitespace).
// Returns the child exit code (0 = success), or -1 on spawn/timeout failure.
#ifdef _WIN32
// Locate a POSIX-ish shell via the one shared resolver (pty_win.c), so tool
// probing, identity and RUN always agree. Catalog commands assume `sh -c`
// semantics, so a cmd.exe resolution means "no usable shell" here.
// Resolved once per scan, before the worker threads start:
// bridge_pty_resolve_shell writes a static buffer and is not thread-safe.
static char g_win_shell[MAX_PATH];
// Serializes pipe creation + CreateProcess across worker threads: inheritable
// handles are process-wide, so without this a concurrent child would inherit
// another probe's pipe write end and hold it open. Only the spawn is locked;
// the wait/collect part runs in parallel.
static CRITICAL_SECTION g_spawn_mu;

static void win_shell_resolve(void) {
    static int mu_ready = 0;
    if (!mu_ready) { InitializeCriticalSection(&g_spawn_mu); mu_ready = 1; }
    g_win_shell[0] = '\0';
    bridge_prepend_tools_path_win();
    const char *sh = bridge_pty_resolve_shell(NULL);
    if (!sh || !*sh) return;
    const char *base = sh + strlen(sh);
    while (base > sh && base[-1] != '\\' && base[-1] != '/') base--;
    if (_stricmp(base, "cmd.exe") == 0 || _stricmp(base, "cmd") == 0) return;
    snprintf(g_win_shell, sizeof(g_win_shell), "%s", sh);
}

static int run_shell(const char *cmd, int timeout_ms, char *out, size_t cap) {
    if (cap) out[0] = '\0';
    const char *sh = g_win_shell;
    if (!*sh) return -1;

    char cmdline[16384];  // presence_scan passes every catalog binary in one line
    // Quote shell path; pass `cmd` as a single argument to `-c`, escaped so
    // embedded `"` / `\` reach the shell intact.
    int n = snprintf(cmdline, sizeof(cmdline), "\"%s\" -c ", sh);
    if (n <= 0 || (size_t)n >= sizeof(cmdline)) return -1;
    if (bridge_win_quote_arg(cmd, cmdline + n, sizeof(cmdline) - (size_t)n) < 0) return -1;

    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = TRUE };
    HANDLE r = NULL, w = NULL;
    PROCESS_INFORMATION pi = {0};
    EnterCriticalSection(&g_spawn_mu);
    if (!CreatePipe(&r, &w, &sa, 0)) { LeaveCriticalSection(&g_spawn_mu); return -1; }
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si = { .cb = sizeof(si), .dwFlags = STARTF_USESTDHANDLES,
                        .hStdOutput = w, .hStdError = w, .hStdInput = NULL };
    BOOL spawned = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(w);  // child holds the only writer now (or nobody, if spawn failed)
    LeaveCriticalSection(&g_spawn_mu);
    if (!spawned) { CloseHandle(r); return -1; }

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
        // Order matters, and so does every guarded close: if the bridge was
        // started with a standard descriptor already closed, pipe() hands back
        // the low number that frees up — pipefd[0] can BE fd 0. Closing a
        // source fd unconditionally after it has become a destination undoes
        // the very redirect we just made, so each close is guarded and stdin is
        // claimed last, once the pipe ends are out of the way.
        dup2(pipefd[1], 1);
        dup2(pipefd[1], 2);
        if (pipefd[0] > 2) close(pipefd[0]);
        if (pipefd[1] > 2) close(pipefd[1]);
        // stdin from /dev/null, never the bridge's own. A probe that reads
        // stdin (a CLI prompting for a password, a `read` in a statusCmd)
        // would otherwise inherit our terminal or socket and block until the
        // deadline killed it — reported as "not authenticated" for a tool that
        // was merely waiting for input nobody was there to type. /dev/null
        // gives it instant EOF, so it fails fast and honestly instead.
        // This also closes the pipe's read end in the case where it landed on
        // fd 0; if /dev/null can't be opened, an EBADF stdin still beats
        // inheriting ours, which is what this exists to prevent.
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            if (devnull != 0) { dup2(devnull, 0); close(devnull); }
        } else {
            close(0);
        }
        // New process group so we can kill the whole shell pipeline on timeout.
        setpgid(0, 0);
        // Backend-authored probe command: same jail as a RUN shell.
        if (bridge_policy_jail_child() != 0) _exit(127);
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

// "$HOME/.todoforai/<file>" into path[cap]. 0 on failure (no home / too long).
static int todoforai_path(char *path, size_t cap, const char *file) {
#ifdef _WIN32
    // USERPROFILE first — matches the edge's os.homedir(); Git/MSYS may set
    // HOME elsewhere.
    const char *home = getenv("USERPROFILE");
    if (!home || !*home) home = getenv("HOME");
#else
    const char *home = getenv("HOME");
#endif
    if (!home || !*home) return 0;
    int pn = snprintf(path, cap, "%s/.todoforai/%s", home, file);
    return pn > 0 && (size_t)pn < cap;
}

// Whole file into a malloc'd buffer (NUL-terminated, *len = bytes). NULL when
// absent, empty or ≥ cap.
static char *read_file(const char *path, size_t cap, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return NULL; }
    *len = fread(buf, 1, cap, f);
    fclose(f);
    if (*len == 0 || *len >= cap) { free(buf); return NULL; }
    buf[*len] = '\0';
    return buf;
}

// Read $HOME/.todoforai/custom_tools.json (≤ CUSTOM_FILE_CAP). Heap-allocated
// custom_tool_t[]; *out_n receives count. NULL when absent/unreadable/empty.
static custom_tool_t *load_custom_tools(int *out_n) {
    *out_n = 0;
    char path[1024];
    if (!todoforai_path(path, sizeof(path), "custom_tools.json")) return NULL;
    size_t len = 0;
    char *buf = read_file(path, CUSTOM_FILE_CAP, &len);
    if (!buf) return NULL;

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
    // Presence short-circuit (see presence_scan): the bare binary the
    // versionCmd starts with, whether one `command -v` pass found it
    // (-1 = unknown ⇒ run the versionCmd as-is), and its fingerprint
    // "<resolved path>\t<ls -ldL line>" for the version cache.
    char bin[64];
    int  present;
    char fp[PRESENCE_FP_CAP];
    int  cacheable;             // version may be served from / saved to the cache
    int  v_cached;              // version_out came from the cache
} probe_t;

// ── Version cache (~/.todoforai/tools_cache.json) ───────────────────────────
// `<tool> --version` is the expensive half of a probe (node/python startup,
// VERSION_TIMEOUT_MS deadline) and its answer only changes when the binary
// does. Keyed by
// tool; an entry is reused when the fingerprint (resolved path + `ls -ldL`
// line: perms, size, mtime to the minute) AND the versionCmd match. A
// same-size, same-minute in-place replacement would keep a stale version
// string — never a stale installed/auth answer. Auth status is never cached
// — tokens expire.
#define CACHE_MAX      256
#define CACHE_FILE_CAP 131072

typedef struct {
    char key[64];
    char fp[PRESENCE_FP_CAP];
    char vcmd[512];
    char version[VERSION_CAP + 1];
} cache_ent_t;

static cache_ent_t *load_cache(int *out_n) {
    *out_n = 0;
    char path[1024];
    if (!todoforai_path(path, sizeof(path), "tools_cache.json")) return NULL;
    size_t len = 0;
    char *buf = read_file(path, CACHE_FILE_CAP, &len);
    if (!buf) return NULL;
    cache_ent_t *ents = calloc(CACHE_MAX, sizeof(*ents));
    if (!ents) { free(buf); return NULL; }
    int n = 0;
    size_t pos = 0;
    const char *k, *v; size_t kl, vl; json_type_t vt;
    while (n < CACHE_MAX && json_obj_iter(buf, len, &pos, &k, &kl, &v, &vl, &vt)) {
        if (vt != JT_OBJ) continue;
        cache_ent_t *c = &ents[n];
        if (json_unescape_span(k, kl, c->key, sizeof(c->key)) <= 0) continue;
        size_t dl;
        if (!json_get_str_decoded(v, vl, "fp",   c->fp,   sizeof(c->fp),   &dl)) continue;
        if (!json_get_str_decoded(v, vl, "vcmd", c->vcmd, sizeof(c->vcmd), &dl)) continue;
        if (!json_get_str_decoded(v, vl, "version", c->version, sizeof(c->version), &dl) || !c->version[0]) continue;
        n++;
    }
    free(buf);
    if (n == 0) { free(ents); return NULL; }
    *out_n = n;
    return ents;
}

static const cache_ent_t *cache_find(const cache_ent_t *ents, int n, const probe_t *p) {
    for (int i = 0; i < n; i++) {
        if (strcmp(ents[i].key, p->key) == 0 && strcmp(ents[i].fp, p->fp) == 0 &&
            strcmp(ents[i].vcmd, p->vcmd) == 0) return &ents[i];
    }
    return NULL;
}

// Rewrite the cache from this run's successful version probes. Failures are
// never cached: `python3 -c 'import x'` starts working after a pip install
// that leaves python3's fingerprint untouched. Best effort: any failure just
// means a re-probe next time.
static void save_cache(const probe_t *probes, int n) {
    char path[1024], tmp[1040];
    if (!todoforai_path(path, sizeof(path), "tools_cache.json")) return;
    char *buf = malloc(CACHE_FILE_CAP);
    if (!buf) return;
    size_t used = 0;
    int emitted = 0, ok = json_emit_raw(buf, CACHE_FILE_CAP, &used, "{", 1) == 0;
    for (int i = 0; ok && i < n; i++) {
        const probe_t *p = &probes[i];
        if (p->present != 1 || !p->cacheable || p->v_exit != 0 || !p->version_out[0]) continue;
        ok = (emitted == 0 || json_emit_raw(buf, CACHE_FILE_CAP, &used, ",", 1) == 0) &&
             json_emit_str(buf, CACHE_FILE_CAP, &used, p->key, -1) == 0 &&
             json_emit_raw(buf, CACHE_FILE_CAP, &used, ":{\"fp\":", 7) == 0 &&
             json_emit_str(buf, CACHE_FILE_CAP, &used, p->fp, -1) == 0 &&
             json_emit_raw(buf, CACHE_FILE_CAP, &used, ",\"vcmd\":", 8) == 0 &&
             json_emit_str(buf, CACHE_FILE_CAP, &used, p->vcmd, -1) == 0 &&
             json_emit_raw(buf, CACHE_FILE_CAP, &used, ",\"version\":", 11) == 0 &&
             json_emit_str(buf, CACHE_FILE_CAP, &used, p->version_out, -1) == 0 &&
             json_emit_raw(buf, CACHE_FILE_CAP, &used, "}", 1) == 0;
        emitted++;
    }
    ok = ok && json_emit_raw(buf, CACHE_FILE_CAP, &used, "}\n", 2) == 0;
    if (ok) {
        snprintf(tmp, sizeof(tmp), "%s.tmp", path);
        FILE *f = fopen(tmp, "wb");
        if (f) {
            ok = fwrite(buf, 1, used, f) == used;
            ok = (fclose(f) == 0) && ok;
#ifdef _WIN32
            if (ok) ok = MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING);
#else
            if (ok) ok = rename(tmp, path) == 0;
#endif
            if (!ok) remove(tmp);
        }
    }
    free(buf);
}

// ── Presence pass ───────────────────────────────────────────────────────────
// Most versionCmds are `<bin> --version ...`. One shell pass answers "is
// <bin> on PATH" for all of them at once (same shell + PATH the probes use,
// so it can't disagree with them), which turns the ~80 absent tools of a
// typical host from 80 spawns into zero. Present tools get their resolved
// path + `ls -ldL` line as a cache fingerprint. Names are plain tokens
// (custom_name_safe) and go unquoted; resolved paths are single-quoted
// (double quotes don't survive the Windows command line).
//
#define PRESENCE_TIMEOUT_MS 10000
#define PRESENCE_OUT_CAP    32768

// A versionCmd that starts with an interpreter (`node -p "...shopify..."`)
// really versions some other package: the interpreter's presence is still a
// valid precondition, but its fingerprint says nothing about that package,
// so such probes are never served from the cache.
static int is_interpreter(const char *bin) {
    static const char *const names[] = { "node", "bun", "deno", "python", "python3", "py", "ruby", "perl", "sh", "bash", NULL };
    for (int i = 0; names[i]; i++) if (strcmp(bin, names[i]) == 0) return 1;
    return 0;
}

static void probe_set_bin(probe_t *p) {
    p->present = -1;
    const char *src = p->synthetic ? p->key : p->vcmd;
    if (!p->have_v) return;
    // `a --version || b --version`: absence of `a` says nothing. Probe as-is.
    if (!p->synthetic && strstr(src, "||")) return;
    size_t n = strcspn(src, " \t|;&<>");
    if (n == 0 || n >= sizeof(p->bin)) return;
    memcpy(p->bin, src, n); p->bin[n] = '\0';
    if (!custom_name_safe(p->bin)) { p->bin[0] = '\0'; return; }
    p->present = 0;
    p->cacheable = !p->synthetic && !is_interpreter(p->bin);
}

static probe_t *probe_by_bin(probe_t *probes, int n, const char *name, size_t len) {
    for (int i = 0; i < n; i++) {
        if (probes[i].present == 0 && strlen(probes[i].bin) == len &&
            memcmp(probes[i].bin, name, len) == 0) return &probes[i];
    }
    return NULL;
}

// Two shell spawns total: pass 1 is fork-free (`command -v` is a builtin),
// pass 2 is one `ls` over every hit. A `$(...)` per name would cost ~30 ms
// each under MSYS and eat the whole win.
static void presence_scan(probe_t *probes, int n) {
    char *cmd = malloc(8192), *out = malloc(PRESENCE_OUT_CAP);
    if (!cmd || !out) goto unknown;
    size_t used = (size_t)snprintf(cmd, 8192, "set -f; IFS=; for n in");
    int any = 0;
    for (int i = 0; i < n; i++) {
        if (probes[i].present != 0) continue;
        int m = snprintf(cmd + used, 8192 - used, " %s", probes[i].bin);
        if (m < 0 || (size_t)m >= 8192 - used) goto unknown;
        used += (size_t)m; any = 1;
    }
    if (!any) goto done;
    int m = snprintf(cmd + used, 8192 - used,
        "; do printf '%%s\\t' $n; command -v $n 2>/dev/null || echo; done; echo END");
    if (m < 0 || (size_t)m >= 8192 - used) goto unknown;
    if (run_shell(cmd, PRESENCE_TIMEOUT_MS, out, PRESENCE_OUT_CAP) != 0) goto unknown;
    // run_shell drops output past its cap silently; a missing sentinel means
    // the tail (and every tool in it) went unseen — fall back to probing.
    size_t ol = strlen(out);
    if (ol < 3 || strcmp(out + ol - 3, "END") != 0 || (ol > 3 && out[ol - 4] != '\n')) goto unknown;

    int hits = 0;
    for (char *line = out; *line; ) {
        char *eol = strchr(line, '\n');
        size_t ll = eol ? (size_t)(eol - line) : strlen(line);
        char *t = memchr(line, '\t', ll);
        probe_t *p = t ? probe_by_bin(probes, n, line, (size_t)(t - line)) : NULL;
        size_t pl = t ? ll - (size_t)(t + 1 - line) : 0;
        if (p && pl > 0) {
            p->present = 1; hits++;
            // Path too long to fingerprint ⇒ known present, just not cacheable.
            if (pl < sizeof(p->fp) / 2) { memcpy(p->fp, t + 1, pl); p->fp[pl] = '\0'; }
            else p->cacheable = 0;
        }
        if (!eol) break;
        line = eol + 1;
    }
    if (!hits) goto done;

    // Pass 2: fingerprint the hits. A hit that gets no ls line (shell
    // builtin, oversized command, unreadable path) stays present but is
    // excluded from the cache — the path alone is not a safe key.
    used = (size_t)snprintf(cmd, 8192, "ls -ldL --");
    for (int i = 0; i < n; i++) {
        if (probes[i].present != 1 || !probes[i].cacheable) continue;
        if (used + 2 >= 8192) goto done;
        cmd[used++] = ' '; cmd[used++] = '\'';
        for (const char *c = probes[i].fp; *c; c++) {
            if (*c == '\'') { if (used + 4 >= 8192) goto done; memcpy(cmd + used, "'\\''", 4); used += 4; }
            else { if (used + 1 >= 8192) goto done; cmd[used++] = *c; }
        }
        if (used + 2 >= 8192) goto done;
        cmd[used++] = '\''; cmd[used] = '\0';
    }
    // ls exits nonzero if any operand failed but still lists the rest.
    if (run_shell(cmd, PRESENCE_TIMEOUT_MS, out, PRESENCE_OUT_CAP) < 0) goto done;
    for (char *line = out; *line; ) {
        char *eol = strchr(line, '\n');
        size_t ll = eol ? (size_t)(eol - line) : strlen(line);
        // ls line ends with the path we passed; several tools may share one.
        for (int i = 0; i < n; i++) {
            probe_t *p = &probes[i];
            if (p->present != 1 || !p->cacheable || strchr(p->fp, '\t')) continue;
            size_t pl = strlen(p->fp);
            if (ll <= pl || line[ll - pl - 1] != ' ' || memcmp(line + ll - pl, p->fp, pl) != 0) continue;
            if (pl + 1 + ll >= sizeof(p->fp)) continue;
            p->fp[pl] = '\t'; memcpy(p->fp + pl + 1, line, ll); p->fp[pl + 1 + ll] = '\0';
        }
        if (!eol) break;
        line = eol + 1;
    }
    for (int i = 0; i < n; i++)
        if (probes[i].present == 1 && !strchr(probes[i].fp, '\t')) probes[i].cacheable = 0;
    goto done;
unknown:
    for (int i = 0; i < n; i++) if (probes[i].present == 0) probes[i].present = -1;
done:
    free(cmd); free(out);
}

// Run versionCmd (unless presence/cache already answered it) + statusCmd.
// Pure: no shared state.
static void probe_run(probe_t *p) {
    p->s_exit = -1;
    if (p->present == 0) {
        p->v_exit = 1;
    } else if (p->present == 1 && p->synthetic) {
        // `command -v <name>` already ran: its answer is the path in fp.
        size_t pl = strcspn(p->fp, "\t");
        if (pl > VERSION_CAP) pl = VERSION_CAP;
        memcpy(p->version_out, p->fp, pl); p->version_out[pl] = '\0';
        p->v_exit = 0;
    } else if (!p->v_cached) {
        p->v_exit = -1;
        if (p->have_v) p->v_exit = run_shell(p->vcmd, VERSION_TIMEOUT_MS, p->version_out, sizeof(p->version_out));
    }
    p->installed = (p->have_v && p->v_exit == 0 && p->version_out[0] != '\0');
    // A versionCmd that never returned an exit status (v_exit < 0: deadline,
    // spawn failure, killed shell) is not evidence of absence — a real "not
    // installed" shell exit is 1/127, which is >= 0. presence_scan resolved
    // this binary on PATH. Heavy node CLIs cost ~2 s to print a version alone
    // and blow past VERSION_TIMEOUT_MS when 16 probe threads run at once, so a
    // just-installed tool would report as missing and the install would be
    // called a failure. Interpreters are excluded: `node` being present says
    // nothing about the package its versionCmd actually versions.
    if (!p->installed && p->present == 1 && p->v_exit < 0 && !is_interpreter(p->bin))
        p->installed = 1;
    // statusCmd only matters once installed (or as the sole installed-check
    // when there's no versionCmd); a known-absent tool's auth is never emitted.
    if (p->have_s && (p->installed || !p->have_v))
        p->s_exit = run_shell(p->scmd, STATUS_TIMEOUT_MS, p->status_out, sizeof(p->status_out));
    if (!p->have_v && p->have_s && p->s_exit == 0) p->installed = 1;
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
    // s_exit == -1 is our own failure to run the probe (deadline hit, spawn
    // error), not the tool's answer. Emitting `false` for it would label a
    // working CLI "signed out"; omitting the field leaves it "not checked",
    // which the backend merge keeps at its last known value.
    //
    // Only -1 qualifies. A probe that ran and died on a signal still exits
    // through the shell as 128+signo (SIGABRT = 134), which is a real, if
    // unhappy, answer from the tool and is reported as such.
    if (p->installed && p->have_s && p->s_exit >= 0) {
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

// Shared job queue: workers pop the next index until exhausted.
typedef struct {
    probe_t *probes;
    int      n;
    int      next;
#ifdef _WIN32
    CRITICAL_SECTION mu;
#else
    pthread_mutex_t mu;
#endif
} job_pool_t;

static void worker_drain(job_pool_t *jp) {
    for (;;) {
#ifdef _WIN32
        EnterCriticalSection(&jp->mu);
        int i = jp->next < jp->n ? jp->next++ : -1;
        LeaveCriticalSection(&jp->mu);
#else
        pthread_mutex_lock(&jp->mu);
        int i = jp->next < jp->n ? jp->next++ : -1;
        pthread_mutex_unlock(&jp->mu);
#endif
        if (i < 0) return;
        probe_run(&jp->probes[i]);
    }
}

#ifdef _WIN32
static unsigned __stdcall worker_main(void *arg) { worker_drain(arg); return 0; }
#else
static void *worker_main(void *arg) { worker_drain(arg); return NULL; }
#endif

// Run every probe on a pool of up to PARALLEL_WORKERS threads. Thread
// creation failures are absorbed: the calling thread drains what's left.
static void run_probes(probe_t *probes, int n) {
    int nworkers = n < PARALLEL_WORKERS ? n : PARALLEL_WORKERS;
    if (nworkers <= 1) {
        for (int i = 0; i < n; i++) probe_run(&probes[i]);
        return;
    }
    job_pool_t jp = { .probes = probes, .n = n, .next = 0 };
    int started = 0;
#ifdef _WIN32
    InitializeCriticalSection(&jp.mu);
    HANDLE tids[PARALLEL_WORKERS];
    for (int i = 0; i < nworkers; i++) {
        uintptr_t h = _beginthreadex(NULL, 0, worker_main, &jp, 0, NULL);
        if (h) tids[started++] = (HANDLE)h;
    }
    if (started < nworkers) worker_drain(&jp);
    if (started > 0) WaitForMultipleObjects((DWORD)started, tids, TRUE, INFINITE);
    for (int i = 0; i < started; i++) CloseHandle(tids[i]);
    DeleteCriticalSection(&jp.mu);
#else
    pthread_mutex_init(&jp.mu, NULL);
    pthread_t tids[PARALLEL_WORKERS];
    for (int i = 0; i < nworkers; i++) {
        if (pthread_create(&tids[started], NULL, worker_main, &jp) == 0) started++;
    }
    if (started < nworkers) worker_drain(&jp);
    for (int i = 0; i < started; i++) pthread_join(tids[i], NULL);
    pthread_mutex_destroy(&jp.mu);
#endif
}

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
    win_shell_resolve();
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
#endif
    for (int i = 0; i < n; i++) probe_set_bin(&probes[i]);
    presence_scan(probes, n);
    int n_cache = 0;
    cache_ent_t *cache = load_cache(&n_cache);
    for (int i = 0; i < n; i++) {
        probe_t *p = &probes[i];
        if (p->present != 1 || !p->cacheable) continue;
        const cache_ent_t *c = cache_find(cache, n_cache, p);
        if (!c) continue;
        snprintf(p->version_out, sizeof(p->version_out), "%s", c->version);
        p->v_exit = 0;
        p->v_cached = 1;
    }
    free(cache);
    run_probes(probes, n);
    save_cache(probes, n);

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
            // A probe we failed to run (s_exit -1) has no answer to count.
            if (p->installed && p->have_s && p->s_exit >= 0) {
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

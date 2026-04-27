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

    long dl;
    if (vl > 0 && vl < vcmd_cap * 2) {
        dl = b64_decode(t1 + 1, vl, (uint8_t *)vcmd);
        if (dl > 0 && (size_t)dl < vcmd_cap) { vcmd[dl] = '\0'; *have_v = 1; }
    }
    if (sl > 0 && sl < scmd_cap * 2) {
        dl = b64_decode(t2 + 1, sl, (uint8_t *)scmd);
        if (dl > 0 && (size_t)dl < scmd_cap) { scmd[dl] = '\0'; *have_s = 1; }
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

    if (!first) { if (*used + 1 >= out_cap) return -1; out[(*used)++] = ','; }
    if (json_append_quoted(out, out_cap, used, key) != 0) return -1;
    #define A(lit) do { size_t _l = sizeof(lit) - 1; \
        if (*used + _l >= out_cap) return -1; \
        memcpy(out + *used, (lit), _l); *used += _l; } while (0)
    A(":{\"installed\":");
    if (installed) A("true"); else A("false");
    if (installed && have_v && v_exit == 0 && version_out[0] != '\0') {
        if (strlen(version_out) > VERSION_CAP) version_out[VERSION_CAP] = '\0';
        A(",\"version\":");
        if (json_append_quoted(out, out_cap, used, version_out) != 0) return -1;
    }
    if (installed && have_s) {
        A(",\"authenticated\":");
        if (authed) A("true"); else A("false");
        if (status_out[0] != '\0') {
            A(",\"statusOutput\":");
            if (json_append_quoted(out, out_cap, used, status_out) != 0) return -1;
        }
    }
    A("}");
    #undef A
    return 0;
}

int bridge_scan_tools(const char *entries, size_t entries_len,
                      char *out, size_t out_cap) {
    size_t used = 0;
    APPEND_LIT("{\"type\":\"installed_tools\",\"data\":{");

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

    APPEND_LIT("}}");
    if (used >= out_cap) return -1;
    out[used] = '\0';
    return (int)used;
}

// ────────────────────────────────────────────────────────────────────────────
// Live PATH watcher (Linux/inotify only). Re-probes affected catalog entries
// when binaries appear/disappear in PATH, pushing delta `installed_tools`.
// On non-Linux: bridge_tools_watch_init is a no-op stub.
// ────────────────────────────────────────────────────────────────────────────

#ifdef __linux__
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <limits.h>

// Cached catalog entry (used both for binary→key lookup and re-probe).
typedef struct {
    char key[64];
    char vcmd[512];
    char scmd[512];
    int  have_v, have_s;
    char binary[64]; // first whitespace token of vcmd, or empty
} cat_entry_t;

typedef struct {
    cat_entry_t *entries;
    int          n;
    int          ifd;       // inotify fd
    int          tfd;       // debounce timerfd
    int          epfd;
    int          stop_efd;  // signals watcher thread to exit
    int          ready_efd; // signals main loop a delta is ready to drain
    pthread_t    thread;
    int          initialized;
    int          running;
    pthread_mutex_t  pending_mu;
    char            *pending_keys; // tab-separated set of catalog keys to re-probe
    size_t           pending_len, pending_cap;
    pthread_mutex_t  ready_mu;
    char            *ready_json;   // owned; non-NULL = drainable delta waiting
    size_t           ready_len;
} watcher_t;

static watcher_t W = { .ifd = -1, .tfd = -1, .epfd = -1, .stop_efd = -1, .ready_efd = -1 };

// Extract leading argv[0] token from a shell command (stop at space/tab/quote/redirect).
static void extract_binary(const char *cmd, char *out, size_t cap) {
    out[0] = '\0';
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    size_t n = 0;
    while (*cmd && *cmd != ' ' && *cmd != '\t' && *cmd != '|' &&
           *cmd != '<' && *cmd != '>' && *cmd != ';' && *cmd != '&' &&
           n + 1 < cap) {
        out[n++] = *cmd++;
    }
    out[n] = '\0';
    // Reject paths and shell-builtin-style invocations — only bare names map cleanly to PATH dirs.
    if (strchr(out, '/')) out[0] = '\0';
}

static void pending_add(const char *key) {
    pthread_mutex_lock(&W.pending_mu);
    size_t klen = strlen(key);
    // Skip if already present.
    const char *p = W.pending_keys;
    while (p && *p) {
        const char *t = strchr(p, '\t');
        size_t L = t ? (size_t)(t - p) : strlen(p);
        if (L == klen && memcmp(p, key, klen) == 0) {
            pthread_mutex_unlock(&W.pending_mu); return;
        }
        if (!t) break;
        p = t + 1;
    }
    if (W.pending_len + klen + 2 > W.pending_cap) {
        size_t nc = W.pending_cap ? W.pending_cap * 2 : 256;
        while (nc < W.pending_len + klen + 2) nc *= 2;
        W.pending_keys = realloc(W.pending_keys, nc);
        W.pending_cap = nc;
    }
    if (W.pending_len) W.pending_keys[W.pending_len++] = '\t';
    memcpy(W.pending_keys + W.pending_len, key, klen);
    W.pending_len += klen;
    W.pending_keys[W.pending_len] = '\0';
    pthread_mutex_unlock(&W.pending_mu);
}

// Arm the debounce timer (500ms after the most recent event).
static void arm_timer(void) {
    struct itimerspec it = { .it_value = { .tv_sec = 0, .tv_nsec = 500 * 1000 * 1000 } };
    timerfd_settime(W.tfd, 0, &it, NULL);
}

static void handle_inotify_events(void) {
    char buf[16 * 1024] __attribute__((aligned(8)));
    for (;;) {
        ssize_t n = read(W.ifd, buf, sizeof buf);
        if (n <= 0) return;
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            p += sizeof *ev + ev->len;
            if (!ev->len) continue;
            // Match this filename against any catalog binary.
            for (int i = 0; i < W.n; i++) {
                if (W.entries[i].binary[0] &&
                    strcmp(W.entries[i].binary, ev->name) == 0) {
                    pending_add(W.entries[i].key);
                }
            }
        }
        arm_timer();
    }
}

static void flush_pending(void) {
    pthread_mutex_lock(&W.pending_mu);
    char *keys = W.pending_keys;
    size_t klen = W.pending_len;
    W.pending_keys = NULL; W.pending_len = W.pending_cap = 0;
    pthread_mutex_unlock(&W.pending_mu);
    if (!keys || klen == 0) { free(keys); return; }

    enum { OUT_CAP_BYTES = 64 * 1024 };
    char *out = malloc(OUT_CAP_BYTES);
    if (!out) { free(keys); return; }
    const size_t out_cap = OUT_CAP_BYTES;
    size_t used = 0;
    static const char hdr[] = "{\"type\":\"installed_tools\",\"data\":{";
    memcpy(out + used, hdr, sizeof(hdr) - 1); used += sizeof(hdr) - 1;
    int first = 1;

    char *save, *tok = strtok_r(keys, "\t", &save);
    while (tok) {
        for (int i = 0; i < W.n; i++) {
            if (strcmp(W.entries[i].key, tok) != 0) continue;
            if (probe_and_append(W.entries[i].key,
                                 W.entries[i].vcmd, W.entries[i].have_v,
                                 W.entries[i].scmd, W.entries[i].have_s,
                                 first, out, out_cap, &used) == 0) {
                first = 0;
            }
            break;
        }
        tok = strtok_r(NULL, "\t", &save);
    }
    if (used + 3 < out_cap) { out[used++] = '}'; out[used++] = '}'; out[used] = '\0'; }
    free(keys);

    if (first || used >= out_cap) { free(out); return; } // nothing to publish

    // Publish: replace any prior unread delta (latest wins; backend merges anyway).
    pthread_mutex_lock(&W.ready_mu);
    free(W.ready_json);
    W.ready_json = out;
    W.ready_len  = used;
    pthread_mutex_unlock(&W.ready_mu);
    uint64_t one = 1; (void)!write(W.ready_efd, &one, sizeof one);
    fprintf(stderr, "tools: queued delta (%zu bytes)\n", used);
}

static void *watcher_thread(void *_) {
    (void)_;
    struct epoll_event evs[3];
    while (W.running) {
        int nev = epoll_wait(W.epfd, evs, 3, -1);
        if (nev < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < nev; i++) {
            int fd = evs[i].data.fd;
            if (fd == W.stop_efd) return NULL;
            if (fd == W.ifd) handle_inotify_events();
            else if (fd == W.tfd) {
                uint64_t exp; (void)!read(W.tfd, &exp, sizeof exp);
                flush_pending();
            }
        }
    }
    return NULL;
}

// Parse $PATH and inotify_add_watch each unique dir.
static int watch_path_dirs(int ifd) {
    const char *path = getenv("PATH");
    if (!path || !*path) return -1;
    char *dup = strdup(path);
    if (!dup) return -1;
    int added = 0;
    char *save, *dir = strtok_r(dup, ":", &save);
    while (dir) {
        if (*dir) {
            int wd = inotify_add_watch(ifd, dir,
                IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM |
                IN_ATTRIB | IN_ONLYDIR | IN_EXCL_UNLINK);
            if (wd >= 0) added++;
            // Missing dirs are normal in $PATH; don't treat as fatal.
        }
        dir = strtok_r(NULL, ":", &save);
    }
    free(dup);
    return added > 0 ? 0 : -1;
}

int bridge_tools_watch_init(const char *entries, size_t entries_len) {
    if (W.initialized) return 0;

    // Cache catalog into W.entries — only entries with a trackable PATH binary
    // (status-only entries can't be triggered by PATH events, so skip them).
    int cap = 16, n = 0;
    cat_entry_t *arr = calloc(cap, sizeof *arr);
    if (!arr) { fprintf(stderr, "tools: oom\n"); return -1; }
    const char *p = entries, *end = entries + entries_len;
    while (p < end) {
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;
        if (n == cap) {
            int nc = cap * 2;
            cat_entry_t *narr = realloc(arr, nc * sizeof *narr);
            if (!narr) { free(arr); return -1; }
            memset(narr + cap, 0, (nc - cap) * sizeof *narr);
            arr = narr; cap = nc;
        }
        cat_entry_t *e = &arr[n];
        if (parse_entry(p, (size_t)(line_end - p),
                        e->key, sizeof(e->key),
                        e->vcmd, sizeof(e->vcmd), &e->have_v,
                        e->scmd, sizeof(e->scmd), &e->have_s)) {
            if (e->have_v) extract_binary(e->vcmd, e->binary, sizeof(e->binary));
            if (e->binary[0]) n++;
        }
        p = line_end + 1;
    }
    W.entries = arr; W.n = n;

    pthread_mutex_init(&W.pending_mu, NULL);
    pthread_mutex_init(&W.ready_mu, NULL);

    W.ifd       = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    W.tfd       = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    W.epfd      = epoll_create1(EPOLL_CLOEXEC);
    W.stop_efd  = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    W.ready_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (W.ifd < 0 || W.tfd < 0 || W.epfd < 0 || W.stop_efd < 0 || W.ready_efd < 0) {
        fprintf(stderr, "tools: watcher init failed: %s\n", strerror(errno));
        W.initialized = 1; bridge_tools_watch_stop();
        return -1;
    }

    if (watch_path_dirs(W.ifd) < 0) {
        fprintf(stderr, "tools: failed to watch any PATH directory\n");
        W.initialized = 1; bridge_tools_watch_stop();
        return -1;
    }

    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = W.ifd;      epoll_ctl(W.epfd, EPOLL_CTL_ADD, W.ifd,      &ev);
    ev.data.fd = W.tfd;      epoll_ctl(W.epfd, EPOLL_CTL_ADD, W.tfd,      &ev);
    ev.data.fd = W.stop_efd; epoll_ctl(W.epfd, EPOLL_CTL_ADD, W.stop_efd, &ev);

    W.running = 1;
    W.initialized = 1;
    if (pthread_create(&W.thread, NULL, watcher_thread, NULL) != 0) {
        fprintf(stderr, "tools: pthread_create failed\n");
        W.running = 0;
        bridge_tools_watch_stop();
        return -1;
    }
    fprintf(stderr, "tools: live PATH watcher armed (%d entries)\n", n);
    return 0;
}

int bridge_tools_watch_eventfd(void) {
    return W.initialized ? W.ready_efd : -1;
}

int bridge_tools_watch_drain(char *out, size_t out_cap) {
    if (!W.initialized) return 0;
    // Consume the eventfd counter (level→edge).
    uint64_t v; (void)!read(W.ready_efd, &v, sizeof v);

    pthread_mutex_lock(&W.ready_mu);
    char *json = W.ready_json; size_t len = W.ready_len;
    W.ready_json = NULL; W.ready_len = 0;
    pthread_mutex_unlock(&W.ready_mu);

    if (!json) return 0;
    if (len + 1 > out_cap) { free(json); return -1; }
    memcpy(out, json, len); out[len] = '\0';
    free(json);
    return (int)len;
}

void bridge_tools_watch_stop(void) {
    if (!W.initialized) return;
    if (W.running) {
        W.running = 0;
        uint64_t one = 1; (void)!write(W.stop_efd, &one, sizeof one);
        pthread_join(W.thread, NULL);
    }
    if (W.ifd       >= 0) close(W.ifd);
    if (W.tfd       >= 0) close(W.tfd);
    if (W.epfd      >= 0) close(W.epfd);
    if (W.stop_efd  >= 0) close(W.stop_efd);
    if (W.ready_efd >= 0) close(W.ready_efd);
    free(W.entries); free(W.pending_keys); free(W.ready_json);
    pthread_mutex_destroy(&W.pending_mu);
    pthread_mutex_destroy(&W.ready_mu);
    memset(&W, 0, sizeof W);
    W.ifd = W.tfd = W.epfd = W.stop_efd = W.ready_efd = -1;
}

#else  // non-Linux: no live watcher.

int bridge_tools_watch_init(const char *entries, size_t entries_len) {
    (void)entries; (void)entries_len;
    return 0;
}
int bridge_tools_watch_eventfd(void) { return -1; }
int bridge_tools_watch_drain(char *out, size_t out_cap) { (void)out; (void)out_cap; return 0; }
void bridge_tools_watch_stop(void) {}

#endif

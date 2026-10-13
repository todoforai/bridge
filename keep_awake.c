// Keep-awake while tasks run. See keep_awake.h.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "keep_awake.h"
#include "json.h"
#include "policy.h"   // bridge_config_dir

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <direct.h>
#else
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/stat.h>
#  include <sys/syscall.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

// ── idle timer (pure) ──────────────────────────────────────────────────────

int keep_awake_want(keep_awake_timer_t *t, int enabled, int busy, int64_t now_ms) {
    if (!enabled) { t->held = 0; return 0; }
    if (busy) { t->last_busy_ms = now_ms; t->held = 1; }
    else if (t->held && now_ms - t->last_busy_ms >= KEEP_AWAKE_GRACE_MS) t->held = 0;
    return t->held;
}

// ── config.json ────────────────────────────────────────────────────────────

static int cfg_path(char *buf, size_t cap, char *dir, size_t dcap) {
    if (bridge_config_dir(dir, dcap) != 0) return -1;
    int w = snprintf(buf, cap, "%s/config.json", dir);
    return (w < 0 || (size_t)w >= cap) ? -1 : 0;
}

int keep_awake_load(void) {
    char dir[1024], path[1100], buf[4096];
    if (cfg_path(path, sizeof path, dir, sizeof dir) != 0) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    int v = 0;
    if (!json_validate_doc(buf, n) || !json_get_bool(buf, n, "keep_awake", &v)) {
        if (n) fprintf(stderr, "keep-awake: %s unreadable or no boolean \"keep_awake\" — treating as off\n", path);
        return 0;
    }
    return v;
}

int keep_awake_save(int enabled) {
    char dir[1024], path[1100], tmp[1120];
    if (cfg_path(path, sizeof path, dir, sizeof dir) != 0) return -1;
    for (char *q = dir + 1; ; q++) {      // mkdir -p
        int end = *q == '\0';
        if (!end && *q != '/' && *q != '\\') continue;
        char c = *q; *q = '\0';
#ifdef _WIN32
        _mkdir(dir);
#else
        mkdir(dir, 0700);
#endif
        *q = c;
        if (end) break;
    }
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
#ifdef _WIN32
    FILE *f = fopen(tmp, "wb");
#else
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (!f && fd >= 0) close(fd);
#endif
    if (!f) return -1;
    fprintf(f, "{\n  \"keep_awake\": %s\n}\n", enabled ? "true" : "false");
    if (fclose(f) != 0) return -1;
#ifdef _WIN32
    return MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
#else
    return rename(tmp, path);
#endif
}

// ── OS hold ────────────────────────────────────────────────────────────────

static struct {
    int loaded, enabled, prev_busy, failed;
    int64_t reload_ms;   // last config.json re-read while held
    keep_awake_timer_t timer;
#ifdef _WIN32
    int held;
#else
    pid_t pid;      // helper; 0 = none
    int   wfd;      // write end of the helper's stdin; closing it ends the hold
#endif
} g;

#ifdef _WIN32
static int os_held(void) { return g.held; }
static int os_acquire(void) {
    if (!SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)) return -1;
    g.held = 1; return 0;
}
static void os_release(void) { SetThreadExecutionState(ES_CONTINUOUS); g.held = 0; }
static void os_reap(void) {}
#else
static int os_held(void) { return g.pid > 0; }

static int os_acquire(void) {
    int p[2];
    if (pipe(p) != 0) return -1;
    fcntl(p[1], F_SETFD, FD_CLOEXEC);
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) {
        int nul = open("/dev/null", O_RDWR);
        dup2(p[0], 0);
        if (nul >= 0) { dup2(nul, 1); dup2(nul, 2); }
        // Never leak the WS socket / PTY masters into a long-lived helper.
#if defined(__linux__) && defined(SYS_close_range)
        if (syscall(SYS_close_range, 3, ~0U, 0) != 0)
#endif
        {
            long maxfd = sysconf(_SC_OPEN_MAX);
            if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
            for (int fd = 3; fd < maxfd; fd++) close(fd);
        }
        signal(SIGPIPE, SIG_DFL);
#ifdef __APPLE__
        // -i: PreventUserIdleSystemSleep. Not -d/-s: display sleep + lock stay.
        execl("/usr/bin/caffeinate", "caffeinate", "-i", "/bin/cat", (char *)NULL);
#else
        // sleep only (not idle): the idle inhibitor would keep some desktops
        // from blanking/locking the screen.
        execlp("systemd-inhibit", "systemd-inhibit", "--what=sleep", "--mode=block",
               "--who=TODOforAI bridge", "--why=TODOforAI task running", "cat", (char *)NULL);
#endif
        _exit(127);
    }
    close(p[0]);
    g.pid = pid; g.wfd = p[1];
    return 0;
}

// Helper died on its own (no logind, polkit said no, …): note it and retry
// on the next task rather than every tick.
static void os_reap(void) {
    if (g.pid <= 0) return;
    int st = 0;
    pid_t r;
    while ((r = waitpid(g.pid, &st, WNOHANG)) < 0 && errno == EINTR) {}
    if (r == 0) return;   // still running
    if (r > 0)
        fprintf(stderr, "keep-awake: helper exited (%s %d) — not holding; "
#ifdef __APPLE__
                        "is /usr/bin/caffeinate present?\n",
#else
                        "is systemd-inhibit/logind available to this user?\n",
#endif
                WIFEXITED(st) ? "status" : "signal", WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
    close(g.wfd);
    g.pid = 0; g.wfd = -1; g.failed = 1;
}

// SIGKILL, not TERM: the reap is then bounded (even a stopped helper dies),
// so the main loop never stalls. The inhibitor lives in the helper's logind
// fd / power assertion, which the kernel drops with the process; an orphaned
// `cat` grandchild sees EOF on the pipe we close and exits too.
static void os_release(void) {
    if (g.pid <= 0) return;
    close(g.wfd); g.wfd = -1;
    kill(g.pid, SIGKILL);
    while (waitpid(g.pid, NULL, 0) < 0 && errno == EINTR) {}
    g.pid = 0;
}
#endif

int keep_awake_enabled(void) { return g.enabled; }
int keep_awake_active(void)  { return os_held(); }

static void ensure_loaded(void) {
    if (!g.loaded) { g.loaded = 1; g.enabled = keep_awake_load(); }
}

static int apply(int busy, int64_t now_ms) {
    int was = os_held();
    os_reap();
    int want = keep_awake_want(&g.timer, g.enabled, busy, now_ms);
    if (want && !os_held() && !g.failed) {
        if (os_acquire() == 0) fprintf(stderr, "keep-awake: holding system sleep while tasks run\n");
        else { g.failed = 1; fprintf(stderr, "keep-awake: could not take the sleep hold\n"); }
    } else if (!want && os_held()) {
        os_release();
        fprintf(stderr, "keep-awake: released\n");
    }
    return was != os_held();
}

#define KEEP_AWAKE_RELOAD_MS 30000

int keep_awake_tick(int busy, int64_t now_ms) {
    ensure_loaded();
    int changed = 0;
    // Pick up `config keep-awake …` edits: on each new task (also gives a
    // failed helper another go), and every 30s while work runs — so `off`
    // ends a long task's hold too. Idle costs nothing.
    if ((busy && !g.prev_busy) || (busy && now_ms - g.reload_ms >= KEEP_AWAKE_RELOAD_MS)) {
        int en = keep_awake_load();
        changed = en != g.enabled;
        g.enabled = en;
        if (!g.prev_busy) g.failed = 0;
        g.reload_ms = now_ms;
    }
    g.prev_busy = busy;
    return apply(busy, now_ms) | changed;
}

int keep_awake_set(int enabled) {
    ensure_loaded();
    enabled = !!enabled;
    if (keep_awake_save(enabled) != 0)
        fprintf(stderr, "keep-awake: could not write config.json (%s)\n", strerror(errno));
    int changed = enabled != g.enabled;
    g.enabled = enabled;
    g.failed = 0;
    return changed;   // the hold itself follows on the next tick
}

int keep_awake_release(void) {
    int was = os_held();
    if (was) os_release();
    g.timer.held = 0;
    return was;
}

int keep_awake_state_json(char *out, unsigned cap) {
    ensure_loaded();
    int n = snprintf(out, cap, "{\"type\":\"keep_awake_state\",\"enabled\":%s,\"active\":%s}",
                     g.enabled ? "true" : "false", os_held() ? "true" : "false");
    return (n < 0 || (unsigned)n >= cap) ? -1 : n;
}

// ── CLI ────────────────────────────────────────────────────────────────────

int cmd_config(int argc, char **argv) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "keep-awake") == 0)) {
        printf("keep-awake: %s\n", keep_awake_load() ? "on" : "off");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "keep-awake") == 0 &&
        (strcmp(argv[2], "on") == 0 || strcmp(argv[2], "off") == 0)) {
        int on = strcmp(argv[2], "on") == 0;
        if (keep_awake_save(on) != 0) { fprintf(stderr, "error: cannot write config.json: %s\n", strerror(errno)); return 1; }
        printf("keep-awake: %s (a running bridge applies it from the next task)\n", on ? "on" : "off");
        return 0;
    }
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("Usage: todoforai-bridge config [keep-awake [on|off]]\n\n"
               "  keep-awake on|off  keep this computer from sleeping while agents run a task\n"
               "                     (released ~2 min after the last one). Display sleep and\n"
               "                     screen lock are untouched — lock your screen. Off by default.\n");
        return 0;
    }
    fprintf(stderr, "Usage: todoforai-bridge config [keep-awake [on|off]]\n");
    return 2;
}

// Pre-warmed one-shot shells — see pty_pool.h for the why.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "pty_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#  include <windows.h>
#endif

// Split-quoted so an echoing console (ConPTY/cmd) can't match its own input.
#define MARKER_CMD "printf '\\nSP''ARE_READY\\n'\n"
#define MARKER     "SPARE_READY"

typedef struct {
    bridge_pty_t pty;
    int64_t      spawned_ms;
    int          live;         // slot holds a spawned shell
    int          ready;        // marker seen: parked at prompt
    char         rbuf[128];    // pre-marker bytes (shell banner noise)
    size_t       rlen;
} spare_t;

static spare_t     g_spares[PTY_POOL_MAX];
static int         g_target = -1;          // -1 = init not run, 0 off
static const char *g_shell;
static char        g_init[256];
static size_t      g_init_len;

static void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts = { 0, (long)ms * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

static int64_t pool_now_ms(void) {
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static int  spare_spawn(spare_t *sp, int64_t now);
static void spare_poll_ready(spare_t *sp);
static void spare_drop(spare_t *sp);

void pty_pool_init(const char *shell, const char *init, size_t init_len) {
    g_shell = shell;
    if (init_len + sizeof MARKER_CMD > sizeof g_init) init_len = 0;  // never expected
    memcpy(g_init, init, init_len);
    memcpy(g_init + init_len, MARKER_CMD, sizeof MARKER_CMD - 1);
    g_init_len = init_len + sizeof MARKER_CMD - 1;
    memset(g_spares, 0, sizeof g_spares);

    const char *env = getenv("BRIDGE_SPARES");
    if (env && *env) {
        long n = strtol(env, NULL, 10);
        g_target = n < 0 ? 0 : n > PTY_POOL_MAX ? PTY_POOL_MAX : (int)n;
        fprintf(stderr, "pty pool: BRIDGE_SPARES=%d\n", g_target);
        return;
    }

    // Probe: one synchronous spawn, timed to the readiness marker. Done here
    // (startup, before the socket) rather than in the loop, whose 50 ms tick
    // would swamp a 1 ms spawn. The probe shell becomes the first spare.
    int64_t t0 = pool_now_ms();
    spare_t *sp = &g_spares[0];
    if (spare_spawn(sp, t0) != 0) { g_target = 0; return; }
    while (!sp->ready && pool_now_ms() - t0 < PTY_POOL_PROBE_CAP_MS) {
        spare_poll_ready(sp);
        if (!sp->ready) sleep_ms(1);
    }
    int64_t cost = pool_now_ms() - t0;
    g_target = sp->ready && cost > PTY_POOL_THRESHOLD_MS ? PTY_POOL_MAX : 0;
    fprintf(stderr, "pty pool: cold spawn %lld ms -> %s\n", (long long)cost, g_target ? "enabled" : "off");
    if (!g_target) spare_drop(sp);
}

int pty_pool_target(void)      { return g_target; }
int pty_pool_ready_count(void) {
    int n = 0;
    for (int i = 0; i < PTY_POOL_MAX; i++) n += g_spares[i].live && g_spares[i].ready;
    return n;
}

static void spare_drop(spare_t *sp) {
    if (sp->live) {
        bridge_pty_signal(&sp->pty, 9 /*SIGKILL*/);
        bridge_pty_close(&sp->pty);
    }
    memset(sp, 0, sizeof *sp);
}

static int spare_spawn(spare_t *sp, int64_t now) {
    memset(sp, 0, sizeof *sp);
    if (bridge_pty_spawn(&sp->pty, g_shell, NULL, /*no_echo=*/1) != 0) return -1;
    if (bridge_pty_write_all(&sp->pty, g_init, g_init_len) != 0) {
        bridge_pty_close(&sp->pty);
        return -1;
    }
    sp->live = 1;
    sp->spawned_ms = now;
    return 0;
}

// Read pending bytes, looking for the marker. Keeps only a tail so a chatty
// shell profile can't overflow; the marker itself is short.
static void spare_poll_ready(spare_t *sp) {
    for (;;) {
        if (sp->rlen > sizeof sp->rbuf / 2) {
            size_t keep = sizeof MARKER;
            memmove(sp->rbuf, sp->rbuf + sp->rlen - keep, keep);
            sp->rlen = keep;
        }
        long n = bridge_pty_read(&sp->pty, sp->rbuf + sp->rlen, sizeof sp->rbuf - sp->rlen);
        if (n <= 0) return;
        sp->rlen += (size_t)n;
        if (memmem(sp->rbuf, sp->rlen, MARKER, sizeof MARKER - 1)) {
            sp->ready = 1;
            sp->rlen = 0;
            // Drain the marker's trailing newline so the adopting RUN's
            // begin-drain sees only its own bytes.
            char sink[64];
            while (bridge_pty_read(&sp->pty, sink, sizeof sink) > 0) {}
            return;
        }
    }
}

int pty_pool_take(bridge_pty_t *out) {
    if (g_target <= 0) return 0;
    for (int i = 0; i < PTY_POOL_MAX; i++) {
        spare_t *sp = &g_spares[i];
        if (!sp->live || !sp->ready) continue;
        int code;
        if (bridge_pty_reap(&sp->pty, &code)) { spare_drop(sp); continue; }  // died at the prompt
        *out = sp->pty;
        memset(sp, 0, sizeof *sp);
        return 1;
    }
    return 0;
}

void pty_pool_service(int64_t now) {
    if (g_target <= 0) return;
    if (now == 0) now = pool_now_ms();

    int live = 0;
    for (int i = 0; i < PTY_POOL_MAX; i++) {
        spare_t *sp = &g_spares[i];
        if (!sp->live) continue;
        int code;
        if (bridge_pty_reap(&sp->pty, &code) || now - sp->spawned_ms > PTY_POOL_MAX_AGE_MS) {
            spare_drop(sp);
            continue;
        }
        if (!sp->ready) spare_poll_ready(sp);
        live++;
    }

    if (live >= g_target) return;
    for (int i = 0; i < PTY_POOL_MAX; i++) {
        if (g_spares[i].live) continue;
        if (spare_spawn(&g_spares[i], now) != 0) {
            // Spawn failure (fd/pty exhaustion): back off, the next tick
            // retries. Don't turn the pool off — a RUN's cold spawn will
            // report the real error to the agent.
            fprintf(stderr, "pty pool: spare spawn failed\n");
        }
        return;   // one per tick: spread the exec cost, never burst
    }
}

void pty_pool_shutdown(void) {
    for (int i = 0; i < PTY_POOL_MAX; i++) spare_drop(&g_spares[i]);
}

size_t pty_pool_cd_prefix(const char *cwd, char *out, size_t cap) {
    static const char head[] = "cd -- '";
    static const char tail[] = "' || exit 1; ";
    size_t n = 0;
    #define PUT(s, l) do { if (n + (l) >= cap) return 0; memcpy(out + n, (s), (l)); n += (l); } while (0)
    PUT(head, sizeof head - 1);
    for (const char *p = cwd; *p; p++) {
        if (*p == '\'') PUT("'\\''", 4);
        else PUT(p, 1);
    }
    PUT(tail, sizeof tail - 1);
    #undef PUT
    out[n] = '\0';
    return n;
}

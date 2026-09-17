// Pre-warmed PTY pool (pty_pool.c): a one-shot RUN adopts a ready spare,
// its cwd is honoured via the `cd` prefix, exit codes flow through, the pool
// refills, a dead spare is reaped, and adopted shells are torn down at
// STEP_DONE exactly like cold ones. Includes main.c like test_initdrain.
// Run: make test-pool

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int test_capture(const char *json, size_t len);

#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

static int  g_step_done, g_last_code, g_errors;
static char g_out[1 << 16]; static size_t g_out_len;

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    return test_capture((const char *)pt, pt_len);
}

static int test_capture(const char *json, size_t len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_get_str(json, len, "type", &type, &type_len)) return 0;
    if (type_len == 9 && !memcmp(type, "step_done", 9)) {
        g_step_done++;
        long c = -1; json_get_long(json, len, "exitCode", &c);
        g_last_code = (int)c;
        return 0;
    }
    if (type_len == 5 && !memcmp(type, "error", 5)) { g_errors++; return 0; }
    if (!(type_len == 6 && !memcmp(type, "output", 6))) return 0;
    const char *data = NULL; size_t data_len = 0;
    assert(json_get_str(json, len, "data", &data, &data_len));
    g_out_len += b64_decode(data, data_len, g_out + g_out_len, sizeof g_out - g_out_len);
    return 0;
}

static void send_run(edge_t *e, const char *cmd, const char *cwd) {
    static int seq = 0;
    char b64[4096];
    size_t bl = b64_encode((const uint8_t *)cmd, strlen(cmd), b64, sizeof b64);
    b64[bl] = '\0';
    char frame[8192];
    int n = snprintf(frame, sizeof frame,
        "{\"type\":\"run\",\"blockId\":\"run_%d\",\"cmdB64\":\"%s\",\"cwd\":\"%s\"}", ++seq, b64, cwd);
    assert(n > 0 && (size_t)n < sizeof frame);
    g_out_len = 0; g_out[0] = '\0';
    handle_command(e, frame, (size_t)n);
}

static int active_sessions(edge_t *e) {
    int n = 0;
    for (int i = 0; i < g_max_sessions; i++) n += e->sessions[i].active != 0;
    return n;
}
static int no_active(edge_t *e) { return active_sessions(e) == 0; }
static int pool_ready(edge_t *e) { (void)e; return pty_pool_ready_count() > 0; }
static int pool_full(edge_t *e) { (void)e; return pty_pool_ready_count() >= pty_pool_target(); }

static int pump_until(edge_t *e, int (*pred)(edge_t *), int ms) {
    int64_t end = monotonic_ms() + ms;
    while (monotonic_ms() < end) {
        if (pred(e)) return 1;
        struct pollfd pfd = { .fd = -1 };
        poll(&pfd, 0, 5);
        service_sessions(e);
        pty_pool_service(monotonic_ms());
    }
    return pred(e);
}

static int child_count(void) {
    char cmd[128];
    snprintf(cmd, sizeof cmd, "pgrep -P %d | wc -l", (int)getpid());
    FILE *f = popen(cmd, "r"); assert(f);
    int n = -1;
    if (fscanf(f, "%d", &n) != 1) n = -1;
    pclose(f);
    return n;
}

static edge_t *mk_edge(void) {
    edge_t *e = calloc(1, sizeof *e); assert(e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions); assert(e->sessions);
    e->noise.handshake_done = 1;
    snprintf(e->api_url, sizeof e->api_url, "http://test");
    return e;
}

#define CHECK(cond, ...) do { if (!(cond)) { fprintf(stderr, "FAIL: " __VA_ARGS__); fputc('\n', stderr); fails++; } \
                              else { fprintf(stderr, "ok: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

int main(void) {
    g_max_sessions = 8;
    int fails = 0;
    setenv("BRIDGE_SPARES", "2", 1);
    {
        char init_line[96];
        size_t in_n = build_init_line(init_line, sizeof init_line);
        pty_pool_init(DEFAULT_SHELL, init_line, in_n);
    }
    edge_t *e = mk_edge();
    int base_children = child_count();

    // Pool fills to target, one spawn per tick.
    CHECK(pump_until(e, pool_full, 3000) && pty_pool_ready_count() == 2, "pool filled to 2 (ready=%d)", pty_pool_ready_count());
    CHECK(child_count() == base_children + 2, "2 spare shells alive (children=%d base=%d)", child_count(), base_children);

    // Adopt: cwd honoured via cd prefix (quote in path exercised), exit code flows.
    char dir[] = "/tmp/pool_it's_XXXXXX";
    assert(mkdtemp(dir));
    // JSON-escape not needed: no quotes/backslashes JSON cares about… except the
    // apostrophe, which is fine in JSON. Good — it stresses the shell quoting.
    send_run(e, "pwd; exit 7", dir);
    CHECK(pump_until(e, no_active, 5000) && g_step_done == 1, "adopted run finished (done=%d)", g_step_done);
    CHECK(strstr(g_out, dir) != NULL, "adopted run pwd == cwd (out=%.*s)", (int)g_out_len, g_out);
    CHECK(g_last_code == 7, "adopted run exit code 7 (got %d)", g_last_code);
    CHECK(pty_pool_ready_count() <= 1, "one spare consumed (ready=%d)", pty_pool_ready_count());

    // Refill.
    CHECK(pump_until(e, pool_full, 3000), "pool refilled (ready=%d)", pty_pool_ready_count());
    CHECK(child_count() == base_children + 2, "adopted shell torn down at STEP_DONE, spares back (children=%d)", child_count());

    // Burst: 3 runs at once, only 2 spares → third goes cold; all complete.
    g_step_done = 0;
    send_run(e, "echo a", "/tmp");
    send_run(e, "echo b", "/tmp");
    send_run(e, "echo c", "/tmp");
    CHECK(pump_until(e, no_active, 5000) && g_step_done == 3, "burst of 3 completed (done=%d)", g_step_done);

    // Vanished cwd after validation isn't testable without a race; instead,
    // the `cd || exit 1` path itself: adopt with a cwd the shell can't enter.
    // (stat() passes for a dir with no +x bit for a non-root user.)
    if (geteuid() != 0) {
        char nox[] = "/tmp/pool_nox_XXXXXX";
        assert(mkdtemp(nox));
        chmod(nox, 0600);
        pump_until(e, pool_ready, 3000);
        g_step_done = 0; g_last_code = 0;
        send_run(e, "echo should-not-run", nox);
        CHECK(pump_until(e, no_active, 5000) && g_step_done == 1 && g_last_code != 0,
              "unenterable cwd → STEP_DONE code!=0 (done=%d code=%d)", g_step_done, g_last_code);
        CHECK(strstr(g_out, "should-not-run") == NULL, "command did not run in wrong cwd");
        chmod(nox, 0700); rmdir(nox);
    }

    // Dead spare is reaped and replaced.
    pump_until(e, pool_full, 3000);
    {
        char cmd[128];
        snprintf(cmd, sizeof cmd, "pkill -9 -P %d -x sh; pkill -9 -P %d -x zsh; pkill -9 -P %d -x bash",
                 (int)getpid(), (int)getpid(), (int)getpid());
        (void)system(cmd);
        int64_t t = monotonic_ms();
        while (monotonic_ms() - t < 200) { struct pollfd p = { .fd = -1 }; poll(&p, 0, 5); pty_pool_service(monotonic_ms()); }
        CHECK(pump_until(e, pool_full, 3000), "pool recovered after spares were killed (ready=%d)", pty_pool_ready_count());
        g_step_done = 0;
        send_run(e, "echo alive", "/tmp");
        CHECK(pump_until(e, no_active, 5000) && g_step_done == 1 && strstr(g_out, "alive"), "run after recovery ok");
    }

    // Shutdown leaves no children.
    pty_pool_shutdown();
    CHECK(child_count() == base_children, "shutdown reaps all spares (children=%d base=%d)", child_count(), base_children);
    CHECK(g_errors == 0, "no ERROR frames (%d)", g_errors);

    rmdir(dir);
    free(e->sessions); free(e);
    if (fails) fprintf(stderr, "\n%d check(s) failed\n", fails);
    else       fprintf(stderr, "\nall pool tests passed\n");
    return fails ? 1 : 0;
}

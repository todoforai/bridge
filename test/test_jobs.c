// Off-loop jobs: the point of jobs.c is that the event loop keeps ticking
// while a slow worker runs, so every assert here is about the PARENT staying
// responsive — not just about the result being correct.
//
// This binary doubles as its own worker: bridge_job_start re-executes it as
// `<self> __job <kind>`, exactly as the bridge re-executes itself.
//
// Build/run: make test-jobs

#define _POSIX_C_SOURCE 200809L

#include "../jobs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

// usleep() was dropped in POSIX.1-2008; nanosleep is the portable spelling.
static void sleep_ms(long ms) {
    struct timespec t = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

// ── Bodies (run in the worker process) ──────────────────────────────────────

// Kinds are opaque to jobs.c, so the test picks its own.
#define K_SLOW       11
#define K_ECHO       12
#define K_BIG        13
#define K_SILENT     14
#define K_TRUNCATED  15
#define K_HANG       16
#define K_SPAWNER    17

static int slow_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n;
    sleep_ms(400);                   // stand-in for a multi-second tool scan
    emit(ctx, "{\"a\":1}", 7);
    return emit(ctx, "{\"b\":2}", 7);
}

// Echoes the payload back, so a round-trip proves the stdin hand-off.
static int echo_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    if (n == 0) return emit(ctx, "{}", 2);
    // Large payloads come back as a length, to keep the frame cap out of it.
    if (n > BRIDGE_JOB_FRAME_MAX) {
        for (size_t i = 0; i < n; i++) if (p[i] != 'p') return -1;   // intact?
        char buf[64];
        int k = snprintf(buf, sizeof buf, "{\"len\":%zu}", n);
        return emit(ctx, buf, (size_t)k);
    }
    return emit(ctx, p, n);
}

#define BIG_FRAME  40000
#define BIG_COUNT  40
static int big_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n;
    char *buf = malloc(BIG_FRAME);
    if (!buf) return -1;
    memset(buf, 'x', BIG_FRAME);
    int rc = 0;
    for (int i = 0; i < BIG_COUNT && rc == 0; i++) rc = emit(ctx, buf, BIG_FRAME);
    free(buf);
    return rc;
}

static int silent_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n; (void)emit; (void)ctx;
    return 0;
}

// Emits, then dies without finishing — the shape of a crashed preview that
// sent chunks but never its terminal frame.
static int truncated_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n;
    emit(ctx, "{\"seq\":0}", 9);
    _exit(1);                        // no unwinding, no marker
}

static int hang_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n; (void)emit; (void)ctx;
    sleep(30);
    return 0;
}

// Spawns shells that outlive the body — proves cancellation sweeps the process
// group rather than orphaning them (a real scan has 16 probes in flight).
#define SPAWN_MARK "tfajobmark"
static int spawner_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n; (void)emit; (void)ctx;
    for (int i = 0; i < 3; i++)
        if (fork() == 0) {
            execl("/bin/sh", "sh", "-c", "sleep 30 #" SPAWN_MARK, (char *)NULL);
            _exit(127);
        }
    sleep(30);
    return 0;
}

static int run_worker(int kind) {
    switch (kind) {
        case K_SLOW:      return bridge_job_worker_main(slow_body);
        case K_ECHO:      return bridge_job_worker_main(echo_body);
        case K_BIG:       return bridge_job_worker_main(big_body);
        case K_SILENT:    return bridge_job_worker_main(silent_body);
        case K_TRUNCATED: return bridge_job_worker_main(truncated_body);
        case K_HANG:      return bridge_job_worker_main(hang_body);
        case K_SPAWNER:   return bridge_job_worker_main(spawner_body);
        default:          return 2;
    }
}

// ── Parent-side collectors ──────────────────────────────────────────────────

static int    frames, dones, oks, last_kind;
static int    fail_delivery_after;      // -1 = deliver everything
static size_t total_bytes;
static char   last[128], last_err[160];

static int on_frame(void *c, const bridge_job_t *j, const char *d, size_t l) {
    (void)c;
    if (fail_delivery_after >= 0 && frames >= fail_delivery_after) return -1;
    frames++; total_bytes += l; last_kind = j->kind;
    size_t k = l < sizeof last - 1 ? l : sizeof last - 1;
    memcpy(last, d, k); last[k] = '\0';
    return 0;
}

static void on_done(void *c, const bridge_job_t *j, int ok, const char *err) {
    (void)c; (void)j;
    dones++; oks += ok;
    snprintf(last_err, sizeof last_err, "%s", err ? err : "");
}

static void reset(void) {
    frames = dones = oks = last_kind = 0;
    fail_delivery_after = -1;
    total_bytes = 0; last[0] = last_err[0] = '\0';
}

// Pump until the job settles. Returns the number of ticks and reports the
// worst gap between ticks — a parked loop shows up as a huge gap.
static int pump(bridge_jobs_t *jobs, int budget_ms, int64_t *worst_gap) {
    int ticks = 0;
    int64_t t0 = now_ms(), prev = t0;
    *worst_gap = 0;
    while (dones == 0 && now_ms() - t0 < budget_ms) {
        bridge_jobs_poll(jobs, now_ms(), on_frame, on_done, NULL);
        int64_t n = now_ms();
        if (n - prev > *worst_gap) *worst_gap = n - prev;
        prev = n;
        ticks++;
        sleep_ms(5);
    }
    return ticks;
}

static int start(bridge_jobs_t *jobs, int kind, const char *pl, size_t pl_len,
                 int timeout_ms, const char *rid) {
    return bridge_job_start(jobs, kind, pl, pl_len, now_ms(), timeout_ms,
                            rid, strlen(rid), NULL, 0, NULL, 0);
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "__job") == 0) return run_worker(atoi(argv[2]));
    bridge_jobs_init_self(argv[0]);

    bridge_jobs_t jobs;
    memset(&jobs, 0, sizeof jobs);
    int64_t gap;

    // The whole point: a 400ms worker must not cost the loop a single tick.
    reset();
    int64_t t0 = now_ms();
    assert(start(&jobs, K_SLOW, "payload", 7, 5000, "r1") == 0);
    int64_t spawn_ms = now_ms() - t0;
    int ticks = pump(&jobs, 5000, &gap);
    assert(spawn_ms < 100);              // start returns immediately
    assert(ticks > 20);                  // loop stayed alive during the work
    assert(gap < 100);                   // and never parked
    assert(frames == 2 && oks == 1);
    printf("ok 1 loop keeps ticking (spawn=%lldms ticks=%d worst_gap=%lldms)\n",
           (long long)spawn_ms, ticks, (long long)gap);

    // Payload reaches the worker intact; kind survives the round trip.
    reset();
    assert(start(&jobs, K_ECHO, "{\"hello\":1}", 11, 5000, "r2") == 0);
    pump(&jobs, 5000, &gap);
    assert(strcmp(last, "{\"hello\":1}") == 0);
    assert(last_kind == K_ECHO && oks == 1);
    printf("ok 2 payload + kind round-trip\n");

    // A payload far past one pipe buffer: the parent must dribble it out
    // across ticks instead of blocking on a worker that isn't reading yet.
    reset();
    size_t big_pl = 512 * 1024;
    char *pl = malloc(big_pl);
    assert(pl);
    memset(pl, 'p', big_pl);
    t0 = now_ms();
    assert(start(&jobs, K_ECHO, pl, big_pl, 8000, "r2b") == 0);
    spawn_ms = now_ms() - t0;
    ticks = pump(&jobs, 8000, &gap);
    free(pl);
    char want[64];
    snprintf(want, sizeof want, "{\"len\":%zu}", big_pl);
    assert(oks == 1 && strcmp(last, want) == 0);
    assert(spawn_ms < 100 && gap < 100);
    printf("ok 3 512KB payload streams in without parking (spawn=%lldms worst_gap=%lldms)\n",
           (long long)spawn_ms, (long long)gap);

    // Many large frames: exercises partial reads and cross-tick reassembly.
    reset();
    assert(start(&jobs, K_BIG, "", 0, 8000, "r3") == 0);
    pump(&jobs, 8000, &gap);
    assert(frames == BIG_COUNT && total_bytes == (size_t)BIG_COUNT * BIG_FRAME);
    assert(oks == 1 && gap < 100);
    printf("ok 4 %d large frames reassembled (%zuKB, worst_gap=%lldms)\n",
           frames, total_bytes / 1024, (long long)gap);

    // A worker that finishes without saying anything is a completed job with
    // no frames — the caller decides whether that's useful.
    reset();
    assert(start(&jobs, K_SILENT, "", 0, 3000, "r4") == 0);
    pump(&jobs, 3000, &gap);
    assert(dones == 1 && oks == 1 && frames == 0);
    printf("ok 5 silent-but-complete worker reports no frames\n");

    // The case a frame count can't catch: chunks arrived, then the worker died
    // before ending the stream. Must fail, or the backend waits for a terminal
    // frame that will never come.
    reset();
    assert(start(&jobs, K_TRUNCATED, "", 0, 3000, "r5") == 0);
    pump(&jobs, 3000, &gap);
    assert(frames == 1 && oks == 0 && last_err[0] != '\0');
    printf("ok 6 unterminated stream fails despite delivered frames (%s)\n", last_err);

    // A frame the transport refused must fail the job, not count as sent.
    reset();
    fail_delivery_after = 0;
    assert(start(&jobs, K_ECHO, "{\"x\":1}", 7, 3000, "r6") == 0);
    pump(&jobs, 3000, &gap);
    assert(frames == 0 && oks == 0 && strstr(last_err, "deliver"));
    printf("ok 7 undelivered frame fails the job (%s)\n", last_err);

    // A wedged worker is killed by its deadline, not left to hang.
    reset();
    t0 = now_ms();
    assert(start(&jobs, K_HANG, "", 0, 300, "r7") == 0);
    pump(&jobs, 4000, &gap);
    assert(oks == 0 && strstr(last_err, "timed out"));
    assert(now_ms() - t0 < 2000);        // enforced near the deadline
    printf("ok 8 deadline reaps a wedged worker (%lldms)\n", (long long)(now_ms() - t0));

    // Cancelling a job must take its subprocesses with it: a scan worker that
    // dies alone leaves nobody to enforce the probes' own timeouts.
    reset();
    assert(start(&jobs, K_SPAWNER, "", 0, 500, "r8") == 0);
    pump(&jobs, 4000, &gap);
    sleep_ms(300);
    // The [t] keeps the pattern from matching pgrep's own command line.
    assert(system("pgrep -f '[t]fajobmark' >/dev/null 2>&1") != 0);
    printf("ok 9 cancellation sweeps the whole process group\n");

    // Slots are bounded, so a flood of requests can't spawn without limit.
    reset();
    int started = 0;
    for (int i = 0; i < BRIDGE_JOB_MAX + 3; i++)
        if (start(&jobs, K_HANG, "", 0, 9000, "rx") == 0) started++;
    assert(started == BRIDGE_JOB_MAX);
    assert(bridge_jobs_count(&jobs, K_HANG) == BRIDGE_JOB_MAX);
    printf("ok 10 slot cap holds at %d\n", BRIDGE_JOB_MAX);

    // Teardown kills and reaps everything — no orphans across a reconnect.
    bridge_jobs_shutdown(&jobs);
    assert(bridge_jobs_count(&jobs, K_HANG) == 0);
    assert(waitpid(-1, NULL, WNOHANG) == -1);   // nothing left to reap
    printf("ok 11 shutdown reaps every worker\n");

    // Re-exec's sharp edge: a binary that forgets to dispatch on `__job`
    // would restart its normal startup path, spawn a job, and recurse — a
    // fork bomb. The marker in the worker's environment must stop it dead.
    {
        char cmd[1200];
        snprintf(cmd, sizeof cmd,
                 "TODOFORAI_JOB_WORKER=1 %s >/dev/null 2>&1", argv[0]);
        int rc = system(cmd);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) == 70);
        printf("ok 12 undispatched worker refuses to run (exit %d)\n", WEXITSTATUS(rc));
    }

    printf("all job tests passed\n");
    return 0;
}

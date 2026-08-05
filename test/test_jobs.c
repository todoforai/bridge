// Off-loop jobs: the point of jobs.c is that the event loop keeps ticking
// while a slow worker runs, so every assert here is about the PARENT staying
// responsive — not just about the result being correct.
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

// ── Bodies (run in the worker) ──────────────────────────────────────────────

static int slow_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n;
    sleep_ms(400);                   // stand-in for a multi-second tool scan
    emit(ctx, "{\"a\":1}", 7);
    return emit(ctx, "{\"b\":2}", 7);
}

static int echo_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
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
    return -1;
}

static int hang_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)n; (void)emit; (void)ctx;
    sleep(30);
    return 0;
}

// Forks a shell that outlives the body — proves cancellation sweeps the
// process group rather than orphaning a job's subprocesses (a real scan has
// up to 16 of these in flight).
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

int main(void) {
    bridge_jobs_t jobs;
    memset(&jobs, 0, sizeof jobs);
    int64_t gap;

    // The whole point: a 400ms worker must not cost the loop a single tick.
    reset();
    int64_t t0 = now_ms();
    assert(bridge_job_start(&jobs, BRIDGE_JOB_SCAN, "payload", 7, slow_body,
                            now_ms(), 5000, "r1", 2, "a1", 2, NULL, 0) == 0);
    int64_t spawn_ms = now_ms() - t0;
    int ticks = pump(&jobs, 5000, &gap);
    assert(spawn_ms < 100);              // start returns immediately
    assert(ticks > 20);                  // loop stayed alive during the work
    assert(gap < 100);                   // and never parked
    assert(frames == 2 && oks == 1);
    printf("ok 1 loop keeps ticking (spawn=%lldms ticks=%d worst_gap=%lldms)\n",
           (long long)spawn_ms, ticks, (long long)gap);

    // Payload crosses into the worker intact, kind survives the round trip.
    reset();
    assert(bridge_job_start(&jobs, BRIDGE_JOB_PREVIEW, "{\"hello\":1}", 11, echo_body,
                            now_ms(), 5000, "r2", 2, NULL, 0, NULL, 0) == 0);
    pump(&jobs, 3000, &gap);
    assert(strcmp(last, "{\"hello\":1}") == 0);
    assert(last_kind == BRIDGE_JOB_PREVIEW && oks == 1);
    printf("ok 2 payload + kind round-trip\n");

    // Many large frames: exercises partial reads and cross-tick reassembly.
    reset();
    ticks = 0;
    assert(bridge_job_start(&jobs, BRIDGE_JOB_PREVIEW, "", 0, big_body,
                            now_ms(), 8000, "r3", 2, NULL, 0, NULL, 0) == 0);
    ticks = pump(&jobs, 8000, &gap);
    assert(frames == BIG_COUNT && total_bytes == (size_t)BIG_COUNT * BIG_FRAME);
    assert(oks == 1 && gap < 100);
    printf("ok 3 %d large frames reassembled (%zuKB, worst_gap=%lldms)\n",
           frames, total_bytes / 1024, (long long)gap);

    // A worker that finishes without saying anything is a completed job with
    // no frames — the caller decides whether that's useful.
    reset();
    assert(bridge_job_start(&jobs, BRIDGE_JOB_SCAN, "", 0, silent_body,
                            now_ms(), 3000, "r4", 2, NULL, 0, NULL, 0) == 0);
    pump(&jobs, 3000, &gap);
    assert(dones == 1 && oks == 1 && frames == 0);
    printf("ok 4 silent-but-complete worker reports no frames\n");

    // The case a frame count can't catch: chunks arrived, then the worker died
    // before ending the stream. Must fail, or the backend waits for a terminal
    // frame that will never come.
    reset();
    assert(bridge_job_start(&jobs, BRIDGE_JOB_PREVIEW, "", 0, truncated_body,
                            now_ms(), 3000, "r4b", 3, NULL, 0, NULL, 0) == 0);
    pump(&jobs, 3000, &gap);
    assert(frames == 1 && oks == 0 && last_err[0] != '\0');
    printf("ok 5 unterminated stream fails despite delivered frames (%s)\n", last_err);

    // A frame the transport refused must fail the job, not count as sent.
    reset();
    fail_delivery_after = 0;
    assert(bridge_job_start(&jobs, BRIDGE_JOB_PREVIEW, "{\"x\":1}", 7, echo_body,
                            now_ms(), 3000, "r4c", 3, NULL, 0, NULL, 0) == 0);
    pump(&jobs, 3000, &gap);
    assert(frames == 0 && oks == 0 && strstr(last_err, "deliver"));
    printf("ok 6 undelivered frame fails the job (%s)\n", last_err);

    // A wedged worker is killed by its deadline, not left to hang.
    reset();
    t0 = now_ms();
    assert(bridge_job_start(&jobs, BRIDGE_JOB_SCAN, "", 0, hang_body,
                            now_ms(), 300, "r5", 2, NULL, 0, NULL, 0) == 0);
    pump(&jobs, 4000, &gap);
    assert(oks == 0 && strstr(last_err, "timed out"));
    assert(now_ms() - t0 < 2000);        // enforced near the deadline
    printf("ok 7 deadline reaps a wedged worker (%lldms)\n", (long long)(now_ms() - t0));

    // Cancelling a job must take its subprocesses with it: a scan supervisor
    // that dies alone leaves nobody to enforce the probes' own timeouts.
    reset();
    assert(bridge_job_start(&jobs, BRIDGE_JOB_SCAN, "", 0, spawner_body,
                            now_ms(), 400, "r5b", 3, NULL, 0, NULL, 0) == 0);
    pump(&jobs, 4000, &gap);
    sleep_ms(200);
    // The [t] keeps the pattern from matching pgrep's own command line.
    assert(system("pgrep -f '[t]fajobmark' >/dev/null 2>&1") != 0);
    printf("ok 8 cancellation sweeps the whole process group\n");

    // Slots are bounded, so a flood of requests can't fork without limit.
    reset();
    int started = 0;
    for (int i = 0; i < BRIDGE_JOB_MAX + 3; i++)
        if (bridge_job_start(&jobs, BRIDGE_JOB_PREVIEW, "", 0, hang_body,
                             now_ms(), 9000, "rx", 2, NULL, 0, NULL, 0) == 0) started++;
    assert(started == BRIDGE_JOB_MAX);
    assert(bridge_jobs_count(&jobs, BRIDGE_JOB_PREVIEW) == BRIDGE_JOB_MAX);
    printf("ok 9 slot cap holds at %d\n", BRIDGE_JOB_MAX);

    // Teardown kills and reaps everything — no orphans across a reconnect.
    bridge_jobs_shutdown(&jobs);
    assert(bridge_jobs_count(&jobs, BRIDGE_JOB_PREVIEW) == 0);
    assert(waitpid(-1, NULL, WNOHANG) == -1);   // nothing left to reap
    printf("ok 10 shutdown reaps every worker\n");

    printf("all job tests passed\n");
    return 0;
}

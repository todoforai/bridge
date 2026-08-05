// See jobs.h for the model. Wire format on the pipe: repeated
// [u32 little-endian length][length bytes of JSON], then a zero-length frame
// as the end-of-stream marker. A bare EOF without that marker means the
// worker died mid-stream. A length above BRIDGE_JOB_FRAME_MAX means a corrupt
// stream and fails the job.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "jobs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

// ── Worker side ─────────────────────────────────────────────────────────────

typedef struct {
#ifdef _WIN32
    HANDLE w;
#else
    int w;
#endif
} worker_sink_t;

// Write exactly n bytes; short writes are normal on a pipe.
#ifdef _WIN32
static int sink_write_all(HANDLE w, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        DWORD wrote = 0;
        if (!WriteFile(w, p, (DWORD)n, &wrote, NULL) || wrote == 0) return -1;
        p += wrote; n -= wrote;
    }
    return 0;
}
#else
static int sink_write_all(int w, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t k = write(w, p, n);
        if (k < 0) { if (errno == EINTR) continue; return -1; }
        if (k == 0) return -1;
        p += k; n -= (size_t)k;
    }
    return 0;
}
#endif

static int sink_frame(worker_sink_t *s, const char *data, size_t len) {
    uint8_t hdr[4] = { (uint8_t)len, (uint8_t)(len >> 8),
                       (uint8_t)(len >> 16), (uint8_t)(len >> 24) };
    if (sink_write_all(s->w, hdr, 4) != 0) return -1;
    return len && sink_write_all(s->w, data, len) != 0 ? -1 : 0;
}

// bridge_job_emit_fn passed to the body. A failing write means the parent
// closed the pipe (cancel/teardown) — return -1 so the body unwinds.
static int worker_emit(void *ctx, const char *data, size_t len) {
    if (len == 0 || len > BRIDGE_JOB_FRAME_MAX) return -1;
    return sink_frame(ctx, data, len);
}

// Run the body and, only if it completed, write the end-of-stream marker.
static void worker_run(bridge_job_body_fn body,
                       const char *payload, size_t payload_len,
                       worker_sink_t *sink) {
    if (body(payload, payload_len, worker_emit, sink) == 0)
        (void)sink_frame(sink, NULL, 0);
}

#ifdef _WIN32
typedef struct {
    HANDLE             w;
    char              *payload;
    size_t             payload_len;
    bridge_job_body_fn body;
} win_worker_t;

static DWORD WINAPI win_worker_main(LPVOID arg) {
    win_worker_t *a = arg;
    worker_sink_t sink = { .w = a->w };
    worker_run(a->body, a->payload, a->payload_len, &sink);
    CloseHandle(a->w);          // EOF for the parent
    free(a->payload);
    free(a);
    return 0;
}
#endif

// ── Parent side ─────────────────────────────────────────────────────────────

static void job_close(bridge_job_t *j) {
#ifdef _WIN32
    if (j->rd) { CloseHandle((HANDLE)j->rd); j->rd = NULL; }
    // The thread owns its payload and exits on the next failed write; we
    // never TerminateThread (it would leak the pipe handle and the payload).
    if (j->th) { CloseHandle((HANDLE)j->th); j->th = NULL; }
#else
    if (j->rfd >= 0) { close(j->rfd); j->rfd = -1; }
    if (j->pid > 0) {
        // Kill the whole group, not just the supervisor: a tool scan has up to
        // 16 probe shells in flight, and orphaning them would leave nobody to
        // enforce their per-probe timeouts. The child setpgid()s itself, and
        // we repeat it here so the group exists no matter who won the race.
        setpgid(j->pid, j->pid);
        if (kill(-j->pid, SIGKILL) != 0) kill(j->pid, SIGKILL);
        // Targeted reap: the PTY code waits on its own pids, so no wildcard.
        while (waitpid(j->pid, NULL, 0) < 0 && errno == EINTR) {}
        j->pid = 0;
    }
#endif
    free(j->acc);
    j->acc = NULL; j->acc_len = j->acc_cap = 0;
    j->active = 0;
}

int bridge_jobs_count(const bridge_jobs_t *p, int kind) {
    int n = 0;
    for (int i = 0; i < BRIDGE_JOB_MAX; i++)
        if (p->slots[i].active && p->slots[i].kind == kind) n++;
    return n;
}

static void job_set_id(char *dst, size_t *dst_len, size_t cap,
                       const char *src, size_t len) {
    if (!src || len == 0 || len >= cap) { *dst_len = 0; dst[0] = '\0'; return; }
    memcpy(dst, src, len); dst[len] = '\0'; *dst_len = len;
}

int bridge_job_start(bridge_jobs_t *p, int kind,
                     const char *payload, size_t payload_len,
                     bridge_job_body_fn body,
                     int64_t now_ms, int timeout_ms,
                     const char *rid, size_t rid_len,
                     const char *aid, size_t aid_len,
                     const char *eid, size_t eid_len) {
    bridge_job_t *j = NULL;
    for (int i = 0; i < BRIDGE_JOB_MAX; i++)
        if (!p->slots[i].active) { j = &p->slots[i]; break; }
    if (!j) return -1;

    memset(j, 0, sizeof(*j));
    j->kind = kind;
    job_set_id(j->rid, &j->rid_len, sizeof j->rid, rid, rid_len);
    job_set_id(j->aid, &j->aid_len, sizeof j->aid, aid, aid_len);
    job_set_id(j->eid, &j->eid_len, sizeof j->eid, eid, eid_len);

#ifdef _WIN32
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, NULL, 0)) return -1;
    win_worker_t *a = calloc(1, sizeof *a);
    char *copy = malloc(payload_len ? payload_len : 1);
    if (!a || !copy) { free(a); free(copy); CloseHandle(rd); CloseHandle(wr); return -1; }
    if (payload_len) memcpy(copy, payload, payload_len);
    a->w = wr; a->payload = copy; a->payload_len = payload_len; a->body = body;
    HANDLE th = CreateThread(NULL, 0, win_worker_main, a, 0, NULL);
    if (!th) { free(copy); free(a); CloseHandle(rd); CloseHandle(wr); return -1; }
    j->rd = rd; j->th = th;
#else
    int fds[2];
    if (pipe(fds) != 0) return -1;
    // CLOEXEC on both ends: the worker shells out (tool probes), and an
    // inherited write end would hold the pipe open past the body's exit,
    // stalling our EOF until the last grandchild died.
    if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(fds[0]); close(fds[1]); return -1;
    }
    // Checked, because a blocking read end would park the event loop — the
    // one thing this whole module exists to prevent.
    int fl = fcntl(fds[0], F_GETFL, 0);
    if (fl < 0 || fcntl(fds[0], F_SETFL, fl | O_NONBLOCK) != 0) {
        close(fds[0]); close(fds[1]); return -1;
    }

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid == 0) {
        close(fds[0]);
        // Own process group so cancellation can sweep the probe subprocesses
        // this body spawns (see job_close).
        setpgid(0, 0);
        // A dead parent must not kill us via SIGPIPE — the failing write is
        // the cancel signal the body already handles.
        signal(SIGPIPE, SIG_IGN);
        worker_sink_t sink = { .w = fds[1] };
        worker_run(body, payload, payload_len, &sink);
        close(fds[1]);
        _exit(0);
    }
    close(fds[1]);
    setpgid(pid, pid);          // race-free: both sides do it
    j->rfd = fds[0];
    j->pid = pid;
#endif

    j->active = 1;
    j->deadline_ms = timeout_ms > 0 ? now_ms + timeout_ms : 0;
    return 0;
}

// Parse as many complete frames as `acc` holds, handing each to on_frame.
// `err` is set when the stream is corrupt or a frame could not be delivered.
static void job_drain_acc(bridge_job_t *j, bridge_job_frame_cb on_frame,
                          void *ctx, const char **err) {
    size_t off = 0;
    while (j->acc_len - off >= 4 && !*err) {
        const uint8_t *h = j->acc + off;
        size_t len = (size_t)h[0] | ((size_t)h[1] << 8) |
                     ((size_t)h[2] << 16) | ((size_t)h[3] << 24);
        if (len > BRIDGE_JOB_FRAME_MAX) { *err = "worker sent an oversized frame"; break; }
        if (len == 0) { j->clean = 1; off += 4; break; }   // end-of-stream
        if (j->acc_len - off - 4 < len) break;             // incomplete tail
        // Count only what actually reached the backend, so a job can never
        // report success for frames the transport dropped.
        if (on_frame && on_frame(ctx, j, (const char *)(h + 4), len) != 0) {
            *err = "failed to deliver frame";
            break;
        }
        j->frames++;
        off += 4 + len;
    }
    if (off) {
        memmove(j->acc, j->acc + off, j->acc_len - off);
        j->acc_len -= off;
    }
}

// Unparsed bytes never legitimately exceed one max frame plus its header —
// anything more means a corrupt stream, so the buffer stays bounded.
#define JOB_ACC_MAX (BRIDGE_JOB_FRAME_MAX + 4)

static int job_acc_reserve(bridge_job_t *j, size_t extra) {
    if (j->acc_cap - j->acc_len >= extra) return 0;
    if (j->acc_len + extra > JOB_ACC_MAX) return -1;
    size_t cap = j->acc_cap ? j->acc_cap : 8192;
    while (cap - j->acc_len < extra) cap *= 2;
    if (cap > JOB_ACC_MAX) cap = JOB_ACC_MAX;
    uint8_t *n = realloc(j->acc, cap);
    if (!n) return -1;
    j->acc = n; j->acc_cap = cap;
    return 0;
}

void bridge_jobs_poll(bridge_jobs_t *p, int64_t now_ms,
                      bridge_job_frame_cb on_frame,
                      bridge_job_done_cb on_done, void *ctx) {
    for (int i = 0; i < BRIDGE_JOB_MAX; i++) {
        bridge_job_t *j = &p->slots[i];
        if (!j->active) continue;

        int eof = 0;
        const char *err = NULL;
        size_t drained = 0;
        // Parse as we go: bounded reassembly means complete frames must leave
        // the buffer before the next read can refill it.
        while (drained < BRIDGE_JOB_DRAIN_MAX && !err) {
            size_t want = BRIDGE_JOB_DRAIN_MAX - drained;
            if (want > 8192) want = 8192;
            if (job_acc_reserve(j, want) != 0) { err = "worker stream overflow"; break; }
            size_t room = j->acc_cap - j->acc_len;
            if (room < want) want = room;
#ifdef _WIN32
            DWORD avail = 0;
            if (!PeekNamedPipe((HANDLE)j->rd, NULL, 0, NULL, &avail, NULL)) { eof = 1; break; }
            if (avail == 0) break;
            if (avail < want) want = avail;
            DWORD got = 0;
            if (!ReadFile((HANDLE)j->rd, j->acc + j->acc_len, (DWORD)want, &got, NULL) || got == 0) { eof = 1; break; }
            j->acc_len += got; drained += got;
#else
            ssize_t n = read(j->rfd, j->acc + j->acc_len, want);
            if (n == 0) { eof = 1; break; }
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                err = "worker stream error"; break;
            }
            j->acc_len += (size_t)n; drained += (size_t)n;
#endif
            job_drain_acc(j, on_frame, ctx, &err);
        }
        if (!err) job_drain_acc(j, on_frame, ctx, &err);

        if (!err && eof && !j->clean)
            err = "worker exited without finishing its result";
        if (!err && !eof && j->deadline_ms > 0 && now_ms >= j->deadline_ms)
            err = "timed out";

        if (err || eof) {
            bridge_job_t snap = *j;
            job_close(j);
            if (on_done) on_done(ctx, &snap, err ? 0 : 1, err);
        }
    }
}

void bridge_jobs_shutdown(bridge_jobs_t *p) {
    for (int i = 0; i < BRIDGE_JOB_MAX; i++)
        if (p->slots[i].active) job_close(&p->slots[i]);
}

// See jobs.h for the model. Wire format on the worker's stdout: repeated
// [u32 little-endian length][length bytes of JSON], then a zero-length frame
// as the end-of-stream marker. A bare EOF without that marker means the
// worker died mid-stream. A length above BRIDGE_JOB_FRAME_MAX means a corrupt
// stream and fails the job. The payload travels the other way, on stdin.

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

// Path to re-execute for a worker. Resolved once: a job must not depend on
// the cwd still being what it was at startup.
static char g_self[1024];

// Set in every worker's environment. A binary that forgets to dispatch on
// `__job` would otherwise re-enter its own startup path and spawn workers
// recursively — a fork bomb whose parent looks perfectly healthy. Seeing the
// marker already set means exactly that, so the worker dies instead.
#define JOB_DEPTH_ENV "TODOFORAI_JOB_WORKER"

void bridge_jobs_init_self(const char *argv0) {
#ifdef _WIN32
    char depth[8];
    if (GetEnvironmentVariableA(JOB_DEPTH_ENV, depth, sizeof depth) > 0) {
#else
    if (getenv(JOB_DEPTH_ENV)) {
#endif
        fprintf(stderr, "[jobs] refusing to run: started as a worker but never "
                        "dispatched on `__job` (would spawn recursively)\n");
        exit(70);
    }
#ifdef _WIN32
    if (GetModuleFileNameA(NULL, g_self, sizeof g_self)) return;
#else
    ssize_t n = readlink("/proc/self/exe", g_self, sizeof g_self - 1);
    if (n <= 0) n = readlink("/proc/curproc/file", g_self, sizeof g_self - 1);  // BSD
    if (n > 0) { g_self[n] = '\0'; return; }
#endif
    snprintf(g_self, sizeof g_self, "%s", argv0 ? argv0 : "");
}

// ── Worker side ─────────────────────────────────────────────────────────────

#ifdef _WIN32
typedef HANDLE sink_fd_t;
#else
typedef int sink_fd_t;
#endif

// Write exactly n bytes; short writes are normal on a pipe.
static int sink_write_all(sink_fd_t w, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
#ifdef _WIN32
        DWORD wrote = 0;
        if (!WriteFile(w, p, (DWORD)n, &wrote, NULL) || wrote == 0) return -1;
#else
        ssize_t wrote = write(w, p, n);
        if (wrote < 0) { if (errno == EINTR) continue; return -1; }
        if (wrote == 0) return -1;
#endif
        p += wrote; n -= (size_t)wrote;
    }
    return 0;
}

static int sink_frame(sink_fd_t w, const char *data, size_t len) {
    uint8_t hdr[4] = { (uint8_t)len, (uint8_t)(len >> 8),
                       (uint8_t)(len >> 16), (uint8_t)(len >> 24) };
    if (sink_write_all(w, hdr, 4) != 0) return -1;
    return len && sink_write_all(w, data, len) != 0 ? -1 : 0;
}

// bridge_job_emit_fn handed to the body. A failing write means the parent is
// gone (cancel/teardown) — return -1 so the body unwinds.
static int worker_emit(void *ctx, const char *data, size_t len) {
    if (len == 0 || len > BRIDGE_JOB_FRAME_MAX) return -1;
    return sink_frame(*(sink_fd_t *)ctx, data, len);
}

int bridge_job_worker_main(bridge_job_body_fn body) {
#ifdef _WIN32
    sink_fd_t in  = GetStdHandle(STD_INPUT_HANDLE);
    sink_fd_t out = GetStdHandle(STD_OUTPUT_HANDLE);
#else
    sink_fd_t in = 0, out = 1;
    // The parent vanishing must surface as a failed write, not as a signal.
    signal(SIGPIPE, SIG_IGN);
#endif

    // Slurp the payload: the parent closes its end when done, so EOF is the
    // terminator. Bounded, so a bogus stream can't exhaust memory.
    size_t cap = 8192, len = 0;
    char *payload = malloc(cap);
    if (!payload) return 1;
    for (;;) {
        if (len == cap) {
            if (cap >= BRIDGE_JOB_PAYLOAD_MAX) { free(payload); return 1; }
            size_t ncap = cap * 2;
            if (ncap > BRIDGE_JOB_PAYLOAD_MAX) ncap = BRIDGE_JOB_PAYLOAD_MAX;
            char *n = realloc(payload, ncap);
            if (!n) { free(payload); return 1; }
            payload = n; cap = ncap;
        }
#ifdef _WIN32
        DWORD got = 0;
        if (!ReadFile(in, payload + len, (DWORD)(cap - len), &got, NULL) || got == 0) break;
#else
        ssize_t got = read(in, payload + len, cap - len);
        if (got < 0) { if (errno == EINTR) continue; break; }
        if (got == 0) break;
#endif
        len += (size_t)got;
    }

    // Only a body that ran to completion earns the end-of-stream marker.
    int rc = body(payload, len, worker_emit, &out);
    if (rc == 0) (void)sink_frame(out, NULL, 0);
    free(payload);
    return rc == 0 ? 0 : 1;
}

// ── Parent side ─────────────────────────────────────────────────────────────

static void job_close(bridge_job_t *j) {
#ifdef _WIN32
    // The job object holds the worker and everything it spawned; closing it
    // terminates the whole tree (KILL_ON_JOB_CLOSE).
    if (j->job)  { CloseHandle((HANDLE)j->job);  j->job = NULL; }
    if (j->rd)   { CloseHandle((HANDLE)j->rd);   j->rd = NULL; }
    if (j->wr)   { CloseHandle((HANDLE)j->wr);   j->wr = NULL; }
    if (j->proc) { CloseHandle((HANDLE)j->proc); j->proc = NULL; }
#else
    if (j->rfd >= 0) { close(j->rfd); j->rfd = -1; }
    if (j->wfd >= 0) { close(j->wfd); j->wfd = -1; }
    if (j->pid > 0) {
        // Kill the group, not just the worker: a tool scan has probe shells in
        // flight, and they stay in the worker's group precisely so that one
        // signal reaps the whole tree. Runs on every completion path, so even
        // a normal exit sweeps stragglers the worker left behind.
        if (kill(-j->pid, SIGKILL) != 0) kill(j->pid, SIGKILL);
        // Targeted reap: the PTY code waits on its own pids, so no wildcard.
        while (waitpid(j->pid, NULL, 0) < 0 && errno == EINTR) {}
        j->pid = 0;
    }
#endif
    free(j->acc); free(j->pl);
    j->acc = NULL; j->acc_len = j->acc_cap = 0;
    j->pl = NULL; j->pl_len = j->pl_off = 0;
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
                     int64_t now_ms, int timeout_ms,
                     const char *rid, size_t rid_len,
                     const char *aid, size_t aid_len,
                     const char *eid, size_t eid_len) {
    if (!g_self[0] || payload_len > BRIDGE_JOB_PAYLOAD_MAX) return -1;

    bridge_job_t *j = NULL;
    for (int i = 0; i < BRIDGE_JOB_MAX; i++)
        if (!p->slots[i].active) { j = &p->slots[i]; break; }
    if (!j) return -1;

    memset(j, 0, sizeof(*j));
    j->kind = kind;
    job_set_id(j->rid, &j->rid_len, sizeof j->rid, rid, rid_len);
    job_set_id(j->aid, &j->aid_len, sizeof j->aid, aid, aid_len);
    job_set_id(j->eid, &j->eid_len, sizeof j->eid, eid, eid_len);

    if (payload_len) {
        j->pl = malloc(payload_len);
        if (!j->pl) return -1;
        memcpy(j->pl, payload, payload_len);
        j->pl_len = payload_len;
    }

    char kind_s[16];
    snprintf(kind_s, sizeof kind_s, "%d", kind);

#ifdef _WIN32
    // Child ends inheritable, our ends not — otherwise the worker would hold
    // its own read end open and never see EOF.
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof sa, .bInheritHandle = TRUE };
    HANDLE in_rd = NULL, in_wr = NULL, out_rd = NULL, out_wr = NULL;
    if (!CreatePipe(&in_rd, &in_wr, &sa, 0)) { free(j->pl); j->pl = NULL; return -1; }
    if (!CreatePipe(&out_rd, &out_wr, &sa, 0)) {
        CloseHandle(in_rd); CloseHandle(in_wr); free(j->pl); j->pl = NULL; return -1;
    }
    SetHandleInformation(in_wr,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

    char cmdline[1200];
    snprintf(cmdline, sizeof cmdline, "\"%s\" __job %s", g_self, kind_s);

    STARTUPINFOA si = { .cb = sizeof si };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = in_rd;
    si.hStdOutput = out_wr;
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);   // worker logs to our stderr
    // Inherited by the worker; see JOB_DEPTH_ENV.
    SetEnvironmentVariableA(JOB_DEPTH_ENV, "1");

    // Job object: the Windows answer to a process group. Killed as one tree,
    // which is what makes a wedged worker cancellable at all.
    HANDLE wjob = CreateJobObjectA(NULL, NULL);
    if (wjob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(wjob, JobObjectExtendedLimitInformation, &jeli, sizeof jeli);
    }

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    CloseHandle(in_rd); CloseHandle(out_wr);        // child owns its ends now
    if (!ok) {
        if (wjob) CloseHandle(wjob);
        CloseHandle(in_wr); CloseHandle(out_rd);
        free(j->pl); j->pl = NULL;
        return -1;
    }
    SetEnvironmentVariableA(JOB_DEPTH_ENV, NULL);     // ours again
    if (wjob && !AssignProcessToJobObject(wjob, pi.hProcess)) { CloseHandle(wjob); wjob = NULL; }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    j->rd = out_rd; j->wr = in_wr; j->proc = pi.hProcess; j->job = wjob;
#else
    int in_fds[2], out_fds[2];
    if (pipe(in_fds) != 0) { free(j->pl); j->pl = NULL; return -1; }
    if (pipe(out_fds) != 0) {
        close(in_fds[0]); close(in_fds[1]); free(j->pl); j->pl = NULL; return -1;
    }
    // Our ends: close-on-exec so they don't leak into the worker (or any other
    // child), and non-blocking so neither draining frames nor feeding the
    // payload can ever park the loop — the one thing this module exists for.
    int ok = 1;
    for (int fd_i = 0; fd_i < 2; fd_i++) {
        int fd = fd_i ? in_fds[1] : out_fds[0];
        int fl = fcntl(fd, F_GETFL, 0);
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || fl < 0 ||
            fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) { ok = 0; break; }
    }
    if (!ok) {
        close(in_fds[0]); close(in_fds[1]); close(out_fds[0]); close(out_fds[1]);
        free(j->pl); j->pl = NULL;
        return -1;
    }

    // Our environment plus the worker marker, assembled before the fork:
    // between fork and exec nothing may allocate, so the child can only be
    // handed a finished array (execle) — setenv there would be unsafe.
    extern char **environ;
    size_t nenv = 0;
    while (environ[nenv]) nenv++;
    char **child_env = malloc((nenv + 2) * sizeof *child_env);
    if (!child_env) {
        close(in_fds[0]); close(in_fds[1]); close(out_fds[0]); close(out_fds[1]);
        free(j->pl); j->pl = NULL;
        return -1;
    }
    memcpy(child_env, environ, nenv * sizeof *child_env);
    child_env[nenv]     = (char *)JOB_DEPTH_ENV "=1";
    child_env[nenv + 1] = NULL;

    pid_t pid = fork();
    if (pid < 0) {
        free(child_env);
        close(in_fds[0]); close(in_fds[1]); close(out_fds[0]); close(out_fds[1]);
        free(j->pl); j->pl = NULL;
        return -1;
    }
    if (pid == 0) {
        // Nothing here may allocate or take a lock: exec is immediate, and the
        // only state that matters is the three descriptors.
        dup2(in_fds[0], 0);
        dup2(out_fds[1], 1);
        close(in_fds[0]); close(in_fds[1]);
        close(out_fds[0]); close(out_fds[1]);
        setpgid(0, 0);              // own group, so cancel can sweep the tree
        execle(g_self, g_self, "__job", kind_s, (char *)NULL, child_env);
        _exit(127);
    }
    free(child_env);
    close(in_fds[0]); close(out_fds[1]);
    setpgid(pid, pid);              // race-free: both sides do it
    j->rfd = out_fds[0];
    j->wfd = in_fds[1];
    j->pid = pid;
#endif

    j->active = 1;
    j->deadline_ms = timeout_ms > 0 ? now_ms + timeout_ms : 0;
    return 0;
}

// Push what fits of the payload without blocking, then close the write end so
// the worker sees EOF and starts working.
static void job_feed(bridge_job_t *j) {
#ifdef _WIN32
    if (!j->wr) return;
#else
    if (j->wfd < 0) return;
#endif
    while (j->pl_off < j->pl_len) {
        size_t n = j->pl_len - j->pl_off;
        if (n > 8192) n = 8192;
#ifdef _WIN32
        // A pipe write can still block once the buffer fills; keep chunks
        // small and stop as soon as the worker stops draining.
        DWORD wrote = 0;
        if (!WriteFile((HANDLE)j->wr, j->pl + j->pl_off, (DWORD)n, &wrote, NULL) || wrote == 0) break;
#else
        ssize_t wrote = write(j->wfd, j->pl + j->pl_off, n);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;   // retry next tick
            break;                                                 // worker gone
        }
        if (wrote == 0) break;
#endif
        j->pl_off += (size_t)wrote;
    }
#ifdef _WIN32
    CloseHandle((HANDLE)j->wr); j->wr = NULL;
#else
    close(j->wfd); j->wfd = -1;
#endif
    free(j->pl); j->pl = NULL;
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

        job_feed(j);

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

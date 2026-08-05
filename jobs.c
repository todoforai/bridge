// See jobs.h for the model. Wire format on the worker's stdout: repeated
// [u32 little-endian length][length bytes of JSON], then a zero-length frame
// as the end-of-stream marker. A bare EOF without that marker means the
// worker died mid-stream. A length above BRIDGE_JOB_FRAME_MAX means a corrupt
// stream and fails the job.
//
// The payload travels the other way on stdin, length-prefixed the same way:
// EOF alone can't distinguish "that was all of it" from "the parent died
// halfway", and a body must never run on half a request.

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
#  include <sys/syscall.h>
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
    DWORD n = GetModuleFileNameA(NULL, g_self, sizeof g_self);
    // A return of exactly the buffer size means the path was truncated.
    if (n > 0 && n < sizeof g_self) return;
    g_self[0] = '\0';
#else
    // The magic link itself, not its target: it keeps pointing at the running
    // inode, so an upgrade that replaces the file mid-run still spawns THIS
    // build rather than a newer one that may speak a different job protocol
    // (or nothing at all, if the path now reads "... (deleted)").
    if (access("/proc/self/exe", X_OK) == 0) {
        snprintf(g_self, sizeof g_self, "%s", "/proc/self/exe");
        return;
    }
    ssize_t n = readlink("/proc/curproc/file", g_self, sizeof g_self - 1);  // BSD
    if (n > 0 && (size_t)n < sizeof g_self - 1) { g_self[n] = '\0'; return; }
#endif
    // Fall back to argv[0]. A bare name means we were found through PATH and
    // exec would not repeat that search, so resolve it the same way.
    if (!argv0 || !*argv0) { g_self[0] = '\0'; return; }
#ifndef _WIN32
    if (!strchr(argv0, '/')) {
        const char *path = getenv("PATH");
        if (path) for (const char *p = path; ; ) {
            const char *end = strchr(p, ':');
            size_t dlen = end ? (size_t)(end - p) : strlen(p);
            // An empty component means the current directory, same as execvp.
            const char *dir = dlen ? p : ".";
            if (!dlen) dlen = 1;
            if (dlen + strlen(argv0) + 2 < sizeof g_self) {
                snprintf(g_self, sizeof g_self, "%.*s/%s", (int)dlen, dir, argv0);
                if (access(g_self, X_OK) == 0) return;
            }
            if (!end) break;
            p = end + 1;
        }
        g_self[0] = '\0';
        return;
    }
#endif
    snprintf(g_self, sizeof g_self, "%s", argv0);
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

// Read exactly n bytes or fail; a short read means the parent went away.
static int read_exactly(sink_fd_t r, void *buf, size_t n) {
    char *p = buf;
    while (n) {
#ifdef _WIN32
        DWORD got = 0;
        if (!ReadFile(r, p, (DWORD)n, &got, NULL) || got == 0) return -1;
#else
        ssize_t got = read(r, p, n);
        if (got < 0) { if (errno == EINTR) continue; return -1; }
        if (got == 0) return -1;
#endif
        p += got; n -= (size_t)got;
    }
    return 0;
}

int bridge_job_worker_main(bridge_job_body_fn body) {
    // The guard has done its job by getting here, so drop it before the body
    // runs: bodies shell out (tool probes), and every descendant would
    // otherwise inherit a marker that makes our own binary refuse to start.
#ifdef _WIN32
    SetEnvironmentVariableA(JOB_DEPTH_ENV, NULL);
    sink_fd_t in  = GetStdHandle(STD_INPUT_HANDLE);
    sink_fd_t out = GetStdHandle(STD_OUTPUT_HANDLE);
#else
    unsetenv(JOB_DEPTH_ENV);
    // Everything above stderr belongs to the daemon, not to us: exec only
    // clears descriptors marked close-on-exec, so without this a worker (and
    // every tool probe it shells out to) would hold the live backend socket
    // and every active PTY master. Doing it here covers them wholesale,
    // including any the daemon grows later.
#  if defined(__linux__) && defined(SYS_close_range)
    if (syscall(SYS_close_range, 3, ~0U, 0) != 0)   // glibc <2.34 lacks the wrapper
#  endif
    {
        for (int fd = 3; fd < 256; fd++) close(fd);
    }
    sink_fd_t in = 0, out = 1;
    // The parent vanishing must surface as a failed write, not as a signal.
    signal(SIGPIPE, SIG_IGN);
#endif

    // Read exactly the announced payload: anything short means the parent
    // died mid-hand-off, and running the body on a truncated request would
    // turn a delivery failure into a plausible-looking wrong answer.
    uint8_t hdr[4];
    if (read_exactly(in, hdr, 4) != 0) return 1;
    size_t want = (size_t)hdr[0] | ((size_t)hdr[1] << 8) |
                  ((size_t)hdr[2] << 16) | ((size_t)hdr[3] << 24);
    if (want > BRIDGE_JOB_PAYLOAD_MAX) return 1;

    char *payload = malloc(want ? want : 1);
    if (!payload) return 1;
    if (want && read_exactly(in, payload, want) != 0) { free(payload); return 1; }

    // Only a body that ran to completion earns the end-of-stream marker.
    int rc = body(payload, want, worker_emit, &out);
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

    // Buffer the length prefix with the payload so the feeder is one blob.
    j->pl = malloc(4 + payload_len);
    if (!j->pl) return -1;
    j->pl[0] = (char)(payload_len & 0xff);
    j->pl[1] = (char)((payload_len >> 8) & 0xff);
    j->pl[2] = (char)((payload_len >> 16) & 0xff);
    j->pl[3] = (char)((payload_len >> 24) & 0xff);
    if (payload_len) memcpy(j->pl + 4, payload, payload_len);
    j->pl_len = 4 + payload_len;

    char kind_s[16];
    snprintf(kind_s, sizeof kind_s, "%d", kind);

#ifdef _WIN32
    // Size the payload pipe to hold the whole payload. Windows has no
    // non-blocking write and no way to ask a write handle for free space
    // (PeekNamedPipe needs a read handle), so the only way to keep job_feed
    // off the blocking path is to guarantee the buffer is big enough. Payloads
    // are capped at BRIDGE_JOB_PAYLOAD_MAX, so this is bounded.
    #define JOB_PIPE_CAP 65536
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof sa, .bInheritHandle = TRUE };
    HANDLE in_rd = NULL, in_wr = NULL, out_rd = NULL, out_wr = NULL;
    // Child ends inheritable, our ends not — otherwise the worker would hold
    // its own stdin writer open and never see the payload end.
    if (!CreatePipe(&in_rd, &in_wr, &sa, (DWORD)j->pl_len)) { free(j->pl); j->pl = NULL; return -1; }
    if (!CreatePipe(&out_rd, &out_wr, &sa, JOB_PIPE_CAP) ||
        !SetHandleInformation(in_wr,  HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(in_rd); CloseHandle(in_wr);
        if (out_rd) CloseHandle(out_rd);
        if (out_wr) CloseHandle(out_wr);
        free(j->pl); j->pl = NULL; return -1;
    }

    char cmdline[1200];
    snprintf(cmdline, sizeof cmdline, "\"%s\" __job %s", g_self, kind_s);

    STARTUPINFOA si = { .cb = sizeof si };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = in_rd;
    si.hStdOutput = out_wr;
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);   // worker logs to our stderr

    // Job object: the Windows answer to a process group, and the only thing
    // that makes a wedged worker killable. Without it we'd be back to the
    // detached-thread behaviour this whole change exists to remove, so a
    // failure to set one up fails the spawn.
    HANDLE wjob = CreateJobObjectA(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!wjob || !SetInformationJobObject(wjob, JobObjectExtendedLimitInformation,
                                          &jeli, sizeof jeli)) {
        if (wjob) CloseHandle(wjob);
        CloseHandle(in_rd); CloseHandle(in_wr);
        CloseHandle(out_rd); CloseHandle(out_wr);
        free(j->pl); j->pl = NULL; return -1;
    }

    // Our environment plus the worker marker, as a block passed to this child
    // alone. Mutating the process environment around CreateProcess instead
    // would leave the daemon marked as a worker whenever a spawn fails
    // between the set and the restore.
    char *env_block = NULL;
    {
        char *parent_env = GetEnvironmentStringsA();
        if (!parent_env) {
            CloseHandle(wjob);
            CloseHandle(in_rd); CloseHandle(in_wr);
            CloseHandle(out_rd); CloseHandle(out_wr);
            free(j->pl); j->pl = NULL; return -1;
        }
        size_t env_len = 0;                        // block ends with "\0\0"
        while (parent_env[env_len] || parent_env[env_len + 1]) env_len++;
        env_len += 2;
        const char marker[] = JOB_DEPTH_ENV "=1";
        env_block = malloc(env_len + sizeof marker);
        if (!env_block) {
            FreeEnvironmentStringsA(parent_env);
            CloseHandle(wjob);
            CloseHandle(in_rd); CloseHandle(in_wr);
            CloseHandle(out_rd); CloseHandle(out_wr);
            free(j->pl); j->pl = NULL; return -1;
        }
        memcpy(env_block, parent_env, env_len - 1);            // drop final NUL
        memcpy(env_block + env_len - 1, marker, sizeof marker);
        env_block[env_len - 1 + sizeof marker] = '\0';         // terminate block
        FreeEnvironmentStringsA(parent_env);
    }

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW,
                             env_block, NULL, &si, &pi);
    free(env_block);
    CloseHandle(in_rd); CloseHandle(out_wr);        // child owns its ends now
    if (!ok) {
        CloseHandle(wjob);
        CloseHandle(in_wr); CloseHandle(out_rd);
        free(j->pl); j->pl = NULL;
        return -1;
    }
    // Suspended until it's in the job, so it cannot spawn anything outside it.
    if (!AssignProcessToJobObject(wjob, pi.hProcess) || ResumeThread(pi.hThread) == (DWORD)-1) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(wjob);
        CloseHandle(in_wr); CloseHandle(out_rd);
        free(j->pl); j->pl = NULL;
        return -1;
    }
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
        // The guards matter when stdin/stdout were closed before the spawn, in
        // which case a pipe end can *be* fd 0 or 1 and the close would undo
        // the dup2 we just did.
        // (-Wanalyzer-fd-leak fires on these paths; every one of them ends in
        // _exit, which takes the descriptors with it.)
        if (dup2(in_fds[0], 0) < 0) _exit(127);
        if (dup2(out_fds[1], 1) < 0) _exit(127);
        if (in_fds[0]  > 1) close(in_fds[0]);
        if (in_fds[1]  > 1) close(in_fds[1]);
        if (out_fds[0] > 1) close(out_fds[0]);
        if (out_fds[1] > 1) close(out_fds[1]);
        // Own group, so cancellation can sweep the probes the worker spawns.
        // Without it a wedged tool probe would survive the job's death.
        if (setpgid(0, 0) != 0) _exit(127);
        execle(g_self, g_self, "__job", kind_s, (char *)NULL, child_env);
        _exit(127);
    }
    free(child_env);
    close(in_fds[0]); close(out_fds[1]);
    // Both sides call it so the group exists whoever wins the race. EACCES
    // means the child already execed (it set its own group first); ESRCH that
    // it's gone already, which surfaces as EOF on the next poll. Anything else
    // means no group, so nothing to sweep the worker's own children with.
    if (setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
        // No group means job_close couldn't sweep the tree — don't pretend.
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        close(in_fds[1]); close(out_fds[0]);
        free(j->pl); j->pl = NULL;
        return -1;
    }
    j->rfd = out_fds[0];
    j->wfd = in_fds[1];
    j->pid = pid;
#endif

    j->active = 1;
    j->deadline_ms = timeout_ms > 0 ? now_ms + timeout_ms : 0;
    return 0;
}

static void job_close_wr(bridge_job_t *j) {
#ifdef _WIN32
    if (j->wr) { CloseHandle((HANDLE)j->wr); j->wr = NULL; }
#else
    if (j->wfd >= 0) { close(j->wfd); j->wfd = -1; }
#endif
    free(j->pl); j->pl = NULL;
}

// Push as much of the payload as the pipe takes right now, never blocking.
// Sets *err if the hand-off failed: the worker would otherwise be left
// waiting for bytes that will never arrive, until its deadline.
static void job_feed(bridge_job_t *j, const char **err) {
#ifdef _WIN32
    if (!j->wr) return;
#else
    if (j->wfd < 0) return;
#endif
#ifdef _WIN32
    // One write, all of it. The pipe was created large enough for the whole
    // payload and nothing else is ever written to it, so the buffer has room
    // and the call returns without waiting for the worker to read. That
    // matters because Windows has no non-blocking write and no way to ask a
    // write handle for free space (PeekNamedPipe needs a read handle) — the
    // room has to be bought up front rather than checked.
    DWORD wrote = 0;
    if (!WriteFile((HANDLE)j->wr, j->pl, (DWORD)j->pl_len, &wrote, NULL) ||
        wrote != (DWORD)j->pl_len) {
        *err = "failed to send payload to worker";
        job_close_wr(j);
        return;
    }
    j->pl_off = j->pl_len;
#else
    while (j->pl_off < j->pl_len) {
        size_t n = j->pl_len - j->pl_off;
        if (n > 8192) n = 8192;
        ssize_t wrote = write(j->wfd, j->pl + j->pl_off, n);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;   // retry next tick
            *err = "failed to send payload to worker";
            job_close_wr(j);
            return;
        }
        if (wrote == 0) { *err = "failed to send payload to worker"; job_close_wr(j); return; }
        j->pl_off += (size_t)wrote;
    }
#endif
    job_close_wr(j);        // EOF: the worker has the whole payload
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
        job_feed(j, &err);
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

// Off-loop jobs: run a bounded, blocking operation (tool scan, preview fetch)
// without parking the single-threaded event loop.
//
// The worker never touches WS/Noise state — it only produces ready-to-send
// JSON messages, which travel back to the main loop as length-prefixed frames
// over a pipe. The main loop drains that pipe non-blocking and does all the
// Noise encryption + sending itself, so the transport stays single-writer
// (the send nonce must advance in one place only).
//
// POSIX: fork(). The child gets a COW snapshot of the payload, so the parent
//        can free its copy immediately and a cancel is just close+SIGKILL.
// Windows: no fork, so a worker thread writes into an anonymous pipe. Cancel
//        closes the read end and DETACHES the thread — there is no safe way to
//        kill it (TerminateThread would leak its locks). It unwinds at its next
//        emit, so a worker wedged inside a fetch or a probe can outlive the
//        connection; it owns its payload, so nothing is freed underneath it.
#ifndef BRIDGE_JOBS_H
#define BRIDGE_JOBS_H

#include <stddef.h>
#include <stdint.h>

#define BRIDGE_JOB_MAX        8
#define BRIDGE_JOB_FRAME_MAX  (64 * 1024)
// Per-job bytes drained per tick. A few preview chunks' worth: enough to move
// a multi-MB response along briskly, small enough that eight busy jobs can't
// starve the WS/PTY work in the same tick.
#define BRIDGE_JOB_DRAIN_MAX  (256 * 1024)

// Kinds are opaque to this module — the caller routes results by them.
#define BRIDGE_JOB_SCAN     1
#define BRIDGE_JOB_PREVIEW  2

// Emit one ready-to-send JSON message from inside the worker. Returns 0, or
// -1 once the parent is gone / cancelled (workers should then unwind).
// Signature-compatible with preview_emit_fn so preview.c plugs in unchanged.
typedef int (*bridge_job_emit_fn)(void *ctx, const char *data, size_t len);

// The actual work, executed in the child/thread. Must not touch WS or Noise.
// Return 0 when the job said everything it meant to say, -1 otherwise: only
// a 0 makes the worker write the end-of-stream marker, which is what lets the
// parent tell "finished" apart from "died mid-stream" (a crash, or a preview
// that emitted chunks but never its terminal frame).
typedef int (*bridge_job_body_fn)(const char *payload, size_t payload_len,
                                  bridge_job_emit_fn emit, void *emit_ctx);

typedef struct {
    int      active;
    int      kind;
    int64_t  deadline_ms;
    int      frames;              // frames successfully forwarded so far
    int      clean;               // end-of-stream marker seen
    // Routing echoed back on completion (requestId / agentId / edgeId).
    char     rid[80]; size_t rid_len;
    char     aid[80]; size_t aid_len;
    char     eid[80]; size_t eid_len;
#ifdef _WIN32
    void    *rd;                  // HANDLE, read end
    void    *th;                  // HANDLE, worker thread
#else
    int      rfd;
    int      pid;
#endif
    uint8_t *acc; size_t acc_len, acc_cap;   // partial-frame reassembly
} bridge_job_t;

typedef struct {
    bridge_job_t slots[BRIDGE_JOB_MAX];
} bridge_jobs_t;

// One complete JSON message from a worker — send it as-is. Return -1 if it
// could not be delivered (WS/Noise failure): the job then stops and fails,
// instead of reporting success for bytes that never reached the backend.
typedef int (*bridge_job_frame_cb)(void *ctx, const bridge_job_t *j,
                                   const char *data, size_t len);
// Worker finished. ok=1 means it ran to completion and every frame was
// delivered; otherwise `err` explains the failure.
typedef void (*bridge_job_done_cb)(void *ctx, const bridge_job_t *j,
                                   int ok, const char *err);

// Spawn a job. `payload` is copied. rid/aid/eid may be NULL/0.
// Returns 0, or -1 if no slot is free or the spawn failed.
int bridge_job_start(bridge_jobs_t *p, int kind,
                     const char *payload, size_t payload_len,
                     bridge_job_body_fn body,
                     int64_t now_ms, int timeout_ms,
                     const char *rid, size_t rid_len,
                     const char *aid, size_t aid_len,
                     const char *eid, size_t eid_len);

// Drain every running job. Call once per tick; never blocks.
void bridge_jobs_poll(bridge_jobs_t *p, int64_t now_ms,
                      bridge_job_frame_cb on_frame,
                      bridge_job_done_cb on_done, void *ctx);

// Cancel + reap everything (connection teardown). No callbacks fire.
void bridge_jobs_shutdown(bridge_jobs_t *p);

// Active jobs of a kind — for per-kind admission control.
int bridge_jobs_count(const bridge_jobs_t *p, int kind);

#endif

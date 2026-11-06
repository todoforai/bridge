// Background tasks: the files behind a RUN that outlives its step.
//
//   ~/.todoforai/tasks/<pid>.output  everything the command prints from the
//                                    handoff on (VT-stripped on Windows only;
//                                    POSIX keeps colour escapes), appended live; capped at
//                                    BG_OUT_CAP (restarts from 0 with a marker,
//                                    so the end of the file is always current)
//   ~/.todoforai/tasks/<pid>.input   append-only; bytes appended by anyone are
//                                    typed into the task's PTY. Unlinked on exit.
//
// <pid> is the shell's OS pid (Win32 pid on Windows): unique among live
// processes, so it is the task id everywhere (files, frames, registry). Paths
// use forward slashes on every OS (Git Bash, cmd and PowerShell all accept
// them). Windows handles are opened with full sharing so an agent's `>>`,
// `tail -f`, or a delete never hit a sharing violation.
#ifndef BRIDGE_BG_TASK_H
#define BRIDGE_BG_TASK_H

#include <stddef.h>
#include <stdint.h>

#define BG_OUT_CAP     (50LL * 1024 * 1024)
#define BG_PATH_CAP    512
#define BG_REAP_AGE_MS (7LL * 24 * 60 * 60 * 1000)

typedef struct {
    int       open;          // files exist and h is valid
    intptr_t  h;             // .output: POSIX fd / Win32 HANDLE
    long long out_len;       // bytes written since the last cap reset
    long long in_off;        // bytes of .input already fed to the PTY
    char out_path[BG_PATH_CAP];
    char in_path[BG_PATH_CAP];
} bg_task_t;

// Create (truncate) both files for `pid`. 0 on success, -1 (errno set).
int  bg_task_open(bg_task_t *t, long pid);
// Append to .output (best effort; a failed write is dropped). The bridge is
// the only writer; others only read.
void bg_task_write(bg_task_t *t, const void *data, size_t len);
// Peek up to `cap` not-yet-delivered .input bytes (0 = none). The file is the
// queue: the caller advances in_off by what the PTY actually took, so a full
// PTY never loses input. A file shrunk below in_off (someone truncated it)
// restarts from 0.
long bg_task_peek_input(bg_task_t *t, void *buf, size_t cap);
// Last ≤cap bytes of .output, starting on a UTF-8 boundary.
size_t bg_task_tail(const bg_task_t *t, char *buf, size_t cap);
// Close .output (kept for reading) and unlink .input.
void bg_task_close(bg_task_t *t);
// Delete task files not modified for BG_REAP_AGE_MS. Startup only.
void bg_task_reap_old(void);
// Unix epoch ms (wall clock, for startedAt).
int64_t bg_wall_ms(void);

#endif

#ifndef BRIDGE_PTY_H
#define BRIDGE_PTY_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int    master_fd;
    pid_t  child_pid;
    int    alive;
} bridge_pty_t;

// Spawn `shell` in a new PTY. `cwd` may be NULL. If `no_echo`, the slave
// terminal starts with ECHO/ECHOE/ECHOK cleared (used by RUN to keep wrapper
// command lines off the output stream — sentinel scanning relies on this).
// Returns 0 on success, -1 on failure.
int bridge_pty_spawn(bridge_pty_t *p, const char *shell, const char *cwd, int no_echo);

void bridge_pty_resize(bridge_pty_t *p, uint16_t rows, uint16_t cols);

// Write all bytes. Returns 0 on success, -1 on error.
int bridge_pty_write_all(bridge_pty_t *p, const void *buf, size_t len);

// Read available bytes. Returns >=0 on success, -1 on error.
long bridge_pty_read(bridge_pty_t *p, void *buf, size_t len);

// Send signal if whitelisted. Returns 1 if sent, 0 otherwise.
int bridge_pty_signal(bridge_pty_t *p, int sig);

// Non-blocking reap. Returns 1 + sets *code if child exited; 0 otherwise.
// `code` is exit status (>=0) or -signal (<0).
int bridge_pty_reap(bridge_pty_t *p, int *code);

// Close PTY and reap child synchronously. Returns exit/signal code (see reap).
int bridge_pty_close(bridge_pty_t *p);

// Master fd, suitable for poll()/select(). POSIX-only.
int bridge_pty_pollfd(const bridge_pty_t *p);

// Probe whether any task in the PTY's foreground process group is parked in
// a tty read — i.e. blocked waiting for stdin. Linux uses /proc, macOS uses
// libproc (/dev/ttys* fd + sleeping thread heuristic). Other platforms: 0.
//
//   echo_baseline     baseline of (c_lflag & ECHO) bool at session creation;
//                     password_prompt fires only on transitions from that.
//                     RUN sessions spawn with ECHO off (no_echo=1) so pass 0;
//                     EXEC and other interactive sessions pass 1.
//   *fg_pid           ← actual blocked pid when blocked (may be a child of
//                     the pgrp leader, e.g. sudo/ssh)
//   *password_prompt  ← 1 iff slave ECHO is off AND echo_baseline was on
//                     (i.e. the user command turned echo off — getpass/sudo)
//
// Returns 1 if blocked-on-tty-read, 0 otherwise.
int bridge_pty_probe_blocked(const bridge_pty_t *p, int echo_baseline,
                             pid_t *fg_pid, int *password_prompt);

#endif

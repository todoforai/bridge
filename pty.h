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

// Spawn `shell` in a new PTY. Returns 0 on success, -1 on failure.
int bridge_pty_spawn(bridge_pty_t *p, const char *shell);

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

#endif

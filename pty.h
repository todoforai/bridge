#ifndef BRIDGE_PTY_H
#define BRIDGE_PTY_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/types.h>  // pid_t
#endif

// Embedded by value in callers; fields are platform-specific and should be
// treated as opaque — use the API below.
typedef struct {
#ifdef _WIN32
    HANDLE hPC;          // ConPTY pseudoconsole
    HANDLE hPipeIn;      // we write -> child stdin
    HANDLE hPipeOut;     // child stdout/stderr -> we read
    HANDLE hProcess;
    DWORD  pid;
#else
    int    master_fd;
    pid_t  child_pid;
#endif
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
// On Windows only SIGINT/SIGTERM are mapped (to Ctrl+C / process termination).
int bridge_pty_signal(bridge_pty_t *p, int sig);

// Non-blocking reap. Returns 1 + sets *code if child exited; 0 otherwise.
// `code` is exit status (>=0) or -signal (<0, POSIX only).
int bridge_pty_reap(bridge_pty_t *p, int *code);

// Close PTY and reap child synchronously. Returns exit/signal code (see reap).
int bridge_pty_close(bridge_pty_t *p);

// Readable handle suitable for the platform's wait primitive.
// POSIX: master fd for poll()/select().
// Windows: -1 (callers must use overlapped IO / WaitForMultipleObjects on
// the underlying HANDLE — exposed via the struct for the Windows event loop).
int bridge_pty_pollfd(const bridge_pty_t *p);

#endif

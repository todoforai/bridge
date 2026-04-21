#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "pty.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#  include <util.h>
#else
#  include <pty.h>
#endif

int bridge_pty_spawn(bridge_pty_t *p, const char *shell) {
    int master_fd = -1;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid < 0) return -1;

    if (pid == 0) {
        // Child
        char *env[] = {
            (char *)"TERM=xterm-256color",
            (char *)"PATH=/usr/bin:/bin",
            NULL,
        };
        char *argv[] = { (char *)shell, NULL };
        execve(shell, argv, env);
        _exit(1);
    }

    p->master_fd = master_fd;
    p->child_pid = pid;
    p->alive = 1;
    return 0;
}

void bridge_pty_resize(bridge_pty_t *p, uint16_t rows, uint16_t cols) {
    struct winsize ws = { .ws_row = rows, .ws_col = cols, 0, 0 };
    (void)ioctl(p->master_fd, TIOCSWINSZ, &ws);
}

int bridge_pty_write_all(bridge_pty_t *p, const void *buf, size_t len) {
    const uint8_t *b = buf;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(p->master_fd, b + written, len - written);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return -1;
        }
        written += (size_t)n;
    }
    return 0;
}

long bridge_pty_read(bridge_pty_t *p, void *buf, size_t len) {
    ssize_t n = read(p->master_fd, buf, len);
    if (n < 0) {
        // EIO on Linux when the slave side closes — treat as EOF.
        if (errno == EIO) return 0;
        return -1;
    }
    return (long)n;
}

int bridge_pty_signal(bridge_pty_t *p, int sig) {
    static const int allowed[] = {
        SIGINT, SIGQUIT, SIGKILL, SIGTERM, SIGCONT, SIGSTOP, SIGTSTP, SIGWINCH
    };
    for (size_t i = 0; i < sizeof(allowed)/sizeof(allowed[0]); i++) {
        if (sig == allowed[i]) {
            return kill(p->child_pid, sig) == 0 ? 1 : 0;
        }
    }
    return 0;
}

static int decode_status(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return 0;
}

int bridge_pty_reap(bridge_pty_t *p, int *code) {
    if (!p->alive) return 0;
    int status = 0;
    pid_t ret = waitpid(p->child_pid, &status, WNOHANG);
    if (ret > 0) {
        p->alive = 0;
        *code = decode_status(status);
        return 1;
    }
    return 0;
}

int bridge_pty_close(bridge_pty_t *p) {
    if (p->master_fd >= 0) {
        close(p->master_fd);
        p->master_fd = -1;
    }
    int code = 0;
    if (p->alive) {
        int status = 0;
        waitpid(p->child_pid, &status, 0);
        p->alive = 0;
        code = decode_status(status);
    }
    return code;
}

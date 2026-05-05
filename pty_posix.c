#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "pty.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#  include <util.h>
#else
#  include <pty.h>
#endif

#if defined(__APPLE__)
#  include <libproc.h>
#  include <sys/proc_info.h>
#endif

int bridge_pty_spawn(bridge_pty_t *p, const char *shell, const char *cwd, int no_echo) {
    // Pre-build termios so the slave starts in the desired mode. Setting echo
    // from the child after fork races against the parent's first write.
    struct termios t = {0};
    t.c_iflag = ICRNL | IXON;
    t.c_oflag = OPOST | ONLCR;
    t.c_cflag = CREAD | CS8 | B38400;
    t.c_lflag = ICANON | ISIG | IEXTEN | ECHO | ECHOE | ECHOK;
    cfmakeraw(&t);
    // Re-enable canonical line discipline + signals; cfmakeraw turned them off.
    t.c_iflag |= ICRNL;
    t.c_oflag |= OPOST | ONLCR;
    t.c_lflag |= ICANON | ISIG | IEXTEN;
    if (!no_echo) t.c_lflag |= ECHO | ECHOE | ECHOK;

    int master_fd = -1;
    pid_t pid = forkpty(&master_fd, NULL, &t, NULL);
    if (pid < 0) return -1;

    if (pid == 0) {
        if (cwd && *cwd) {
            // Caller validates cwd up-front; failure here is unexpected.
            if (chdir(cwd) != 0) _exit(2);
        }
        // Inherit the parent's environment (HOME, USER, locale, language
        // managers, etc.) so commands behave like a real shell. Override
        // only what we need: empty PS1/PS2 keep prompts out of OUTPUT, and
        // TERM is normalized for line-disciplined scanning.
        setenv("TERM", "xterm-256color", 1);
        setenv("PS1", "", 1);
        setenv("PS2", "", 1);
        char *argv[] = { (char *)shell, NULL };
        execvp(shell, argv);
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
        // Non-blocking master: no data available right now (EAGAIN/EWOULDBLOCK).
        // Not an error, just nothing to read. Caller treats 0 == "skip"; PTY
        // death is detected separately via bridge_pty_reap.
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
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

int bridge_pty_pollfd(const bridge_pty_t *p) {
    return p->master_fd;
}

#if defined(__linux__)
// Per-arch syscall numbers for read(2). Linux numbers are stable per-arch.
#if defined(__x86_64__)
#  define BRIDGE_SYS_READ 0
#elif defined(__aarch64__) || defined(__riscv)
#  define BRIDGE_SYS_READ 63
#elif defined(__i386__)
#  define BRIDGE_SYS_READ 3
#elif defined(__arm__)
#  define BRIDGE_SYS_READ 3
#else
#  define BRIDGE_SYS_READ -1   // unknown arch → syscall path disabled
#endif

// Authoritative: read /proc/<pid>/syscall. Returns 1 iff the task is blocked
// inside read()/pread64()/readv() on an fd pointing at /dev/pts/*. Format:
//   <num> <arg0> <arg1> <arg2> <arg3> <arg4> <arg5> <sp> <pc>
// "running" appears for non-sleeping tasks. Permission denied is normal for
// non-owned processes; caller falls back to wchan.
static int proc_syscall_is_tty_read(pid_t pid) {
    if (BRIDGE_SYS_READ < 0) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/syscall", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    if (strncmp(buf, "running", 7) == 0) return 0;
    long sysnum = -1;
    unsigned long arg0 = 0;
    if (sscanf(buf, "%ld %lx", &sysnum, &arg0) != 2) return 0;
    if (sysnum != BRIDGE_SYS_READ) return 0;
    // Resolve fd → path; require /dev/pts/*.
    snprintf(path, sizeof(path), "/proc/%d/fd/%lu", (int)pid, arg0);
    char target[64];
    ssize_t tn = readlink(path, target, sizeof(target) - 1);
    if (tn <= 0) return 0;
    target[tn] = '\0';
    return strncmp(target, "/dev/pts/", 9) == 0;
}

// Fallback: read /proc/<pid>/wchan and return 1 iff the task is parked in a
// tty read. The wchan symbol moved across kernel versions (older kernels:
// `n_tty_read`; some configs: `tty_read`; some 6.x configs inline the wait
// helper and report `wait_woken` — broader but ambiguous). syscall path is
// preferred; this just rescues kernels where /proc/<pid>/syscall is denied.
static int proc_wchan_is_tty_read(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/wchan", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return (strstr(buf, "n_tty_read") != NULL) || (strstr(buf, "tty_read") != NULL);
}

// Combined check: prefer syscall (authoritative), fall back to wchan symbol.
static int proc_is_blocked_on_tty(pid_t pid) {
    return proc_syscall_is_tty_read(pid) || proc_wchan_is_tty_read(pid);
}

// Read field 5 (pgrp) of /proc/<pid>/stat. The `comm` field (#2) may contain
// spaces and parens, so anchor parsing on the last ')'. Returns 0 on failure.
static pid_t proc_pgrp(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char sb[512];
    ssize_t n = read(fd, sb, sizeof(sb) - 1);
    close(fd);
    if (n <= 0) return 0;
    sb[n] = '\0';
    char *rp = strrchr(sb, ')');
    if (!rp || rp[1] != ' ') return 0;
    char state; int ppid; int pgrp;
    if (sscanf(rp + 2, "%c %d %d", &state, &ppid, &pgrp) != 3) return 0;
    return (pid_t)pgrp;
}
#endif

#if defined(__APPLE__)
// True iff `pid` has any open fd whose vnode path is a pty slave (/dev/ttys*).
// Cheaper than enumerating every fd: we early-exit on first hit.
static int darwin_pid_has_tty_fd(pid_t pid) {
    int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bufsize <= 0) return 0;
    struct proc_fdinfo *fds = (struct proc_fdinfo *)malloc((size_t)bufsize);
    if (!fds) return 0;
    int n = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufsize);
    int hit = 0;
    int count = (n > 0) ? n / (int)sizeof(struct proc_fdinfo) : 0;
    for (int i = 0; i < count; i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_VNODE) continue;
        struct vnode_fdinfowithpath v;
        int r = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO,
                               &v, sizeof v);
        if (r != (int)sizeof v) continue;
        if (strncmp(v.pvip.vip_path, "/dev/ttys", 9) == 0) { hit = 1; break; }
    }
    free(fds);
    return hit;
}

// True iff `pid` has no thread currently on-CPU. Darwin doesn't expose
// per-syscall info like /proc/<pid>/syscall, so we approximate:
// "no running thread + holds a pty fd". Combined with the tcgetpgrp gate
// from the caller this matches the Linux signal in practice.
static int darwin_pid_is_waiting(pid_t pid) {
    struct proc_taskallinfo ti;
    int r = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &ti, sizeof ti);
    if (r != (int)sizeof ti) return 0;
    return ti.ptinfo.pti_numrunning == 0;
}

static int darwin_is_blocked_on_tty(pid_t pid) {
    return darwin_pid_is_waiting(pid) && darwin_pid_has_tty_fd(pid);
}
#endif

int bridge_pty_probe_blocked(const bridge_pty_t *p, int echo_baseline,
                             long *fg_pid, int *password_prompt) {
    if (fg_pid) *fg_pid = 0;
    if (password_prompt) *password_prompt = 0;
    if (!p || p->master_fd < 0 || !p->alive) return 0;

#if defined(__APPLE__)
    pid_t fg = tcgetpgrp(p->master_fd);
    if (fg <= 0) return 0;

    pid_t blocked_pid = 0;
    if (darwin_is_blocked_on_tty(fg)) {
        blocked_pid = fg;
    } else {
        // Enumerate the foreground process group via libproc. Both calls
        // return a byte count (NOT a pid count).
        int bytes = proc_listpgrppids(fg, NULL, 0);
        if (bytes <= 0) return 0;
        pid_t *pids = (pid_t *)malloc((size_t)bytes);
        if (!pids) return 0;
        bytes = proc_listpgrppids(fg, pids, bytes);
        int count = (bytes > 0) ? bytes / (int)sizeof(pid_t) : 0;
        for (int i = 0; i < count; i++) {
            pid_t pid = pids[i];
            if (pid <= 0 || pid == fg) continue;
            if (darwin_is_blocked_on_tty(pid)) { blocked_pid = pid; break; }
        }
        free(pids);
        if (blocked_pid == 0) return 0;
    }
    if (fg_pid) *fg_pid = blocked_pid;

    if (password_prompt && echo_baseline) {
        struct termios t;
        if (tcgetattr(p->master_fd, &t) == 0 && !(t.c_lflag & ECHO)) {
            *password_prompt = 1;
        }
    }
    return 1;
#elif defined(__linux__)
    // Foreground process *group* on our PTY. tcgetpgrp returns a pgid, NOT the
    // pid of the actual reader — for `sudo cmd`, the shell may be in wait()
    // while sudo (a child in the same fg pgrp) is the one parked in n_tty_read.
    // So we walk /proc and check every task with this pgrp.
    pid_t fg = tcgetpgrp(p->master_fd);
    if (fg <= 0) return 0;

    // Fast path: the pgrp leader is by far the most common reader (plain shell
    // builtins like `read`, simple `cmd` invocations). Check it first.
    if (proc_is_blocked_on_tty(fg)) {
        if (fg_pid) *fg_pid = fg;
    } else {
        // Slow path: scan /proc for any task whose pgrp matches `fg` and that
        // is parked in a tty read. Costs ~one open+read per running task,
        // gated by the caller's PAUSE_POLL_MS so it runs at most a few Hz.
        DIR *d = opendir("/proc");
        if (!d) return 0;
        pid_t blocked_pid = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            pid_t pid = (pid_t)atoi(e->d_name);
            if (pid <= 0 || pid == fg) continue;
            if (proc_pgrp(pid) != fg) continue;
            if (proc_is_blocked_on_tty(pid)) { blocked_pid = pid; break; }
        }
        closedir(d);
        if (blocked_pid == 0) return 0;
        if (fg_pid) *fg_pid = blocked_pid;
    }

    if (password_prompt && echo_baseline) {
        // ECHO off on the slave is the canonical password-prompt tell:
        // getpass(3), sudo, ssh, git credential all disable echo before read.
        // We only fire when echo went off RELATIVE to the session baseline —
        // RUN sessions spawn with echo off, so without this gate the flag
        // would be permanently true.
        struct termios t;
        if (tcgetattr(p->master_fd, &t) == 0 && !(t.c_lflag & ECHO)) {
            *password_prompt = 1;
        }
    }
    return 1;
#else
    (void)p;
    return 0;
#endif
}

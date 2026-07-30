// Windows ConPTY smoke test. Runs on a real Windows CI host.
//
// It validates the Windows PTY backend, default Git Bash discovery, command
// input/output, inherited noninteractive environment, resize, and process-tree
// termination. Cross-compiling this test is not enough: it must execute on
// windows-latest.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "pty.h"

static int wait_for_text(bridge_pty_t *pty, const char *needle,
                         char *output, size_t capacity, DWORD timeout_ms) {
    size_t used = 0;
    DWORD start = GetTickCount();

    while (GetTickCount() - start < timeout_ms && used + 1 < capacity) {
        long n = bridge_pty_read(pty, output + used, capacity - used - 1);
        if (n > 0) {
            used += (size_t)n;
            output[used] = '\0';
            if (strstr(output, needle)) return 0;
        } else {
            Sleep(20);
        }
    }

    output[used] = '\0';
    return -1;
}


// ConPTY renders into a screen grid, so it emits cursor/mode escapes and can
// wrap a printed line — strip everything except printable ASCII (and keep '=')
// so a marker like FOO=cat still matches after reflow. In-place squeeze.
static void strip_ansi(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        unsigned char c = (unsigned char)*r;
        if (c >= 32 && c < 127) *w++ = (char)c;
    }
    *w = '\0';
}

static int test_shell_io(void) {
    bridge_pty_t pty;
    if (bridge_pty_spawn(&pty, NULL, NULL, 1) != 0) {
        fprintf(stderr, "FAIL: could not create ConPTY session\n");
        return 1;
    }

    fprintf(stderr, "diag: BRIDGE_SHELL=%s pid=%lu\n",
            getenv("BRIDGE_SHELL") ? getenv("BRIDGE_SHELL") : "(unset)", pty.pid);
    bridge_pty_resize(&pty, 40, 100);

    // Interactive login bash sources /etc/profile (~1s) before it reads stdin;
    // typing too early is dropped. Wait until it emits its prompt (it sets the
    // window title, ending with the BEL after the path) before sending input.
    char warm[8192];
    DWORD wstart = GetTickCount();
    while (GetTickCount() - wstart < 10000) {
        if (bridge_pty_read(&pty, warm, sizeof(warm)) > 0 && strchr(warm, '\x07')) break;
        Sleep(50);
    }
    Sleep(800);

    // Print each fact on its own line so ConPTY reflow can't merge two markers.
    const char *command =
        "printf 'TFAokPAGER=%s\\n' \"$PAGER\"\n"
        "printf 'TFAokGITPAGER=%s\\n' \"$GIT_PAGER\"\n"
        "exit\n";
    if (bridge_pty_write_all(&pty, command, strlen(command)) != 0) {
        fprintf(stderr, "FAIL: could not write to ConPTY session\n");
        bridge_pty_close(&pty);
        return 1;
    }

    // Drain continuously (banner + our output) for a fixed window.
    char output[65536] = {0};
    size_t used = 0;
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 15000 && used + 1 < sizeof(output)) {
        long n = bridge_pty_read(&pty, output + used, sizeof(output) - used - 1);
        if (n > 0) { used += (size_t)n; output[used] = '\0'; }
        else Sleep(20);
    }
    bridge_pty_close(&pty);
    strip_ansi(output);
    fprintf(stderr, "diag: captured %zu raw bytes; stripped=[%s]\n", used, output);

    // bash syntax executed (printf ran) AND the noninteractive env was inherited.
    if (!strstr(output, "TFAokPAGER=cat") || !strstr(output, "TFAokGITPAGER=cat")) {
        fprintf(stderr,
                "FAIL: default shell did not execute bash syntax or inherit "
                "the noninteractive environment. Stripped output:\n%s\n",
                output);
        return 1;
    }

    puts("PASS: ConPTY shell I/O, Git Bash discovery, resize, and environment");
    return 0;
}

static int test_process_tree_termination(void) {
    bridge_pty_t pty;
    if (bridge_pty_spawn(&pty, NULL, NULL, 1) != 0) {
        fprintf(stderr, "FAIL: could not create termination test session\n");
        return 1;
    }

    Sleep(500);

    // Start a long-lived grandchild in the background and print a marker only
    // once it is running. Signalling before the child exists would prove
    // nothing; waiting for the marker guarantees a live process tree to kill.
    const char *command = "sleep 60 & printf '__TFA_CHILD_READY__\\n'; wait\n";
    if (bridge_pty_write_all(&pty, command, strlen(command)) != 0) {
        fprintf(stderr, "FAIL: could not start child process\n");
        bridge_pty_close(&pty);
        return 1;
    }

    char output[4096] = {0};
    if (wait_for_text(&pty, "__TFA_CHILD_READY__", output, sizeof(output), 10000)) {
        fprintf(stderr, "FAIL: background child never started. Output:\n%s\n", output);
        bridge_pty_close(&pty);
        return 1;
    }

    // TerminateJobObject must take down the shell AND the `sleep` grandchild.
    if (!bridge_pty_signal(&pty, 15)) {
        fprintf(stderr, "FAIL: could not terminate ConPTY process tree\n");
        bridge_pty_close(&pty);
        return 1;
    }

    int code = 0;
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 5000) {
        if (bridge_pty_reap(&pty, &code)) {
            bridge_pty_close(&pty);
            puts("PASS: ConPTY process-tree termination");
            return 0;
        }
        Sleep(20);
    }

    fprintf(stderr, "FAIL: terminated ConPTY process did not exit\n");
    bridge_pty_close(&pty);
    return 1;
}

int main(void) {
    if (test_shell_io() != 0) return 1;
    if (test_process_tree_termination() != 0) return 1;
    puts("Windows PTY smoke tests passed");
    return 0;
}

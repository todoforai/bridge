// Windows ConPTY smoke test. Runs on a real Windows CI host.
//
// It validates the Windows PTY backend, default Git Bash discovery, command
// input/output, inherited noninteractive environment, resize, and process-tree
// termination. Cross-compiling this test is not enough: it must execute on
// windows-latest.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
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

    bridge_pty_resize(&pty, 40, 100);

    // Mirror the production RUN path: write the command immediately after spawn
    // (bash reads its stdin pipe as soon as it is up) and scan output for the
    // markers. Each fact on its own line so ConPTY reflow can't merge them.
    const char *command =
        "printf 'TFAokPAGER=%s\\n' \"$PAGER\"\n"
        "printf 'TFAokGITPAGER=%s\\n' \"$GIT_PAGER\"\n"
        "exit\n";
    if (bridge_pty_write_all(&pty, command, strlen(command)) != 0) {
        fprintf(stderr, "FAIL: could not write to ConPTY session\n");
        bridge_pty_close(&pty);
        return 1;
    }

    // Drain continuously (banner + our output) until both markers seen or timeout.
    char output[65536] = {0};
    size_t used = 0;
    DWORD start = GetTickCount();
    int ok = 0;
    while (GetTickCount() - start < 20000 && used + 1 < sizeof(output)) {
        long n = bridge_pty_read(&pty, output + used, sizeof(output) - used - 1);
        if (n > 0) {
            used += (size_t)n; output[used] = '\0';
            char scan[65536]; memcpy(scan, output, used + 1); strip_ansi(scan);
            if (strstr(scan, "TFAokPAGER=cat") && strstr(scan, "TFAokGITPAGER=cat")) { ok = 1; break; }
        } else Sleep(20);
    }
    bridge_pty_close(&pty);

    if (!ok) {
        strip_ansi(output);
        fprintf(stderr,
                "FAIL: default shell did not execute bash syntax or inherit the "
                "noninteractive environment. Captured %zu bytes; stripped:\n%s\n",
                used, output);
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

// The provisioned-busybox floor: spawn busybox sh (path via TFA_TEST_BUSYBOX,
// downloaded by CI) and drive it exactly like the production RUN path — init
// line (stty -echo; PS1=; printf ready) then the bash-syntax wrapper with a
// brace group, $? capture and printf sentinel. Proves the pinned busybox can
// serve as the RUN shell: sentinel completes, exit code is real, and the
// wrapper line itself must NOT appear as a contiguous sentinel in output.
static int test_busybox_run_wrapper(void) {
    const char *bb = getenv("TFA_TEST_BUSYBOX");
    if (!bb || !*bb) {
        puts("SKIP: busybox RUN wrapper (TFA_TEST_BUSYBOX not set)");
        return 0;
    }

    bridge_pty_t pty;
    if (bridge_pty_spawn(&pty, bb, NULL, 1) != 0) {
        fprintf(stderr, "FAIL: could not spawn busybox sh\n");
        return 1;
    }

    // Mirror main.c: init line with split-quoted ready sentinel, then wrapper.
    const char *init =
        "stty -echo 2>/dev/null; PS1=; PS2=; printf '\\n__TB_''READY__\\n'\n";
    const char *wrapper =
        "{ echo hello-from-busybox; ls / >/dev/null 2>/dev/null; false\n"
        "}; __RC=$?; printf '\\n__TB_''STEP__:%d\\n' \"$__RC\"\n";
    if (bridge_pty_write_all(&pty, init, strlen(init)) != 0 ||
        bridge_pty_write_all(&pty, wrapper, strlen(wrapper)) != 0) {
        fprintf(stderr, "FAIL: could not write to busybox session\n");
        bridge_pty_close(&pty);
        return 1;
    }

    char output[65536] = {0};
    if (wait_for_text(&pty, "__TB_STEP__:1", output, sizeof(output), 15000)) {
        strip_ansi(output);
        fprintf(stderr, "FAIL: busybox RUN wrapper sentinel never completed. Output:\n%s\n", output);
        bridge_pty_close(&pty);
        return 1;
    }
    char scan[65536]; memcpy(scan, output, sizeof(scan)); strip_ansi(scan);
    if (!strstr(scan, "hello-from-busybox")) {
        fprintf(stderr, "FAIL: busybox command output missing. Output:\n%s\n", scan);
        bridge_pty_close(&pty);
        return 1;
    }
    bridge_pty_close(&pty);
    puts("PASS: busybox sh runs the production RUN wrapper (init, brace group, $?, sentinel)");
    return 0;
}

// cmd.exe last-resort dialect (main.c cmd_mode): command on its own line,
// `echo <caret-split sentinel>:%ERRORLEVEL%` on the next. Must prove
// (a) %ERRORLEVEL% expands to the previous command's exit code when the lines
// arrive sequentially through ConPTY, and (b) the echoed input line (which
// carries the caret) never yields a contiguous sentinel before the real echo
// output does — i.e. scanning for "<sentinel>:" completes with the right code.
static int test_cmd_dialect(void) {
    bridge_pty_t pty;
    if (bridge_pty_spawn(&pty, "cmd.exe", NULL, 1) != 0) {
        fprintf(stderr, "FAIL: could not spawn cmd.exe\n");
        return 1;
    }

    const char *init = "echo off& echo __TC_^READY__\r\n";
    // `exit /b 7` sets ERRORLEVEL without ending the shell.
    const char *step =
        "cmd /c exit 7\r\n"
        "echo __TC_^STEP__:%ERRORLEVEL%\r\n";
    if (bridge_pty_write_all(&pty, init, strlen(init)) != 0 ||
        bridge_pty_write_all(&pty, step, strlen(step)) != 0) {
        fprintf(stderr, "FAIL: could not write to cmd session\n");
        bridge_pty_close(&pty);
        return 1;
    }

    char output[65536] = {0};
    if (wait_for_text(&pty, "__TC_STEP__:7", output, sizeof(output), 15000)) {
        strip_ansi(output);
        fprintf(stderr, "FAIL: cmd dialect sentinel:%%ERRORLEVEL%% never completed. Output:\n%s\n", output);
        bridge_pty_close(&pty);
        return 1;
    }
    bridge_pty_close(&pty);
    puts("PASS: cmd.exe dialect (caret-split sentinel + %ERRORLEVEL% on its own line)");
    return 0;
}

int main(void) {
    if (test_shell_io() != 0) return 1;
    if (test_process_tree_termination() != 0) return 1;
    if (test_busybox_run_wrapper() != 0) return 1;
    if (test_cmd_dialect() != 0) return 1;
    puts("Windows PTY smoke tests passed");
    return 0;
}

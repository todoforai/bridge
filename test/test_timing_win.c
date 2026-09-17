// Windows twin of test_timing.c: pure bridge-side cost of a one-shot RUN over
// ConPTY with zero network — spawn → write → first byte → sentinel → close.
//
// Build (MSVC, from a vcvars64 shell):
//   cl /O2 /I. /Fe:build\test-timing-win.exe test\test_timing_win.c pty_win.c env_path.c policy.c json.c ws2_32.lib advapi32.lib userenv.lib shell32.lib ole32.lib
// Run:   build\test-timing-win.exe [shell]
//
// Columns (ms): spawn = CreatePseudoConsole+CreateProcess; warmup = spawn→first
// output byte; run = firstByte→sentinel; close = SIGKILL+bridge_pty_close.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "pty.h"

static double now_ms(void) {
    static LARGE_INTEGER f; if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return c.QuadPart * 1000.0 / f.QuadPart;
}

static const char *g_fmt;
static void time_case(const char *label, const char *cmd, const char *shell, int poll_ms) {
    double t0 = now_ms();
    bridge_pty_t p;
    if (bridge_pty_spawn(&p, shell, NULL, /*no_echo=*/1) != 0) {
        fprintf(stderr, "[%s] spawn failed\n", label);
        return;
    }
    double t_spawned = now_ms();

    const char *sentinel = "__BRIDGE_TIMING_SENTINEL__";
    char wrapped[4096];
    int wn = snprintf(wrapped, sizeof(wrapped),
        "stty -echo 2>/dev/null; PS1=; PS2=\n( %s\n); __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n", cmd, sentinel);
    if (wn <= 0 || (size_t)wn >= sizeof(wrapped)) { bridge_pty_close(&p); return; }
    bridge_pty_write_all(&p, wrapped, (size_t)wn);

    static char buf[1u << 20]; size_t total = 0;
    double t_first = -1;
    double deadline = now_ms() + 10000;
    while (now_ms() < deadline && total < sizeof(buf) - 1) {
        long n = bridge_pty_read(&p, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) { if (poll_ms) Sleep(poll_ms); else SwitchToThread(); continue; }
        if (t_first < 0) t_first = now_ms();
        total += (size_t)n;
        buf[total] = '\0';
        if (strstr(buf, sentinel)) break;
    }
    double t_done = now_ms();
    bridge_pty_signal(&p, 9);
    bridge_pty_close(&p);
    double t_closed = now_ms();

    printf("%-16s spawn %6.1f  warmup %6.1f  run %6.1f  close %6.1f  total %6.1f ms%s\n",
           label, t_spawned - t0, (t_first < 0 ? -1 : t_first - t_spawned),
           (t_first < 0 ? -1 : t_done - t_first), t_closed - t_done, t_closed - t0,
           strstr(buf, sentinel) ? "" : "  (NO SENTINEL)");
}

int main(int argc, char **argv) {
    const char *shell = argc > 1 ? argv[1] : NULL;
    int poll_ms = argc > 2 ? atoi(argv[2]) : 50;
    int v = argc > 3 ? atoi(argv[3]) : 0;
    const char *fmts[] = {
      "stty -echo 2>/dev/null; PS1=; PS2=\n( %s\n); __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
      "PS1=; PS2=\n( %s\n); __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
      "PS1=; PS2=\n{ %s\n}; __RC=$?; printf '\\n%s:%%d\\n' \"$__RC\"\n",
      "%s; printf '\\n%s\\n'\n",
      "%s; echo %s\n",
    };
    g_fmt = fmts[v]; printf("variant %d: %s\n", v, g_fmt);
    printf("shell=%s poll=%dms\n", shell ? shell : "(default)", poll_ms);
    const char *cases[][2] = {
        {"true", "true"}, {"true", "true"}, {"true", "true"},
        {"echo", "/bin/echo hi"}, {"echo", "/bin/echo hi"},
        {"git", "git --version"}, {"git", "git --version"},
        {"node", "node -e 0"}, {"node", "node -e 0"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        time_case(cases[i][0], cases[i][1], shell, poll_ms);
    return 0;
}

// ConPTY backend for the bridge PTY abstraction. Mirrors pty_posix.c but
// uses the Win10-1809+ pseudo-console API (CreatePseudoConsole) and a pair
// of anonymous pipes for stdin/stdout.
//
// Shell resolution (in order): explicit `shell` arg → $BRIDGE_SHELL →
// bash.exe in PATH → Git for Windows install paths → cmd.exe (last resort,
// where most catalog tools won't work). The RUN wrapper at main.c:723 is
// bash syntax, so a non-bash shell will produce broken output but the bridge
// itself stays alive.
//
// Auto-pause detection (bridge_pty_probe_blocked) is stubbed to 0 — Linux's
// /proc/<pid>/syscall has no clean Windows equivalent. STEP_PAUSED simply
// won't fire on Windows; the agent can still send INPUT manually.

#define WIN32_LEAN_AND_MEAN
#include "pty.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Resolve the shell path. Caller may pass NULL.
static const char *resolve_shell(const char *shell) {
    static char buf[MAX_PATH];
    if (shell && *shell) { snprintf(buf, sizeof(buf), "%s", shell); return buf; }
    const char *env = getenv("BRIDGE_SHELL");
    if (env && *env) { snprintf(buf, sizeof(buf), "%s", env); return buf; }
    if (SearchPathA(NULL, "bash.exe", NULL, sizeof(buf), buf, NULL) > 0) return buf;
    const char *fallbacks[] = {
        "C:\\Program Files\\Git\\bin\\bash.exe",
        "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
        NULL,
    };
    for (int i = 0; fallbacks[i]; i++) {
        if (GetFileAttributesA(fallbacks[i]) != INVALID_FILE_ATTRIBUTES) {
            snprintf(buf, sizeof(buf), "%s", fallbacks[i]);
            return buf;
        }
    }
    snprintf(buf, sizeof(buf), "cmd.exe");
    return buf;
}

int bridge_pty_spawn(bridge_pty_t *p, const char *shell, const char *cwd, int no_echo) {
    memset(p, 0, sizeof(*p));

    HANDLE in_read = NULL, in_write = NULL, out_read = NULL, out_write = NULL;
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = FALSE };
    if (!CreatePipe(&in_read, &in_write, &sa, 0))   goto fail;
    if (!CreatePipe(&out_read, &out_write, &sa, 0)) goto fail;

    COORD size = { 80, 24 };
    HPCON hpc = NULL;
    HRESULT hr = CreatePseudoConsole(size, in_read, out_write, 0, &hpc);
    if (FAILED(hr)) goto fail;

    // ConPTY duplicates the handles; close our copies of the child-side ends.
    CloseHandle(in_read);  in_read = NULL;
    CloseHandle(out_write); out_write = NULL;

    // STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE.
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(si);

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!si.lpAttributeList) { ClosePseudoConsole(hpc); goto fail; }
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size) ||
        !UpdateProcThreadAttribute(si.lpAttributeList, 0,
                                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                    hpc, sizeof(hpc), NULL, NULL)) {
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        ClosePseudoConsole(hpc);
        goto fail;
    }

    const char *sh = resolve_shell(shell);
    char cmdline[MAX_PATH + 32];
    // Quoting: shell path may contain spaces. ConPTY child gets argv[0] = sh.
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", sh);

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                             EXTENDED_STARTUPINFO_PRESENT,
                             NULL, (cwd && *cwd) ? cwd : NULL,
                             &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    if (!ok) { ClosePseudoConsole(hpc); goto fail; }
    CloseHandle(pi.hThread);

    p->h_process    = pi.hProcess;
    p->h_pcon       = hpc;
    p->h_in_write   = in_write;
    p->h_out_read   = out_read;
    p->pid          = pi.dwProcessId;
    p->alive        = 1;
    (void)no_echo;  // ConPTY has no direct ECHO toggle; bash -c handles it.
    return 0;

fail:
    if (in_read)   CloseHandle(in_read);
    if (in_write)  CloseHandle(in_write);
    if (out_read)  CloseHandle(out_read);
    if (out_write) CloseHandle(out_write);
    return -1;
}

void bridge_pty_resize(bridge_pty_t *p, uint16_t rows, uint16_t cols) {
    if (!p || !p->h_pcon) return;
    COORD size = { (SHORT)cols, (SHORT)rows };
    ResizePseudoConsole((HPCON)p->h_pcon, size);
}

int bridge_pty_write_all(bridge_pty_t *p, const void *buf, size_t len) {
    const uint8_t *b = buf;
    size_t written = 0;
    while (written < len) {
        DWORD n = 0;
        if (!WriteFile((HANDLE)p->h_in_write, b + written, (DWORD)(len - written), &n, NULL))
            return -1;
        if (n == 0) return -1;
        written += n;
    }
    return 0;
}

long bridge_pty_read(bridge_pty_t *p, void *buf, size_t len) {
    DWORD avail = 0;
    if (!PeekNamedPipe((HANDLE)p->h_out_read, NULL, 0, NULL, &avail, NULL)) {
        // Pipe broken (child exited and pipe drained) → treat as EOF/no-data.
        return 0;
    }
    if (avail == 0) return 0;
    DWORD want = avail < (DWORD)len ? avail : (DWORD)len;
    DWORD got = 0;
    if (!ReadFile((HANDLE)p->h_out_read, buf, want, &got, NULL)) return 0;
    return (long)got;
}

int bridge_pty_signal(bridge_pty_t *p, int sig) {
    // Only SIGINT (2), SIGTERM (15), SIGKILL (9) are reachable here — main.c
    // converts the JSON name to a number.
    if (sig == 2) {
        // Ctrl-C through the PTY (line discipline delivers it to the fg pgrp).
        return bridge_pty_write_all(p, "\x03", 1) == 0 ? 1 : 0;
    }
    if (sig == 15 || sig == 9) {
        return TerminateProcess((HANDLE)p->h_process, sig == 9 ? 9 : 15) ? 1 : 0;
    }
    return 0;
}

int bridge_pty_reap(bridge_pty_t *p, int *code) {
    if (!p->alive) return 0;
    DWORD wr = WaitForSingleObject((HANDLE)p->h_process, 0);
    if (wr != WAIT_OBJECT_0) return 0;
    DWORD ec = 0;
    GetExitCodeProcess((HANDLE)p->h_process, &ec);
    *code = (int)ec;
    p->alive = 0;
    return 1;
}

int bridge_pty_close(bridge_pty_t *p) {
    int code = 0;
    if (p->h_pcon)     { ClosePseudoConsole((HPCON)p->h_pcon);  p->h_pcon = NULL; }
    if (p->h_in_write) { CloseHandle((HANDLE)p->h_in_write);    p->h_in_write = NULL; }
    if (p->h_out_read) { CloseHandle((HANDLE)p->h_out_read);    p->h_out_read = NULL; }
    if (p->h_process) {
        if (p->alive) {
            WaitForSingleObject((HANDLE)p->h_process, 2000);
            DWORD ec = 0;
            GetExitCodeProcess((HANDLE)p->h_process, &ec);
            code = (int)ec;
            p->alive = 0;
        }
        CloseHandle((HANDLE)p->h_process);
        p->h_process = NULL;
    }
    return code;
}

int bridge_pty_pollfd(const bridge_pty_t *p) {
    (void)p;
    return -1;  // Not meaningful on Windows; main loop drives via mongoose.
}

int bridge_pty_probe_blocked(const bridge_pty_t *p, int echo_baseline,
                             long *fg_pid, int *password_prompt) {
    (void)p; (void)echo_baseline;
    if (fg_pid) *fg_pid = 0;
    if (password_prompt) *password_prompt = 0;
    return 0;
}

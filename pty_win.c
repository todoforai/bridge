// Windows ConPTY backend.
//
// Note: this implements the bridge_pty_* API. The bridge's current main loop
// (main.c) uses poll() on a POSIX fd, which doesn't exist on Windows. Wiring
// this backend into a Windows event loop is a separate task — when that's done,
// callers should use the HANDLEs in bridge_pty_t directly with overlapped IO
// or WaitForMultipleObjects. bridge_pty_pollfd() returns -1 here to make it
// obvious that poll() is not the right primitive on Windows.

#ifdef _WIN32

#include "pty.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

// ConPTY requires Windows 10 1809+. _WIN32_WINNT must be >= 0x0A00.
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>

static HRESULT create_conpty(bridge_pty_t *p, COORD size,
                             HANDLE *child_in_read, HANDLE *child_out_write) {
    HANDLE in_r = NULL, in_w = NULL, out_r = NULL, out_w = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    if (!CreatePipe(&in_r, &in_w, &sa, 0)) return HRESULT_FROM_WIN32(GetLastError());
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) {
        CloseHandle(in_r); CloseHandle(in_w);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    HRESULT hr = CreatePseudoConsole(size, in_r, out_w, 0, &p->hPC);
    // Child end of pipes is owned by ConPTY now; we keep our ends.
    if (FAILED(hr)) {
        CloseHandle(in_r); CloseHandle(in_w);
        CloseHandle(out_r); CloseHandle(out_w);
        return hr;
    }
    *child_in_read   = in_r;   // owned by ConPTY; we keep in_w
    *child_out_write = out_w;  // owned by ConPTY; we keep out_r
    p->hPipeIn  = in_w;
    p->hPipeOut = out_r;
    return S_OK;
}

int bridge_pty_spawn(bridge_pty_t *p, const char *shell) {
    memset(p, 0, sizeof *p);

    COORD size = { 80, 24 };
    HANDLE child_in_read = NULL, child_out_write = NULL;
    if (FAILED(create_conpty(p, size, &child_in_read, &child_out_write))) return -1;

    // Build STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE.
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!attrs) goto fail;
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) goto fail;
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE,
                                   p->hPC, sizeof p->hPC, NULL, NULL)) goto fail;

    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof si;
    si.lpAttributeList = attrs;

    PROCESS_INFORMATION pi = {0};
    // CreateProcessA wants a writable command line buffer.
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "%s", shell);

    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                             EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                             &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
    // Child owns these now; close our copies so EOF propagates correctly.
    CloseHandle(child_in_read);
    CloseHandle(child_out_write);

    if (!ok) goto fail;

    CloseHandle(pi.hThread);
    p->hProcess = pi.hProcess;
    p->pid      = pi.dwProcessId;
    p->alive    = 1;
    return 0;

fail:
    if (p->hPC)      ClosePseudoConsole(p->hPC);
    if (p->hPipeIn)  CloseHandle(p->hPipeIn);
    if (p->hPipeOut) CloseHandle(p->hPipeOut);
    memset(p, 0, sizeof *p);
    return -1;
}

void bridge_pty_resize(bridge_pty_t *p, uint16_t rows, uint16_t cols) {
    if (!p->hPC) return;
    COORD size = { (SHORT)cols, (SHORT)rows };
    (void)ResizePseudoConsole(p->hPC, size);
}

int bridge_pty_write_all(bridge_pty_t *p, const void *buf, size_t len) {
    const uint8_t *b = buf;
    size_t written = 0;
    while (written < len) {
        DWORD n = 0;
        if (!WriteFile(p->hPipeIn, b + written, (DWORD)(len - written), &n, NULL)) return -1;
        written += n;
    }
    return 0;
}

long bridge_pty_read(bridge_pty_t *p, void *buf, size_t len) {
    DWORD n = 0;
    if (!ReadFile(p->hPipeOut, buf, (DWORD)len, &n, NULL)) {
        DWORD e = GetLastError();
        if (e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF) return 0;
        return -1;
    }
    return (long)n;
}

int bridge_pty_signal(bridge_pty_t *p, int sig) {
    if (!p->hProcess) return 0;
    switch (sig) {
        case SIGINT:
            // Best-effort: send Ctrl+C through the pty input.
            return bridge_pty_write_all(p, "\x03", 1) == 0;
        case SIGTERM:
        case SIGKILL:
            return TerminateProcess(p->hProcess, 1) ? 1 : 0;
        default:
            return 0;
    }
}

int bridge_pty_reap(bridge_pty_t *p, int *code) {
    if (!p->alive) return 0;
    DWORD ec = 0;
    if (!GetExitCodeProcess(p->hProcess, &ec)) return 0;
    if (ec == STILL_ACTIVE) return 0;
    p->alive = 0;
    *code = (int)ec;
    return 1;
}

int bridge_pty_close(bridge_pty_t *p) {
    int code = 0;
    if (p->alive && p->hProcess) {
        WaitForSingleObject(p->hProcess, INFINITE);
        DWORD ec = 0;
        if (GetExitCodeProcess(p->hProcess, &ec)) code = (int)ec;
        p->alive = 0;
    }
    if (p->hPC)      { ClosePseudoConsole(p->hPC); p->hPC = NULL; }
    if (p->hPipeIn)  { CloseHandle(p->hPipeIn);    p->hPipeIn = NULL; }
    if (p->hPipeOut) { CloseHandle(p->hPipeOut);   p->hPipeOut = NULL; }
    if (p->hProcess) { CloseHandle(p->hProcess);   p->hProcess = NULL; }
    return code;
}

int bridge_pty_pollfd(const bridge_pty_t *p) {
    (void)p;
    return -1;  // Windows callers must use overlapped IO on hPipeOut directly.
}

#endif // _WIN32

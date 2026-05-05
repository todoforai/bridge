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
// Auto-pause detection: implemented via NtQuerySystemInformation +
// JobObjectBasicProcessIdList — see "Auto-pause detection" section below.
// password_prompt is not exposed via the ConPTY API (the child's ECHO bit
// lives in conhost), so it is always 0 on Windows.

#define WIN32_LEAN_AND_MEAN
#include "pty.h"

#include <windows.h>
#include <winternl.h>   // UNICODE_STRING, used by the SYSTEM_PROCESS_INFORMATION layout
#include <stdint.h>
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

    // Job object: groups the shell with every process it spawns. Closing the
    // job handle (or TerminateJobObject) kills the whole tree at once — the
    // POSIX-pgrp-equivalent we'd otherwise lack on Windows. Created suspended-
    // by-flag (CREATE_SUSPENDED) so we can assign before the shell runs.
    HANDLE job = CreateJobObjectA(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    PROCESS_INFORMATION pi = {0};
    // EXTENDED_STARTUPINFO_PRESENT: STARTUPINFOEX in use.
    // CREATE_SUSPENDED: assign-to-job before first instruction runs.
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED;
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                             flags, NULL, (cwd && *cwd) ? cwd : NULL,
                             &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    if (!ok) {
        if (job) CloseHandle(job);
        ClosePseudoConsole(hpc);
        goto fail;
    }
    if (job && !AssignProcessToJobObject(job, pi.hProcess)) {
        // Already-jobbed (rare: nested job without BREAKAWAY) — proceed without.
        CloseHandle(job); job = NULL;
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    p->h_process    = pi.hProcess;
    p->h_pcon       = hpc;
    p->h_in_write   = in_write;
    p->h_out_read   = out_read;
    p->h_job        = job;
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
        // Prefer the job: nukes the shell AND every child it spawned. Falls
        // back to the process if no job (rare: AssignProcessToJobObject failed).
        if (p->h_job) {
            return TerminateJobObject((HANDLE)p->h_job, sig == 9 ? 9 : 15) ? 1 : 0;
        }
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
    // Closing the job handle (with KILL_ON_JOB_CLOSE set) reaps any stragglers.
    if (p->h_job) { CloseHandle((HANDLE)p->h_job); p->h_job = NULL; }
    return code;
}

int bridge_pty_pollfd(const bridge_pty_t *p) {
    (void)p;
    return -1;  // Not meaningful on Windows; main loop drives via mongoose.
}

// ── Auto-pause detection ────────────────────────────────────────────────────
//
// Windows analog of pty_posix.c's /proc/<pid>/syscall + tcgetpgrp probe.
//
// "Process group": there is no pgrp on Windows. We use the per-session Job
// Object as the surrogate — it contains the shell and every descendant
// (assigned at spawn time, see bridge_pty_spawn). conhost.exe is NOT in the
// job (it's spawned by CreatePseudoConsole via csrss), so we don't have to
// filter it out.
//
// "Blocked in n_tty_read": ConPTY clients call ReadConsole/ReadFile(CONIN$),
// which translates to an ALPC request to conhost. A thread parked there
// shows up in NtQuerySystemInformation(SystemProcessInformation) as
// ThreadState=Waiting (5) and WaitReason=WrLpcReply (17). We deliberately
// don't accept WrUserRequest — it's the generic "waiting on an event" reason
// (every idle worker thread is in it) and would produce false positives.
//
// Gating: main.c only calls this while the session is in SESS_RUNNING (i.e.
// between sentinels), so a shell idling at its prompt does not produce
// false positives — the shell isn't "running" then.
//
// password_prompt: not implemented on Windows. The child's
// ENABLE_ECHO_INPUT bit lives in conhost and isn't exposed through any
// ConPTY API. Always reported as 0.

#define BRIDGE_SystemProcessInformation 5
#define BRIDGE_STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#define BRIDGE_ThreadStateWaiting          5
#define BRIDGE_WrLpcReply                  17

// Subset of SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION sufficient
// to walk the snapshot. Layout is ABI-stable since NT 4.0; using local names
// to avoid clashing with winternl.h's partial declarations.
typedef struct {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    HANDLE        UniqueProcess;   // CLIENT_ID.UniqueProcess (PID)
    HANDLE        UniqueThread;    // CLIENT_ID.UniqueThread (TID)
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} bridge_sys_thread_info_t;

typedef struct {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    BYTE           Reserved1[48];
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    // Threads array follows immediately after a fixed-size header. The header
    // size beyond this point varies across Windows versions (HandleCount,
    // SessionId, working-set fields, etc.), so we don't pin a struct layout —
    // we walk by NextEntryOffset and start threads at offset
    // sizeof(SYSTEM_PROCESS_INFORMATION) computed dynamically. See enum loop.
} bridge_sys_proc_info_t;

typedef LONG (WINAPI *bridge_NtQuerySystemInformation_fn)(
    ULONG, PVOID, ULONG, PULONG);

// Resolve once. ntdll is guaranteed loaded in every Win32 process.
static bridge_NtQuerySystemInformation_fn bridge_resolve_ntqsi(void) {
    static bridge_NtQuerySystemInformation_fn fn = NULL;
    static int tried = 0;
    if (!tried) {
        tried = 1;
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            fn = (bridge_NtQuerySystemInformation_fn)
                 GetProcAddress(ntdll, "NtQuerySystemInformation");
        }
    }
    return fn;
}

// Snapshot all processes. Caller frees with HeapFree(GetProcessHeap(),0,*).
// Returns NULL on failure.
static bridge_sys_proc_info_t *bridge_snapshot_processes(void) {
    bridge_NtQuerySystemInformation_fn ntqsi = bridge_resolve_ntqsi();
    if (!ntqsi) return NULL;
    ULONG cap = 256 * 1024;
    for (int attempt = 0; attempt < 6; attempt++) {
        void *buf = HeapAlloc(GetProcessHeap(), 0, cap);
        if (!buf) return NULL;
        ULONG need = 0;
        LONG st = ntqsi(BRIDGE_SystemProcessInformation, buf, cap, &need);
        if (st == 0) return (bridge_sys_proc_info_t *)buf;
        HeapFree(GetProcessHeap(), 0, buf);
        if (st != BRIDGE_STATUS_INFO_LENGTH_MISMATCH) return NULL;
        // Grow to (returned_need + slack). Snapshots can grow between calls.
        cap = (need ? need : cap * 2) + 64 * 1024;
    }
    return NULL;
}

static int bridge_pid_in_list(DWORD pid, const DWORD *pids, ULONG n) {
    for (ULONG i = 0; i < n; i++) {
        if (pids[i] == pid) return 1;
    }
    return 0;
}

// Read the job's PID list into a malloc'd array. Caller frees. Returns count
// in *out_count; returns NULL on failure.
static DWORD *bridge_job_pid_list(HANDLE job, ULONG *out_count) {
    *out_count = 0;
    if (!job) return NULL;
    ULONG cap = 64;
    for (int attempt = 0; attempt < 4; attempt++) {
        // JOBOBJECT_BASIC_PROCESS_ID_LIST is a variable-length struct with a
        // ULONG_PTR ProcessIdList[1] tail; size = header + (cap-1)*sizeof(ULONG_PTR).
        size_t bytes = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)
                     + (cap > 0 ? (cap - 1) * sizeof(ULONG_PTR) : 0);
        JOBOBJECT_BASIC_PROCESS_ID_LIST *list =
            (JOBOBJECT_BASIC_PROCESS_ID_LIST *)HeapAlloc(GetProcessHeap(), 0, bytes);
        if (!list) return NULL;
        DWORD ret_len = 0;
        BOOL ok = QueryInformationJobObject(job, JobObjectBasicProcessIdList,
                                            list, (DWORD)bytes, &ret_len);
        if (ok || GetLastError() == ERROR_MORE_DATA) {
            ULONG n = list->NumberOfProcessIdsInList;
            if (!ok && n > cap) {
                // Grow and retry.
                HeapFree(GetProcessHeap(), 0, list);
                cap = n + 16;
                continue;
            }
            DWORD *pids = (DWORD *)malloc(sizeof(DWORD) * (n ? n : 1));
            if (!pids) { HeapFree(GetProcessHeap(), 0, list); return NULL; }
            for (ULONG i = 0; i < n; i++) pids[i] = (DWORD)list->ProcessIdList[i];
            HeapFree(GetProcessHeap(), 0, list);
            *out_count = n;
            return pids;
        }
        HeapFree(GetProcessHeap(), 0, list);
        return NULL;
    }
    return NULL;
}

int bridge_pty_probe_blocked(const bridge_pty_t *p, int echo_baseline,
                             long *fg_pid, int *password_prompt) {
    (void)echo_baseline;  // No ECHO introspection on Windows; see file header.
    if (fg_pid) *fg_pid = 0;
    if (password_prompt) *password_prompt = 0;
    if (!p || !p->alive || !p->h_job) return 0;

    ULONG njobpids = 0;
    DWORD *jobpids = bridge_job_pid_list((HANDLE)p->h_job, &njobpids);
    if (!jobpids || njobpids == 0) { free(jobpids); return 0; }

    bridge_sys_proc_info_t *snap = bridge_snapshot_processes();
    if (!snap) { free(jobpids); return 0; }

    // Resolve the per-process header size (offset to the SYSTEM_THREAD_INFORMATION
    // array) once from the first entry that has both NextEntryOffset and
    // threads. Layout is uniform across entries within one snapshot, but the
    // header has grown across Windows versions (extra trailing fields), so
    // we compute it rather than hardcode. Fallback only triggers in the
    // pathological case of a single-process snapshot with zero threads, which
    // can't happen here (the snapshot always contains _Total + System).
    size_t thread_offset = 0;
    for (bridge_sys_proc_info_t *q = snap; ; ) {
        if (q->NextEntryOffset != 0 && q->NumberOfThreads > 0) {
            thread_offset = (size_t)q->NextEntryOffset
                - (size_t)q->NumberOfThreads * sizeof(bridge_sys_thread_info_t);
            break;
        }
        if (q->NextEntryOffset == 0) break;
        q = (bridge_sys_proc_info_t *)((uint8_t *)q + q->NextEntryOffset);
    }
    if (thread_offset == 0) thread_offset = 0x100;  // Conservative Win10/11 default.

    long blocked_pid = 0;
    bridge_sys_proc_info_t *pi = snap;
    for (;;) {
        DWORD pid = (DWORD)(uintptr_t)pi->UniqueProcessId;
        if (pid != 0 && bridge_pid_in_list(pid, jobpids, njobpids)) {
            bridge_sys_thread_info_t *th =
                (bridge_sys_thread_info_t *)((uint8_t *)pi + thread_offset);
            for (ULONG i = 0; i < pi->NumberOfThreads; i++) {
                if (th[i].ThreadState == BRIDGE_ThreadStateWaiting &&
                    th[i].WaitReason == BRIDGE_WrLpcReply) {
                    blocked_pid = (long)pid;
                    break;
                }
            }
            if (blocked_pid) break;
        }
        if (pi->NextEntryOffset == 0) break;
        pi = (bridge_sys_proc_info_t *)((uint8_t *)pi + pi->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, snap);
    free(jobpids);

    if (blocked_pid == 0) return 0;
    if (fg_pid) *fg_pid = blocked_pid;
    return 1;
}

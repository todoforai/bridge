// ConPTY backend for the bridge PTY abstraction. Mirrors pty_posix.c but
// uses the Win10-1809+ pseudo-console API (CreatePseudoConsole) and a pair
// of anonymous pipes for stdin/stdout.
//
// Shell resolution (in order): explicit `shell` arg → $BRIDGE_SHELL → Git for
// Windows install paths (bash.exe or sh.exe, bin\ then usr\bin\) → bash.exe /
// sh.exe in PATH (never the System32 WSL stub) → provisioned busybox →
// cmd.exe (last resort, where most catalog tools won't work). The RUN wrapper is
// bash syntax, so a non-bash shell will produce broken output but the bridge
// itself stays alive.
//
// Auto-pause detection: implemented via NtQuerySystemInformation +
// JobObjectBasicProcessIdList — see "Auto-pause detection" section below.
// password_prompt is not exposed via the ConPTY API (the child's ECHO bit
// lives in conhost), so it is always 0 on Windows.

#define WIN32_LEAN_AND_MEAN
#include "pty.h"
#include "env_path.h"
#include "tools.h"   // bridge_win_quote_arg

#include <windows.h>
#include <winternl.h>   // UNICODE_STRING, used by the SYSTEM_PROCESS_INFORMATION layout
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── provisioned shell (busybox-w32) ─────────────────────────────────────────
// When neither Git Bash nor a PATH bash exists, the bridge guarantees its own
// POSIX shell: a pinned busybox-w32 (ash + coreutils applets, ~660 KB, 64-bit
// Unicode build) mirrored as a todoforai/bridge release asset. Downloaded once
// to %USERPROFILE%\.todoforai\shell\sh.exe, sha256-verified against the pin
// below. GPLv2; upstream https://github.com/rmyorston/busybox-w32.
#define SHELL_ASSET_URL \
    "https://github.com/todoforai/bridge/releases/download/shell-busybox-FRP-6075/busybox-w64u.exe"
#define SHELL_ASSET_SHA256 \
    "6E263D154D8548D1EB936F65D1D8312C80DF31C45974E48D6335E4DCC0F4F34C"

// %USERPROFILE%\.todoforai\shell\sh.exe. Returns 0 on success.
static int canonical_shell_path(char *buf, size_t cap) {
    const char *home = getenv("USERPROFILE");
    if (!home || !*home) return -1;
    int n = snprintf(buf, cap, "%s\\.todoforai\\shell\\sh.exe", home);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

// Fire-and-forget download of the pinned busybox to the canonical path.
// The bridge has no TLS client (update.c precedent), so shell out to
// powershell: fetch to a per-PID .part file, verify sha256, atomic rename.
// Idempotent per process; safe across racing bridge processes (unique temp,
// Move-Item -Force). Failure is silent here — the resolver keeps returning
// cmd.exe and RUN keeps failing fast with a self-diagnosing error.
static void provision_shell_async(void) {
    static int started = 0;
    if (started) return;
    started = 1;

    char dest[MAX_PATH];
    if (canonical_shell_path(dest, sizeof dest) != 0) return;
    // dest is interpolated into a single-quoted powershell string below; a
    // quote in USERPROFILE (C:\Users\O'Brien) would break out of it. Rare
    // enough to just skip — NO_BASH-mode guidance still tells the user what
    // to install by hand.
    if (strpbrk(dest, "'\"")) return;

    // mkdir -p %USERPROFILE%\.todoforai\shell
    char dir[MAX_PATH];
    snprintf(dir, sizeof dir, "%s", dest);
    char *slash = strrchr(dir, '\\');
    if (!slash) return;
    *slash = '\0';
    char parent[MAX_PATH];
    snprintf(parent, sizeof parent, "%s", dir);
    char *pslash = strrchr(parent, '\\');
    if (pslash) { *pslash = '\0'; CreateDirectoryA(parent, NULL); }
    CreateDirectoryA(dir, NULL);

    char pscmd[2048];
    int n = snprintf(pscmd, sizeof pscmd,
        "powershell -NoProfile -NonInteractive -Command "
        "\"$ProgressPreference='SilentlyContinue';"
        "$d='%s';$t=$d+'.'+$PID+'.part';"
        "try{Invoke-WebRequest -UseBasicParsing -Uri '%s' -OutFile $t;"
        "if((Get-FileHash $t -Algorithm SHA256).Hash -eq '%s')"
        "{Move-Item -Force $t $d}else{Remove-Item -Force $t}}"
        "catch{if(Test-Path $t){Remove-Item -Force $t -ErrorAction SilentlyContinue}}\"",
        dest, SHELL_ASSET_URL, SHELL_ASSET_SHA256);
    if (n <= 0 || (size_t)n >= sizeof pscmd) return;

    fprintf(stderr, "note: no bash found — provisioning minimal shell (busybox) to %s\n", dest);
    fflush(stderr);

    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (CreateProcessA(NULL, pscmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);   // don't wait: resolver re-checks per call
    }
}

// Resolve the shell path. Caller may pass NULL.
// True if `path` lives in System32 — i.e. the WSL launcher (…\System32\bash.exe).
// That stub is NOT a POSIX shell: with no WSL distro installed it just prints a
// notice and exits, and even with one it runs a Linux userland the bridge's
// Windows tool paths don't match. RUN wrappers are Git-Bash semantics, so skip
// it and prefer Git for Windows bash.
static int is_wsl_stub(const char *path) {
    char sysdir[MAX_PATH];
    UINT n = GetSystemDirectoryA(sysdir, sizeof(sysdir));   // e.g. C:\Windows\System32
    if (n == 0 || n >= sizeof(sysdir)) return 0;
    return _strnicmp(path, sysdir, n) == 0;
}

// True for a bash binary (bash.exe / bash), which accepts --norc --noprofile.
static int bridge_shell_is_bash(const char *sh) {
    const char *base = sh;
    for (const char *p = sh; *p; p++) if (*p == '\\' || *p == '/') base = p + 1;
    return _stricmp(base, "bash.exe") == 0 || _stricmp(base, "bash") == 0;
}

// Git\bin\{bash,sh}.exe are launcher shims that exec ..\usr\bin\bash.exe. If
// that target is gone (renamed `bash.exe.disabled` by hardening tools) the shim
// prints "…usr\bin\bash.exe not found" and exits 1 — every RUN then died
// silently until timeout. Treat such a shim as absent; usr\bin\sh.exe (a real
// msys2 bash copy) is probed later in the list.
static int is_orphan_git_shim(const char *path) {
    char target[MAX_PATH];
    snprintf(target, sizeof target, "%s", path);
    char *leaf = strrchr(target, '\\');
    if (!leaf) return 0;
    *leaf = '\0';                                   // ...\Git\bin or ...\Git\usr\bin
    size_t n = strlen(target);
    if (n < 4 || _stricmp(target + n - 4, "\\bin") != 0) return 0;
    if (n >= 8 && _stricmp(target + n - 8, "\\usr\\bin") == 0) return 0;  // real binary
    // Only a Git for Windows root (has git-bash.exe) — never reject e.g. cygwin's real bin\bash.exe.
    snprintf(target + n - 4, sizeof target - (n - 4), "\\git-bash.exe");
    if (GetFileAttributesA(target) == INVALID_FILE_ATTRIBUTES) return 0;
    snprintf(target + n - 4, sizeof target - (n - 4), "\\usr\\bin\\bash.exe");
    return GetFileAttributesA(target) == INVALID_FILE_ATTRIBUTES;
}

// Public (identity.c reports it; main.c RUN pre-checks it) so the shell the
// backend/agent sees is the shell that actually spawns — never a guess.
const char *bridge_pty_resolve_shell(const char *shell) {
    static char buf[MAX_PATH];
    // Same PATH for every caller (identity, RUN pre-check, spawn): the
    // managed-tools dirs are prepended before the PATH probe below, exactly
    // as spawn does. Idempotent, so spawn's own call becomes a no-op.
    bridge_prepend_tools_path_win();
    if (shell && *shell) { snprintf(buf, sizeof(buf), "%s", shell); return buf; }
    const char *env = getenv("BRIDGE_SHELL");
    if (env && *env) { snprintf(buf, sizeof(buf), "%s", env); return buf; }

    // Git for Windows first — it's the shell RUN/tool catalog assume. The RUN
    // wrapper is bash syntax, so every bash.exe location is probed before any
    // sh.exe. sh.exe is worth probing at all because it's the same msys2
    // binary and an install whose bash.exe was renamed/removed (seen in the
    // wild as `bash.exe.disabled`) still ships a perfectly good sh.exe —
    // vastly better than falling through to busybox or cmd.exe.
    const char *fallbacks[] = {
        "C:\\Program Files\\Git\\bin\\bash.exe",
        "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
        "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
        "C:\\Program Files (x86)\\Git\\usr\\bin\\bash.exe",
        "C:\\Program Files\\Git\\bin\\sh.exe",
        "C:\\Program Files\\Git\\usr\\bin\\sh.exe",
        "C:\\Program Files (x86)\\Git\\bin\\sh.exe",
        "C:\\Program Files (x86)\\Git\\usr\\bin\\sh.exe",
        NULL,
    };
    for (int i = 0; fallbacks[i]; i++) {
        if (GetFileAttributesA(fallbacks[i]) != INVALID_FILE_ATTRIBUTES &&
            !is_orphan_git_shim(fallbacks[i])) {
            snprintf(buf, sizeof(buf), "%s", fallbacks[i]);
            return buf;
        }
    }
    // Then a PATH bash.exe/sh.exe, but never the System32 WSL launcher.
    // sh.exe is checked second: a PATH bash is the better-known shape, and
    // the provisioned busybox (also sh.exe) is reached by the branch below
    // even if it somehow landed on PATH.
    if (SearchPathA(NULL, "bash.exe", NULL, sizeof(buf), buf, NULL) > 0 && !is_wsl_stub(buf) && !is_orphan_git_shim(buf))
        return buf;
    if (SearchPathA(NULL, "sh.exe", NULL, sizeof(buf), buf, NULL) > 0 && !is_wsl_stub(buf) && !is_orphan_git_shim(buf))
        return buf;

    // Provisioned busybox sh (the guaranteed floor — see provision_shell_async).
    if (canonical_shell_path(buf, sizeof(buf)) == 0 &&
        GetFileAttributesA(buf) != INVALID_FILE_ATTRIBUTES)
        return buf;

    // Nothing yet: kick the one-time async provisioning and fall back to
    // cmd.exe for now. RUN refuses cmd.exe (NO_BASH pre-check in main.c) and
    // the resolver re-runs per call, so the first RUN after the download
    // lands picks up sh.exe automatically. Interactive PTY sessions still
    // work in cmd.exe, so refusing to spawn would break more than it fixes.
    provision_shell_async();
    snprintf(buf, sizeof(buf), "cmd.exe");
    return buf;
}

int bridge_pty_spawn(bridge_pty_t *p, const char *shell, const char *cwd, int no_echo) {
    memset(p, 0, sizeof(*p));

    // Make the managed tools binDir discoverable: CreateProcessA below inherits
    // our env (lpEnvironment=NULL), so prepend it to the bridge process PATH.
    bridge_prepend_tools_path_win();

    HANDLE in_read = NULL, in_write = NULL, out_read = NULL, out_write = NULL;
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = FALSE };
    if (!CreatePipe(&in_read, &in_write, &sa, 0))   goto fail;
    if (!CreatePipe(&out_read, &out_write, &sa, 0)) goto fail;

    COORD size = { 80, 24 };
    HPCON hpc = NULL;
    HRESULT hr = CreatePseudoConsole(size, in_read, out_write, 0, &hpc);
    // Carry the reason into GetLastError so the `fail:` translation below
    // reports it (the HRESULT wraps a Win32 code for the cases we can hit:
    // handle/memory exhaustion).
    if (FAILED(hr)) { SetLastError(HRESULT_CODE(hr)); goto fail; }

    // ConPTY duplicates the handles; close our copies of the child-side ends.
    CloseHandle(in_read);  in_read = NULL;
    CloseHandle(out_write); out_write = NULL;

    // STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE.
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(si);
    // Force the child onto the pseudoconsole ONLY. Without STARTF_USESTDHANDLES
    // (and NULL std handles), CreateProcess with bInheritHandles=FALSE
    // duplicates the PARENT's std handles into the child — so in a headless /
    // service / CI context (no interactive console) the child bypasses the
    // ConPTY, writes to the parent's real console, sees stdin EOF and exits
    // immediately. Setting this with NULL handles makes the pcon attribute the
    // sole source of the child's stdio. See MS "Creating a Pseudoconsole session".
    si.StartupInfo.dwFlags   = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput  = NULL;
    si.StartupInfo.hStdOutput = NULL;
    si.StartupInfo.hStdError  = NULL;

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

    // Bridge RUNs are automated even though they execute inside a ConPTY.
    // Keep common CLIs from opening interactive pagers such as less(1),
    // which otherwise park the step at "(END)" and require injected `q`.
    SetEnvironmentVariableA("PAGER", "cat");
    SetEnvironmentVariableA("GH_PAGER", "cat");
    SetEnvironmentVariableA("GIT_PAGER", "cat");
    SetEnvironmentVariableA("MANPAGER", "cat");
    SetEnvironmentVariableA("SYSTEMD_PAGER", "cat");
    SetEnvironmentVariableA("AWS_PAGER", "");
    // For `__detach` (nohup shim): the job-free process to parent on.
    { char pid_s[16]; snprintf(pid_s, sizeof pid_s, "%lu", (unsigned long)GetCurrentProcessId()); SetEnvironmentVariableA("TODOFORAI_BRIDGE_PID", pid_s); }
    // Mirror pty_posix.c: keep prompts out of OUTPUT. Git Bash rc files
    // (git-prompt.sh) may re-set PS1 — main.c's spawn-time init line
    // (`stty -echo; PS1=; …` + ready-sentinel drain) handles that and the
    // ConPTY input echo, which has no host-side toggle here.
    SetEnvironmentVariableA("PS1", "");
    SetEnvironmentVariableA("PS2", "");

    const char *sh = bridge_pty_resolve_shell(shell);
    char cmdline[MAX_PATH + 32];
    // Quoting: shell path may contain spaces. ConPTY child gets argv[0] = sh.
    // bash: skip /etc/profile + ~/.bashrc (git-prompt.sh etc.) — measured
    // ~230 ms of every one-shot RUN on Git for Windows (bash 280 ms vs sh 42 ms
    // to first sentinel). PATH/MSYSTEM are inherited from our env anyway.
    snprintf(cmdline, sizeof(cmdline), "\"%s\"%s", sh,
             bridge_shell_is_bash(sh) ? " --norc --noprofile" : "");

    // Job object: groups the shell with every process it spawns. Closing the
    // job handle (or TerminateJobObject) kills the whole tree at once — the
    // POSIX-pgrp-equivalent we'd otherwise lack on Windows. Created suspended-
    // by-flag (CREATE_SUSPENDED) so we can assign before the shell runs.
    HANDLE job = CreateJobObjectA(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
        // BREAKAWAY_OK: lets `__detach` (the nohup/setsid shim) launch a child
        // outside this job; everything else stays in and dies with it.
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
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

fail: {
    // CloseHandle can clobber GetLastError, so translate first. Mirrors
    // bridge_pty_write_all: the caller diagnoses with strerror(errno), which
    // on Windows would otherwise print "No error" for a failed spawn.
    DWORD ge = GetLastError();
    switch (ge) {
        case ERROR_TOO_MANY_OPEN_FILES: errno = EMFILE;  break;
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:         errno = ENOMEM;  break;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:      errno = ENOENT;  break;
        case ERROR_ACCESS_DENIED:       errno = EACCES;  break;
        default:                        errno = EIO;     break;
    }
    if (in_read)   CloseHandle(in_read);
    if (in_write)  CloseHandle(in_write);
    if (out_read)  CloseHandle(out_read);
    if (out_write) CloseHandle(out_write);
    return -1;
}
}

int bridge_pty_set_canon(bridge_pty_t *p, int on) {
    (void)p; (void)on;  // ConPTY: no termios line discipline to toggle.
    return 0;
}

// Shared core of the two detached launchers. `cmdline` is a mutable Win32
// command line. `h[3]` are the std handles to hand over (any may be NULL ⇒
// NUL): only these get inherited, via the handle-list attribute.
//   CREATE_BREAKAWAY_FROM_JOB — out of every job the bridge put us (or the
//     calling shell) in. The per-RUN job allows it (BREAKAWAY_OK); if the
//     bridge's own enclosing job forbids it, retry without — the child still
//     escapes the per-RUN job, which is the guarantee that matters.
//   DETACHED_PROCESS         — no console at all: nothing to receive a
//     CTRL_CLOSE_EVENT, nothing a ClosePseudoConsole can reach.
//   CREATE_NEW_PROCESS_GROUP — a Ctrl-C to our group never fans out to it.
//   parent (optional)        — PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: the
//     child is created AS IF by that process, inheriting its job membership
//     (none, for the bridge daemon). The `__detach` helper needs this: MSYS/
//     Cygwin bash assigns every child to its own per-user job, which forbids
//     breakaway, so from inside the shell neither flag can get a child out.
//     Handles in `h` are then duplicated into the parent, as inheritance is
//     evaluated against it.
static int win_spawn_detached(char *cmdline, const char *cwd, HANDLE h[3], HANDLE parent) {
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof sa, .bInheritHandle = TRUE };
    HANDLE nul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &sa, OPEN_EXISTING, 0, NULL);
    if (nul == INVALID_HANDLE_VALUE) { errno = EIO; return -1; }
    HANDLE list[4]; DWORD nlist = 0;
    HANDLE owned[4]; DWORD nowned = 0;   // handles we created in `parent`
    for (int i = 0; i < 3; i++) {
        if (!h[i] || h[i] == INVALID_HANDLE_VALUE) h[i] = nul;
        if (parent) {
            HANDLE d = NULL;
            if (!DuplicateHandle(GetCurrentProcess(), h[i], parent, &d, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
                for (DWORD j = 0; j < nowned; j++) DuplicateHandle(parent, owned[j], NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
                CloseHandle(nul); errno = EACCES; return -1;
            }
            h[i] = d; owned[nowned++] = d;
        }
        int dup = 0;
        for (DWORD j = 0; j < nlist; j++) if (list[j] == h[i]) dup = 1;
        if (!dup) list[nlist++] = h[i];
    }
    SIZE_T attr_sz = 0;
    DWORD nattr = parent ? 2 : 1;
    InitializeProcThreadAttributeList(NULL, nattr, 0, &attr_sz);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = malloc(attr_sz);
    if (!attrs || !InitializeProcThreadAttributeList(attrs, nattr, 0, &attr_sz)) {
        free(attrs);
        for (DWORD j = 0; j < nowned; j++) DuplicateHandle(parent, owned[j], NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        CloseHandle(nul); errno = ENOMEM; return -1;
    }
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, nlist * sizeof list[0], NULL, NULL) ||
        (parent && !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent, sizeof parent, NULL, NULL))) {
        DeleteProcThreadAttributeList(attrs);
        free(attrs);
        for (DWORD j = 0; j < nowned; j++) DuplicateHandle(parent, owned[j], NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        CloseHandle(nul); errno = EIO; return -1;
    }
    STARTUPINFOEXA si = { .StartupInfo = { .cb = sizeof si, .dwFlags = STARTF_USESTDHANDLES,
                                           .hStdInput = h[0], .hStdOutput = h[1], .hStdError = h[2] },
                          .lpAttributeList = attrs };
    PROCESS_INFORMATION pi = {0};
    DWORD base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | EXTENDED_STARTUPINFO_PRESENT;
    const char *dir = (cwd && *cwd) ? cwd : NULL;
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, base | CREATE_BREAKAWAY_FROM_JOB,
                             NULL, dir, &si.StartupInfo, &pi);
    if (!ok && GetLastError() == ERROR_ACCESS_DENIED)
        ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, base, NULL, dir, &si.StartupInfo, &pi);
    DWORD gle = ok ? 0 : GetLastError();
    DeleteProcThreadAttributeList(attrs);
    free(attrs);
    for (DWORD j = 0; j < nowned; j++) DuplicateHandle(parent, owned[j], NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    CloseHandle(nul);
    if (!ok) {
        errno = gle == ERROR_FILE_NOT_FOUND || gle == ERROR_PATH_NOT_FOUND ? ENOENT
              : gle == ERROR_ACCESS_DENIED ? EACCES : EIO;
        return -1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

// Is `sh` cmd.exe (no POSIX shell provisioned yet)?
static int win_shell_is_cmd(const char *sh) {
    const char *b = sh + strlen(sh);
    while (b > sh && b[-1] != '\\' && b[-1] != '/') b--;
    return _stricmp(b, "cmd.exe") == 0 || _stricmp(b, "cmd") == 0;
}

int bridge_pty_spawn_detached(const char *shell, const char *cmd, const char *cwd) {
    bridge_prepend_tools_path_win();
    const char *sh = bridge_pty_resolve_shell(shell);
    // `sh -c` is POSIX-shell dialect: no bash/busybox yet ⇒ refuse, do not
    // feed it to cmd.exe (the one-shot path has a cmd dialect; this hasn't).
    if (win_shell_is_cmd(sh)) { errno = ENOENT; return -1; }
    char *cmdline = malloc(65536);
    if (!cmdline) { errno = ENOMEM; return -1; }
    int n = snprintf(cmdline, 65536, "\"%s\" -c ", sh);
    if (n <= 0 || n >= 65536 || bridge_win_quote_arg(cmd, cmdline + n, 65536 - (size_t)n) < 0) {
        free(cmdline); errno = E2BIG; return -1;
    }
    // No ConPTY, no job object, stdio -> NUL (the POSIX /dev/null equivalent;
    // invalid/NULL std handles make node and MSYS bash misbehave).
    HANDLE h[3] = {0};
    int rc = win_spawn_detached(cmdline, cwd, h, NULL);
    free(cmdline);
    return rc;
}

// `<bridge> __detach PROG [ARGS…]`: the body of the `nohup`/`setsid` shim the
// RUN wrapper defines on Windows. The shell does its job up to here — PATH
// lookup is NOT done (PROG may be a script, a shell function's target, a
// .cmd shim), so the shell resolves it: `sh -c 'exec "$0" "$@"' PROG ARGS…`.
// Inherits our cwd, environment and std handles — i.e. the shell's `> log
// 2>&1` redirects — then exits 0 at once so the `&` the agent wrote is a
// no-op. A std handle that is still the ConPTY would die with it, so those
// become NUL (nohup would write nohup.out; close enough).
// The child is created with the bridge daemon ($TODOFORAI_BRIDGE_PID) as its
// parent: we ourselves sit in MSYS bash's per-user job (no breakaway allowed)
// and in the RUN's job, and only a job-free parent yields a job-free child.
int bridge_pty_detach_main(int argc, char **argv) {
    // `nohup -- PROG` / `setsid -- PROG`: skip the option terminator. Any
    // other option (setsid -w, nohup --version) is not supported here.
    if (argc >= 1 && strcmp(argv[0], "--") == 0) { argc--; argv++; }
    if (argc < 1 || argv[0][0] == '-') { fprintf(stderr, "usage: __detach [--] PROG [ARGS...]\n"); return 2; }
    // Parent = the bridge daemon, by pid from the env the daemon set on the
    // shell. Strict parse: a stale/garbled value must not pick a random
    // process. Without it the child would stay in MSYS bash's per-user job
    // and die with the RUN, so refuse rather than pretend.
    HANDLE parent = NULL;
    {
        char pid_s[16]; char *endp = NULL;
        DWORD len = GetEnvironmentVariableA("TODOFORAI_BRIDGE_PID", pid_s, sizeof pid_s);
        unsigned long pid = (len > 0 && len < sizeof pid_s) ? strtoul(pid_s, &endp, 10) : 0;
        if (pid && pid <= 0xFFFFFFFFul && endp && *endp == '\0')
            parent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, (DWORD)pid);
        if (!parent) { fprintf(stderr, "__detach: bridge daemon not reachable (TODOFORAI_BRIDGE_PID)\n"); return 126; }
    }
    bridge_prepend_tools_path_win();
    const char *sh = bridge_pty_resolve_shell(NULL);
    if (win_shell_is_cmd(sh)) { CloseHandle(parent); fprintf(stderr, "__detach: no POSIX shell\n"); return 127; }
    size_t cap = 65536;
    char *cmdline = malloc(cap);
    if (!cmdline) { CloseHandle(parent); return 1; }
    int n = snprintf(cmdline, cap, "\"%s\" -c \"exec \\\"$0\\\" \\\"$@\\\"\"", sh);
    for (int i = 0; i < argc && n > 0 && (size_t)n < cap; i++) {
        cmdline[n++] = ' ';
        int q = bridge_win_quote_arg(argv[i], cmdline + n, cap - (size_t)n);
        if (q < 0) { free(cmdline); CloseHandle(parent); fprintf(stderr, "__detach: command line too long\n"); return 1; }
        n += q;
    }
    // Std handles: a file/pipe redirect is handed over (win_spawn_detached
    // duplicates it into the parent, so inheritability here is irrelevant);
    // a console handle — incl. the ConPTY end — answers GetConsoleMode and
    // would die with the RUN, so it becomes NUL.
    HANDLE h[3] = { GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE) };
    for (int i = 0; i < 3; i++) {
        DWORD mode;
        if (h[i] == INVALID_HANDLE_VALUE || (h[i] && GetConsoleMode(h[i], &mode))) h[i] = NULL;
    }
    int rc = win_spawn_detached(cmdline, NULL, h, parent);
    int err = errno;
    free(cmdline);
    CloseHandle(parent);
    if (rc != 0) { fprintf(stderr, "__detach: %s: %s\n", argv[0], strerror(err)); return err == ENOENT ? 127 : 126; }
    return 0;
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
        if (!WriteFile((HANDLE)p->h_in_write, b + written, (DWORD)(len - written), &n, NULL)) {
            // WriteFile reports via GetLastError, not errno; translate so the
            // caller's strerror(errno) diagnosis is meaningful on Windows too.
            DWORD ge = GetLastError();
            errno = (ge == ERROR_BROKEN_PIPE || ge == ERROR_NO_DATA) ? EPIPE : EIO;
            return -1;
        }
        if (n == 0) { errno = EPIPE; return -1; }
        written += n;
    }
    return 0;
}

int bridge_pty_write_input(bridge_pty_t *p, const void *buf, size_t len) {
    // Enter under ConPTY is '\r': a native console app (python -i) reads a '\n'
    // as just another character and waits for the real Enter forever. MSYS
    // bash `read` takes '\r' as Enter too, so translating is safe for both.
    const uint8_t *b = buf;
    uint8_t out[4096];
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = b[i];
        if (c == '\r' && i + 1 < len && b[i + 1] == '\n') { c = '\r'; i++; }
        else if (c == '\n') c = '\r';
        out[o++] = c;
        if (o == sizeof out) {
            if (bridge_pty_write_all(p, out, o) != 0) return -1;
            o = 0;
        }
    }
    return o ? bridge_pty_write_all(p, out, o) : 0;
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

// Git Bash / busybox are MSYS/Cygwin binaries: a signal death is reported to
// Win32 as a POSIX wait status, `sig << 8` (measured: `kill -1 $$` → 256,
// `kill -9 $$` → 2304). Map that onto the POSIX backend's convention
// (decode_status in pty_posix.c: negative = killed by signal) so the backend
// sees -1/-9 instead of a meaningless "exit 256". Real exit codes are ≤ 255;
// NTSTATUS crash codes (0xC0000005…) have the low byte set and pass through.
static int decode_win_status(DWORD ec) {
    if ((ec & 0xff) == 0 && (ec >> 8) >= 1 && (ec >> 8) <= 64) return -(int)(ec >> 8);
    return (int)ec;
}

int bridge_pty_reap(bridge_pty_t *p, int *code) {
    if (!p->alive) return 0;
    DWORD wr = WaitForSingleObject((HANDLE)p->h_process, 0);
    if (wr != WAIT_OBJECT_0) return 0;
    DWORD ec = 0;
    GetExitCodeProcess((HANDLE)p->h_process, &ec);
    *code = decode_win_status(ec);
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
            code = decode_win_status(ec);
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
    return -1;  // Not meaningful on Windows; main loop drives via poll().
}

// ── Auto-pause detection ────────────────────────────────────────────────────
// Windows analog of pty_posix.c's /proc/<pid>/syscall + tcgetpgrp probe.
//
// Pgrp surrogate: per-session Job Object (shell + descendants; conhost is
// spawned via csrss and not in the job, so no filtering needed).
//
// "Blocked in n_tty_read": the theory was that ConPTY clients hit conhost via
// ALPC, so the parked thread shows ThreadState=Waiting + WaitReason=WrLpcReply
// in NtQuerySystemInformation(SystemProcessInformation).
//
// MEASURED FALSE (Win11, BusyBox sh + bash inside the bridge's own ConPTY):
// a shell blocked in `read` shows State=5/WR=6 (WrExecutive) — byte-identical
// to waiting on a child, on a socket, or on `sleep`. WrLpcReply(17) appeared
// on exactly 5 threads system-wide, all csrss/svchost/explorer, never a shell.
// No thread-state constant discriminates "waiting for stdin"; ConPTY simply
// does not expose TTY semantics. The probe therefore cannot fire, and taking
// a full system process+thread snapshot every PAUSE_POLL_MS per session was
// pure waste — it is disabled (BRIDGE_WIN_PROBE_BLOCKED=0). Interactive
// prompts on Windows surface via the deadline path instead (main.c parks the
// run on timeout).
//
// password_prompt: ENABLE_ECHO_INPUT isn't exposed via ConPTY → always 0.

#ifndef BRIDGE_WIN_PROBE_BLOCKED
#define BRIDGE_WIN_PROBE_BLOCKED 0
#endif

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
    // Threads array follows; header trailing fields vary across Windows
    // versions — we compute thread offset dynamically.
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

size_t bridge_pty_stdin_waiter(const bridge_pty_t *p, char *out, size_t cap) {
    (void)p;  // No cheap per-process "blocked on console read" view on Windows.
    if (out && cap) out[0] = '\0';
    return 0;
}

int bridge_pty_probe_blocked(const bridge_pty_t *p, int echo_baseline,
                             long *fg_pid, int *password_prompt) {
    (void)echo_baseline;  // No ECHO introspection on Windows; see file header.
    if (fg_pid) *fg_pid = 0;
    if (password_prompt) *password_prompt = 0;
    if (!BRIDGE_WIN_PROBE_BLOCKED) return 0;  // See comment above: cannot fire.
    if (!p || !p->alive || !p->h_job) return 0;

    ULONG njobpids = 0;
    DWORD *jobpids = bridge_job_pid_list((HANDLE)p->h_job, &njobpids);
    if (!jobpids || njobpids == 0) { free(jobpids); return 0; }

    bridge_sys_proc_info_t *snap = bridge_snapshot_processes();
    if (!snap) { free(jobpids); return 0; }

    // Resolve thread-array offset from the first entry with NextEntryOffset
    // and threads (layout is uniform within one snapshot).
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

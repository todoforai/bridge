// Self-update. See update.h for the contract.
//
// Why shell out to install.sh instead of downloading in-process: the bridge
// has no TLS client (the Noise channel is its only socket), and install.sh
// already resolves the latest tag, verifies sha256 and replaces the binary
// atomically. Reusing it keeps exactly one download path to audit — and one
// place that knows how a release is published.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "update.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include "args.h"
#include "identity.h"   // BRIDGE_VERSION

// ── version ────────────────────────────────────────────────────────────────

// Parse a leading "vMAJOR.MINOR.PATCH". Returns 0 on success.
static int parse_semver(const char *s, long v[3]) {
    if (!s) return -1;
    while (*s == 'v' || *s == 'V') s++;
    for (int i = 0; i < 3; i++) {
        if (!isdigit((unsigned char)*s)) return -1;
        char *end;
        v[i] = strtol(s, &end, 10);
        s = end;
        if (i < 2) { if (*s != '.') return -1; s++; }
    }
    return 0;
}

// A plain "vX.Y.Z". Anything with a suffix is either a build off a tag
// ("v1.5.7-3-gc4772d0", "…-dirty") or a prerelease ("v1.6.0-rc1"): never
// auto-update off one, and never auto-update onto one.
static int is_release_version(const char *s) {
    long v[3];
    return parse_semver(s, v) == 0 && !strpbrk(s, "-+");
}

int bridge_update_wanted(const char *latest) {
#ifdef _WIN32
    // Windows can't replace a running .exe, so applying an update means
    // stopping the scheduled task — i.e. killing the very process doing the
    // update. `todoforai-bridge update`, run from a shell, has no such problem.
    (void)latest;
    return 0;
#else
    if (!latest || !*latest) return 0;
    if (getenv("TODOFORAI_NO_AUTO_UPDATE")) return 0;
    if (!is_release_version(BRIDGE_VERSION)) return 0;
    if (!is_release_version(latest)) return 0;
    // Applying an update ends in exit(); without something to start us again
    // that's just a bridge that stopped. systemd sets INVOCATION_ID for every
    // unit it runs, launchd reparents its jobs to PID 1. Any other supervisor
    // (pm2, a wrapper script) is unrecognised and simply doesn't auto-update —
    // the conservative direction.
    if (!getenv("INVOCATION_ID") && getppid() != 1) return 0;

    long cur[3], want[3];
    if (parse_semver(BRIDGE_VERSION, cur) != 0) return 0;
    if (parse_semver(latest, want) != 0) return 0;
    for (int i = 0; i < 3; i++) {
        if (want[i] > cur[i]) return 1;
        if (want[i] < cur[i]) return 0;   // never downgrade
    }
    return 0;
#endif
}

// ── install dir ────────────────────────────────────────────────────────────

// Directory holding the running binary, so the update lands where this install
// actually lives rather than the installer's default prefix.
//
// Not shared with jobs.c's g_self: that one deliberately keeps the *unresolved*
// "/proc/self/exe" so re-execs pin the running inode across an upgrade, which
// is the opposite of what's needed here (and dirname("/proc/self/exe") is
// "/proc"). Both are a handful of lines over the same OS calls.
static int self_dir(char *out, size_t cap) {
    char path[1024];
#if defined(_WIN32)
    DWORD n = GetModuleFileNameA(NULL, path, sizeof path);
    if (n == 0 || n >= sizeof path) return -1;
    char *sep = strrchr(path, '\\');
#elif defined(__APPLE__)
    uint32_t sz = sizeof path;
    if (_NSGetExecutablePath(path, &sz) != 0) return -1;
    char *sep = strrchr(path, '/');
#else
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
    if (n <= 0) n = readlink("/proc/curproc/file", path, sizeof path - 1);  // BSD
    if (n <= 0) return -1;
    path[n] = '\0';
    char *sep = strrchr(path, '/');
#endif
    if (!sep || sep == path) return -1;
    *sep = '\0';
    if (strlen(path) >= cap) return -1;
    snprintf(out, cap, "%s", path);
    return 0;
}

// ── apply ──────────────────────────────────────────────────────────────────

int bridge_update_apply(void) {
    char dir[1024];
    if (self_dir(dir, sizeof dir) != 0) {
        fprintf(stderr, "update: could not locate the running binary\n");
        return 1;
    }
    // The path goes into a shell command line; refuse anything that could end
    // the quoted string. Install dirs are plain paths — a quote in one is a bug.
    if (strpbrk(dir, "'\"`$\\\n\r")) {
        fprintf(stderr, "update: install path contains shell metacharacters (%s)\n", dir);
        return 1;
    }

    char cmd[2048];
#ifdef _WIN32
    snprintf(cmd, sizeof cmd,
             "powershell -NoProfile -ExecutionPolicy Bypass -Command "
             "\"iex \\\"& { $(irm https://todofor.ai/bridge.ps1) } -Prefix '%s'\\\"\"", dir);
#else
    // Download the installer to a temp file first: piping it into `sh` would
    // leave the script no stdin, and a truncated download would execute as a
    // half script.
    snprintf(cmd, sizeof cmd,
             "set -e; i=$(mktemp); trap 'rm -f \"$i\"' EXIT; "
             "curl -fsSL https://todofor.ai/bridge -o \"$i\"; "
             "sh \"$i\" --prefix '%s'", dir);
#endif
    fprintf(stderr, "update: installing the latest release into %s ...\n", dir);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "update: installer failed (exit %d) — keeping %s\n", rc, BRIDGE_VERSION);
        return 1;
    }
    return 0;
}

// ── subcommand ─────────────────────────────────────────────────────────────

int cmd_update(int argc, char **argv) {
    static const char *USAGE = "update";
    ko_longopt_t longopts[] = {
        { "help", ko_no_argument, 'h' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "h", longopts)) >= 0) {
        if (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE); return 0; }
        else cli_parse_error("todoforai-bridge", USAGE, argc, argv, &opt, c);
    }
    // No version check first: install.sh resolves the latest tag and reports
    // what it fetched, so asking GitHub here would duplicate that lookup to
    // save a ~90 KiB download that only happens when a human asks for it.
    printf("installed: %s\n", BRIDGE_VERSION);
    if (bridge_update_apply() != 0) return 1;
    printf("done — restart the bridge to run the new build\n");
    return 0;
}

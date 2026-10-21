#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "env_path.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Package-manager bin dirs (relative to $HOME) that a non-login shell misses.
// Only prepended when the directory actually exists.
static const char *OPTIONAL_HOME_DIRS[] = {
#ifdef _WIN32
    ".bun\\bin", ".deno\\bin", ".cargo\\bin", "go\\bin", ".volta\\bin",
    // npm global prefixes: the default per-user location, plus the common
    // `npm config set prefix ~/npm-global` convention (often PATH'd only in
    // ~/.bashrc, which non-interactive scan shells never source).
    "AppData\\Roaming\\npm", "npm-global",
#else
    ".bun/bin", ".deno/bin", ".cargo/bin", "go/bin", ".volta/bin",
    ".local/share/pnpm",
#endif
    NULL,
};

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void bridge_prepend_tools_path_win(void) {
    static int done = 0;
    if (done) return;

    const char *home = getenv("USERPROFILE");
    if (!home || !*home) return;

    DWORD need = GetEnvironmentVariableA("PATH", NULL, 0);
    char *old = NULL;
    const char *suffix = "";
    if (need > 0) {
        old = (char *)malloc(need);
        if (old && GetEnvironmentVariableA("PATH", old, need) < need) suffix = old;
    }

    // Existing optional package-manager dirs, e.g. ";C:\Users\x\.bun\bin".
    char extra[2048] = "";
    size_t extra_len = 0;
    for (int i = 0; OPTIONAL_HOME_DIRS[i]; i++) {
        char dir[MAX_PATH];
        if (snprintf(dir, sizeof(dir), "%s\\%s", home, OPTIONAL_HOME_DIRS[i]) >= (int)sizeof(dir)) continue;
        DWORD attrs = GetFileAttributesA(dir);
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) continue;
        int m = snprintf(extra + extra_len, sizeof(extra) - extra_len, ";%s", dir);
        if (m < 0 || (size_t)m >= sizeof(extra) - extra_len) { extra[extra_len] = '\0'; break; }
        extra_len += (size_t)m;
    }

    int n = snprintf(NULL, 0,
                     "%s\\.todoforai\\tools\\node_modules\\.bin;"
                     "%s\\.todoforai\\tools\\node;"
                     "%s\\.todoforai\\tools\\venv\\Scripts;"
                     "%s\\.todoforai\\tools\\bin;"
                     "%s\\.local;"
                     "%s\\.local\\bin%s;%s",
                     home, home, home, home, home, home, extra, suffix);
    if (n >= 0) {
        char *path = (char *)malloc((size_t)n + 1);
        if (path) {
            snprintf(path, (size_t)n + 1,
                     "%s\\.todoforai\\tools\\node_modules\\.bin;"
                     "%s\\.todoforai\\tools\\node;"
                     "%s\\.todoforai\\tools\\venv\\Scripts;"
                     "%s\\.todoforai\\tools\\bin;"
                     "%s\\.local;"
                     "%s\\.local\\bin%s;%s",
                     home, home, home, home, home, home, extra, suffix);
            if (SetEnvironmentVariableA("PATH", path)) done = 1;
            free(path);
        }
    }
    free(old);
}

#else

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// GUI apps on macOS (Finder/Dock launch) never source ~/.zshrc or
// ~/.zprofile, so Homebrew's shellenv (and its PATH export) never runs —
// `npm`, `git`, etc. installed via `brew` are invisible even though they're
// on disk. These are fixed, well-known locations (not relative to $HOME),
// checked for existence before being added.
static const char *ABSOLUTE_CANDIDATE_DIRS[] = {
    "/opt/homebrew/bin",              // Homebrew, Apple Silicon
    "/opt/homebrew/sbin",
    "/usr/local/bin",                 // Homebrew, Intel mac (and classic Unix)
    "/usr/local/sbin",
#ifdef __linux__
    // Linuxbrew — Linux only: on macOS /home is an autofs automount, and
    // every stat() under it triggers the automounter (directory-services
    // lookup): 365 ms measured, seconds under load — on each spawn.
    "/home/linuxbrew/.linuxbrew/bin",
#endif
    NULL,
};

static int is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

// Parses a leading "vMAJOR.MINOR.PATCH" tag (nvm's directory naming, e.g.
// "v20.11.0"). Returns 1 on success.
static int parse_v_semver(const char *s, long v[3]) {
    if (*s != 'v') return 0;
    s++;
    for (int i = 0; i < 3; i++) {
        char *end;
        if (s[0] < '0' || s[0] > '9') return 0;
        v[i] = strtol(s, &end, 10);
        s = end;
        if (i < 2) { if (*s != '.') return 0; s++; }
    }
    return *s == '\0';
}

static int semver_lt(const long a[3], const long b[3]) {
    for (int i = 0; i < 3; i++) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return 0;
}

// nvm has no "current" symlink on PATH for non-interactive shells — it's a
// shell-function-based version manager, activated only by sourcing
// ~/.nvm/nvm.sh (which a GUI-launched process never does). Best effort:
// pick the highest installed version's bin dir.
static int append_nvm_bin(const char *home, char *extra, size_t cap, size_t *len) {
    char versions_dir[1024];
    if (snprintf(versions_dir, sizeof(versions_dir), "%s/.nvm/versions/node", home) >= (int)sizeof(versions_dir)) return 0;
    DIR *d = opendir(versions_dir);
    if (!d) return 0;

    char best[256] = "";
    long best_v[3] = {-1, -1, -1};
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        long v[3];
        if (!parse_v_semver(ent->d_name, v)) continue;
        if (best[0] && !semver_lt(best_v, v)) continue;
        snprintf(best, sizeof(best), "%s", ent->d_name);
        memcpy(best_v, v, sizeof(v));
    }
    closedir(d);
    if (!best[0]) return 0;

    char dir[1280];
    if (snprintf(dir, sizeof(dir), "%s/bin", best) >= (int)sizeof(dir)) return 0;
    char full[1024 + 1280];
    if (snprintf(full, sizeof(full), "%s/%s", versions_dir, dir) >= (int)sizeof(full)) return 0;
    if (!is_dir(full)) return 0;
    int m = snprintf(extra + *len, cap - *len, ":%s", full);
    if (m < 0 || (size_t)m >= cap - *len) return 0;
    *len += (size_t)m;
    return 1;
}

char *bridge_build_tools_path(void) {
    const char *home = getenv("HOME");
    if (!home || !*home) return NULL;

    const char *old = getenv("PATH");
    if (!old || !*old) old = "/usr/local/bin:/usr/bin:/bin";

    // Existing optional package-manager dirs, e.g. ":/home/x/.bun/bin".
    char extra[2048] = "";
    size_t extra_len = 0;
    for (int i = 0; OPTIONAL_HOME_DIRS[i]; i++) {
        char dir[1024];
        if (snprintf(dir, sizeof(dir), "%s/%s", home, OPTIONAL_HOME_DIRS[i]) >= (int)sizeof(dir)) continue;
        if (!is_dir(dir)) continue;
        int m = snprintf(extra + extra_len, sizeof(extra) - extra_len, ":%s", dir);
        if (m < 0 || (size_t)m >= sizeof(extra) - extra_len) { extra[extra_len] = '\0'; break; }
        extra_len += (size_t)m;
    }
    for (int i = 0; ABSOLUTE_CANDIDATE_DIRS[i]; i++) {
        if (!is_dir(ABSOLUTE_CANDIDATE_DIRS[i])) continue;
        int m = snprintf(extra + extra_len, sizeof(extra) - extra_len, ":%s", ABSOLUTE_CANDIDATE_DIRS[i]);
        if (m < 0 || (size_t)m >= sizeof(extra) - extra_len) { extra[extra_len] = '\0'; break; }
        extra_len += (size_t)m;
    }
    append_nvm_bin(home, extra, sizeof(extra), &extra_len);

    int n = snprintf(NULL, 0,
                     "%s/.todoforai/tools/node_modules/.bin:"
                     "%s/.todoforai/tools/venv/bin:"
                     "%s/.todoforai/tools/bin:"
                     "%s/.local/bin%s:%s",
                     home, home, home, home, extra, old);
    if (n < 0) return NULL;
    char *path = (char *)malloc((size_t)n + 1);
    if (!path) return NULL;
    snprintf(path, (size_t)n + 1,
             "%s/.todoforai/tools/node_modules/.bin:"
             "%s/.todoforai/tools/venv/bin:"
             "%s/.todoforai/tools/bin:"
             "%s/.local/bin%s:%s",
             home, home, home, home, extra, old);
    return path;
}

// sudo/ssh/su are setuid: /proc/<pid>/syscall is EACCES for them, so the
// stdin probe cannot tell a password prompt from a download waiting on a
// socket and falls back to a 2s-silence guess (main.c OPAQUE_QUIET_MS).
// With SUDO_ASKPASS/SSH_ASKPASS set, sudo -A / ssh run THIS unprivileged
// script instead, whose `read </dev/tty` is a plain, visible tty read — the
// probe fires authoritatively in one tick. Only honoured when the caller
// passes -A (sudo) or has no tty (ssh); a plain `sudo` still takes the slow
// path, so the RUN wrapper aliases sudo to `sudo -A`.
static const char ASKPASS_SRC[] =
    "#!/bin/sh\n"
    "# TODOforAI bridge askpass: makes sudo/ssh password prompts a plain tty\n"
    "# read the bridge's stdin probe can see instantly.\n"
    "trap 'stty echo </dev/tty 2>/dev/null' EXIT INT TERM HUP\n"
    "printf '%s' \"${1:-Password: }\" >/dev/tty || exit 1\n"
    "stty -echo </dev/tty 2>/dev/null\n"
    "IFS= read -r pw </dev/tty || exit 1\n"
    "printf '\\n' >/dev/tty\n"
    "printf '%s\\n' \"$pw\"\n";

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#include "agent_browser_guard.h"
#pragma GCC diagnostic pop

// True iff `path` is already exactly `src`: a regular file we own, mode 0700.
// Opened O_NOFOLLOW so a planted symlink never counts.
static int script_is_current(const char *path, const char *src, size_t len) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid()
          && (st.st_mode & 07777) == 0700 && st.st_size == (off_t)len;
    for (size_t off = 0; ok && off < len; ) {
        char cur[4096];
        size_t want = len - off < sizeof cur ? len - off : sizeof cur;
        ssize_t r = read(fd, cur, want);
        ok = r > 0 && memcmp(cur, src + off, (size_t)r) == 0;
        if (ok) off += (size_t)r;
    }
    close(fd);
    return ok;
}

// Write `src` to ~/.todoforai/<rel>/<name> (0700, idempotent); returns its
// path or NULL. Caller frees.
static char *ensure_script(const char *rel, const char *name, const char *src, size_t len) {
    const char *home = getenv("HOME");
    if (!home || !*home) return NULL;
    char dir[1024], path[1200], tmp[1240];
    if (snprintf(dir, sizeof dir, "%s/.todoforai/%s", home, rel) >= (int)sizeof dir) return NULL;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if (script_is_current(path, src, len)) return strdup(path);

    // mkdir -p, 0700 (every level is ours; existing ones are left alone).
    for (char *p = dir + strlen(home) + 1; ; p++) {
        if (*p != '/' && *p != '\0') continue;
        char c = *p; *p = '\0'; mkdir(dir, 0700); *p = c;
        if (!c) break;
    }
    // Write to a fresh temp (O_EXCL, never follows anything) then rename
    // over the destination: readers see either the old or the new script,
    // and a symlink planted at `path` is replaced, not written through.
    snprintf(tmp, sizeof tmp, "%s/.%s.%ld", dir, name, (long)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (fd < 0) return NULL;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, src + off, len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    // O_CREAT mode is masked by umask; force the exact mode on the open fd.
    int ok = off == len && fchmod(fd, 0700) == 0;
    close(fd);
    if (!ok || rename(tmp, path) != 0) { unlink(tmp); return NULL; }
    return strdup(path);
}

char *bridge_ensure_askpass(void) {
    return ensure_script("bin", "askpass", ASKPASS_SRC, sizeof ASKPASS_SRC - 1);
}

char *bridge_ensure_shims(void) {
    char *p = ensure_script("bin/shims", "agent-browser", AGENT_BROWSER_GUARD_SRC, sizeof AGENT_BROWSER_GUARD_SRC - 1);
    if (!p) return NULL;
    *strrchr(p, '/') = '\0';
    return p;
}

#endif

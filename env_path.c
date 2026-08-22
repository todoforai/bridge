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
#include <sys/stat.h>

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
    "/home/linuxbrew/.linuxbrew/bin", // Linuxbrew
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

#endif

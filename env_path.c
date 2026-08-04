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
                     "%s\\.todoforai\\tools\\venv\\Scripts;"
                     "%s\\.todoforai\\tools\\bin;"
                     "%s\\.local;"
                     "%s\\.local\\bin%s;%s",
                     home, home, home, home, home, extra, suffix);
    if (n >= 0) {
        char *path = (char *)malloc((size_t)n + 1);
        if (path) {
            snprintf(path, (size_t)n + 1,
                     "%s\\.todoforai\\tools\\node_modules\\.bin;"
                     "%s\\.todoforai\\tools\\venv\\Scripts;"
                     "%s\\.todoforai\\tools\\bin;"
                     "%s\\.local;"
                     "%s\\.local\\bin%s;%s",
                     home, home, home, home, home, extra, suffix);
            if (SetEnvironmentVariableA("PATH", path)) done = 1;
            free(path);
        }
    }
    free(old);
}

#else

#include <sys/stat.h>

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
        struct stat st;
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        int m = snprintf(extra + extra_len, sizeof(extra) - extra_len, ":%s", dir);
        if (m < 0 || (size_t)m >= sizeof(extra) - extra_len) { extra[extra_len] = '\0'; break; }
        extra_len += (size_t)m;
    }

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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "env_path.h"

#include <stdio.h>
#include <stdlib.h>

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

    int n = snprintf(NULL, 0,
                     "%s\\.todoforai\\tools\\node_modules\\.bin;"
                     "%s\\.todoforai\\tools\\venv\\Scripts;"
                     "%s\\.todoforai\\tools\\bin;"
                     "%s\\.local;"
                     "%s\\.local\\bin;%s",
                     home, home, home, home, home, suffix);
    if (n >= 0) {
        char *path = (char *)malloc((size_t)n + 1);
        if (path) {
            snprintf(path, (size_t)n + 1,
                     "%s\\.todoforai\\tools\\node_modules\\.bin;"
                     "%s\\.todoforai\\tools\\venv\\Scripts;"
                     "%s\\.todoforai\\tools\\bin;"
                     "%s\\.local;"
                     "%s\\.local\\bin;%s",
                     home, home, home, home, home, suffix);
            if (SetEnvironmentVariableA("PATH", path)) done = 1;
            free(path);
        }
    }
    free(old);
}

#else

char *bridge_build_tools_path(void) {
    const char *home = getenv("HOME");
    if (!home || !*home) return NULL;

    const char *old = getenv("PATH");
    if (!old || !*old) old = "/usr/local/bin:/usr/bin:/bin";

    int n = snprintf(NULL, 0,
                     "%s/.todoforai/tools/node_modules/.bin:"
                     "%s/.todoforai/tools/venv/bin:"
                     "%s/.todoforai/tools/bin:"
                     "%s/.local/bin:%s",
                     home, home, home, home, old);
    if (n < 0) return NULL;
    char *path = (char *)malloc((size_t)n + 1);
    if (!path) return NULL;
    snprintf(path, (size_t)n + 1,
             "%s/.todoforai/tools/node_modules/.bin:"
             "%s/.todoforai/tools/venv/bin:"
             "%s/.todoforai/tools/bin:"
             "%s/.local/bin:%s",
             home, home, home, home, old);
    return path;
}

#endif

#include "update.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Resolve our own executable path. /proc/self/exe is the reliable source on
// Linux; on other POSIX systems we fall back to argv0 (best-effort).
static int resolve_self_exe(const char *argv0, char *out, size_t cap) {
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n > 0) { out[n] = '\0'; return 0; }
    if (!argv0 || !*argv0) return -1;
    size_t len = strlen(argv0);
    if (len >= cap) return -1;
    memcpy(out, argv0, len + 1);
    return 0;
}

void bridge_update_swap_on_start(const char *argv0) {
    char exe[4096];
    if (resolve_self_exe(argv0, exe, sizeof(exe)) != 0) return;

    char staged[4096 + 4];
    int n = snprintf(staged, sizeof(staged), "%s.new", exe);
    if (n <= 0 || (size_t)n >= sizeof(staged)) return;

    struct stat st;
    if (stat(staged, &st) != 0) return;  // nothing staged — normal path

    if (rename(staged, exe) != 0) {
        fprintf(stderr, "update: rename %s -> %s failed: %s\n",
                staged, exe, strerror(errno));
        return;
    }
    fprintf(stderr, "update: swapped in new binary at %s\n", exe);
}

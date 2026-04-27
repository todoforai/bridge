// Smoke test for bridge_tools_watch_init.
// Builds against the same tools.c sources (no link to main.c). Run it like:
//   make test-watch && ./build/test-watch
//
// Sets PATH to a single tmp dir, registers two catalog entries (one whose
// versionCmd = "smoketest_foo --version"), creates that file, expects a
// delta `installed_tools` JSON containing "smoketest_foo".
#define _POSIX_C_SOURCE 200809L
#include "tools.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <poll.h>
static char captured[64 * 1024];
static int got_delta = 0;

// Drain helper: poll the watcher's eventfd briefly; on POLLIN, copy delta out.
static int wait_delta(int timeout_ms) {
    int fd = bridge_tools_watch_eventfd();
    if (fd < 0) return 0;
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, timeout_ms) <= 0) return 0;
    int n = bridge_tools_watch_drain(captured, sizeof captured);
    if (n > 0) { got_delta = 1; fprintf(stderr, "[capture] %s\n", captured); }
    return n > 0;
}

// Build a single catalog line. Caller passes shell snippets verbatim.
static size_t make_entry(char *out, size_t cap,
                         const char *key, const char *vcmd, const char *scmd) {
    char vb64[512] = "", sb64[512] = "";
    if (vcmd && *vcmd) b64_encode((const uint8_t *)vcmd, strlen(vcmd), vb64);
    if (scmd && *scmd) b64_encode((const uint8_t *)scmd, strlen(scmd), sb64);
    return (size_t)snprintf(out, cap, "%s\t%s\t%s\n", key, vb64, sb64);
}

int main(void) {
    char tmpdir[] = "/tmp/bridge-watch-XXXXXX";
    if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return 1; }
    setenv("PATH", tmpdir, 1);

    char buf[2048];
    size_t n = 0;
    n += make_entry(buf + n, sizeof buf - n,
                    "smoketest_foo", "smoketest_foo --version", "");
    // Also include an entry without a versionCmd to make sure it's tolerated.
    n += make_entry(buf + n, sizeof buf - n,
                    "no_track", "", "true");

    if (bridge_tools_watch_init(buf, n) != 0) {
        fprintf(stderr, "FAIL: watcher init\n");
        return 1;
    }

    // Drop the binary into the watched dir.
    char path[256];
    snprintf(path, sizeof path, "%s/smoketest_foo", tmpdir);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd < 0) { perror("open"); return 1; }
    write(fd, "#!/bin/sh\necho v0.0.1-smoketest\n", 32);
    close(fd);
    chmod(path, 0755);

    wait_delta(3000);
    bridge_tools_watch_stop();

    if (!got_delta) { fprintf(stderr, "FAIL: no delta received\n"); return 1; }
    if (!strstr(captured, "smoketest_foo")) {
        fprintf(stderr, "FAIL: delta missing key. payload=%s\n", captured); return 1;
    }
    if (!strstr(captured, "v0.0.1-smoketest")) {
        fprintf(stderr, "FAIL: delta missing version. payload=%s\n", captured); return 1;
    }
    if (strstr(captured, "no_track")) {
        fprintf(stderr, "FAIL: untracked entry leaked. payload=%s\n", captured); return 1;
    }

    // Now test removal: re-arm watcher, delete the file, expect installed:false.
    got_delta = 0; captured[0] = 0;
    if (bridge_tools_watch_init(buf, n) != 0) return 1;
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    write(fd, "#!/bin/sh\necho v\n", 17); close(fd); chmod(path, 0755);
    wait_delta(3000);
    got_delta = 0;
    unlink(path);
    wait_delta(3000);
    bridge_tools_watch_stop();
    unlink(path);
    rmdir(tmpdir);

    // Verify safe stop without init.
    bridge_tools_watch_stop();
    if (!got_delta || !strstr(captured, "\"installed\":false")) {
        fprintf(stderr, "FAIL: removal not reported. payload=%s\n", captured); return 1;
    }
    fprintf(stderr, "PASS\n");
    return 0;
}

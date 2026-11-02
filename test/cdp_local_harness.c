// E2E harness for the loopback CDP mux: the real identity server + cdp_local
// + file_server on PORT (argv[1]), without the backend link. The test driver
// plays the backend's `cdp_local` call on stdin:
//   grant <resourceId> <secret> <tokenHash>   → prints "ok" / "err"
// Used by browser-extension/test/local-cdp.e2e.ts. Build: make cdp-local-harness
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../cdp_local.h"
#include "../file_server.h"
#include "../identity_server.h"

static unsigned g_port;
static int grant_cb(const char *path, char *out, size_t cap, char *err, size_t err_cap) {
    char token[FILE_GRANT_TOKEN_LEN + 1];
    long long size = 0;
    if (bridge_file_grant(path, token, sizeof token, &size, err, err_cap) != 0) return -1;
    int n = snprintf(out, cap, "{\"token\":\"%s\",\"port\":%u,\"totalSize\":%lld,\"type\":\"%s\"}",
                     token, g_port, size, bridge_file_mime(path));
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

int main(int argc, char **argv) {
    g_port = argc > 1 ? (unsigned)atoi(argv[1]) : 43199;
    ws_fd_t lfd = bridge_identity_server_open((uint16_t)g_port);
    if (lfd == WS_INVALID_FD) { fprintf(stderr, "port %u taken\n", g_port); return 1; }
    cdp_local_init(grant_cb);
    bridge_identity_server_set_cdp_hook(cdp_local_accept);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("listening %u\n", g_port);
    char line[512]; size_t ll = 0;
    for (;;) {
        struct pollfd p[80]; size_t n = 2;
        p[0] = (struct pollfd){ .fd = lfd, .events = POLLIN };
        p[1] = (struct pollfd){ .fd = 0, .events = POLLIN };
        cdp_local_fill_pfds(p, &n, 80);
        if (poll(p, n, 100) > 0) {
            if (p[0].revents & POLLIN) bridge_identity_server_serve(lfd, "harness");
            if (p[1].revents & (POLLIN | POLLHUP)) {
                ssize_t r = read(0, line + ll, sizeof line - 1 - ll);
                if (r <= 0) break;   // driver gone
                ll += (size_t)r; line[ll] = '\0';
                char *nl;
                while ((nl = strchr(line, '\n'))) {
                    *nl = '\0';
                    char rid[160], sec[160], th[64];
                    if (sscanf(line, "grant %159s %159s %63s", rid, sec, th) == 3)
                        puts(cdp_local_grant(rid, sec, th) == 0 ? "ok" : "err");
                    ll -= (size_t)(nl + 1 - line);
                    memmove(line, nl + 1, ll + 1);
                }
            }
            cdp_local_service(p, 2, n - 2);
        }
        cdp_local_tick();
    }
    cdp_local_close_all();
    return 0;
}

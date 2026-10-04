// Loopback file streaming: grant → GET /file?t= through the real identity
// server accept path, Range semantics, bad/missing tokens, CORS preflight.
// Binds a random-ish port by temporarily using the real one; skips if taken.
// Build+run: make test-file-server
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../file_server.h"
#include "../identity_server.h"

static ws_fd_t g_lfd;

// Send `req`, pump the identity server once, read the full response.
static size_t http(const char *req, char *out, size_t cap) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(IDENTITY_SERVER_PORT) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    assert(send(c, req, strlen(req), 0) == (ssize_t)strlen(req));
    struct pollfd p = { .fd = g_lfd, .events = POLLIN };
    assert(poll(&p, 1, 1000) == 1);
    bridge_identity_server_serve(g_lfd, "dev_test");
    size_t n = 0;
    for (;;) {
        ssize_t r = recv(c, out + n, cap - 1 - n, 0);
        if (r <= 0) break;
        n += (size_t)r;
    }
    out[n] = '\0';
    close(c);
    return n;
}

static const char *body_of(const char *resp) { const char *b = strstr(resp, "\r\n\r\n"); return b ? b + 4 : NULL; }

int main(void) {
    g_lfd = bridge_identity_server_open();
    if (g_lfd == WS_INVALID_FD) { printf("SKIP: port %d taken (a bridge is running)\n", IDENTITY_SERVER_PORT); return 0; }

    char path[] = "/tmp/fs-test-XXXXXX.mp4";
    int fd = mkstemps(path, 4);
    assert(fd >= 0);
    enum { N = 700000 };
    unsigned char *data = malloc(N);
    for (int i = 0; i < N; i++) data[i] = (unsigned char)(i * 7 + 3);
    assert(write(fd, data, N) == N);
    close(fd);

    char tok[FILE_GRANT_TOKEN_LEN + 1], tok2[FILE_GRANT_TOKEN_LEN + 1], err[256];
    long long size = 0;
    assert(bridge_file_grant("/nonexistent/x.mp4", tok, sizeof tok, &size, err, sizeof err) == -1);
    assert(strcmp(err, "file_grant: not found") == 0);
    assert(bridge_file_grant("/tmp", tok, sizeof tok, &size, err, sizeof err) == -1);
    assert(bridge_file_grant(path, tok, sizeof tok, &size, err, sizeof err) == 0 && size == N && strlen(tok) == 32);
    assert(bridge_file_grant(path, tok2, sizeof tok2, &size, err, sizeof err) == 0 && strcmp(tok, tok2) == 0);
    char fifo[] = "/tmp/fs-test-fifo-XXXXXX";
    assert(mkdtemp(fifo));
    char fifo_path[64]; snprintf(fifo_path, sizeof fifo_path, "%s/f", fifo);
    assert(mkfifo(fifo_path, 0600) == 0);
    assert(bridge_file_grant(fifo_path, tok, sizeof tok, &size, err, sizeof err) == -1);  // must not block
    unlink(fifo_path); rmdir(fifo);
    printf("PASS: grant (not found / not regular / FIFO doesn't block / stable token)\n");

    static char resp[1 << 21], req[512];
    http("GET /file?t=00000000000000000000000000000000 HTTP/1.1\r\nHost: x\r\n\r\n", resp, sizeof resp);
    assert(strncmp(resp, "HTTP/1.1 403", 12) == 0);
    http("GET /file?x=1 HTTP/1.1\r\nHost: x\r\n\r\n", resp, sizeof resp);
    assert(strncmp(resp, "HTTP/1.1 403", 12) == 0);
    printf("PASS: bad/missing token -> 403\n");

    snprintf(req, sizeof req, "GET /file?t=%s HTTP/1.1\r\nOrigin: https://todofor.ai\r\n\r\n", tok);
    size_t n = http(req, resp, sizeof resp);
    assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);
    assert(strstr(resp, "Content-Type: video/mp4") && strstr(resp, "Accept-Ranges: bytes"));
    assert(strstr(resp, "Access-Control-Allow-Origin: https://todofor.ai"));
    assert(n - (size_t)(body_of(resp) - resp) == N && memcmp(body_of(resp), data, N) == 0);
    printf("PASS: full GET, byte-exact, CORS\n");

    snprintf(req, sizeof req, "GET /file?t=%s HTTP/1.1\r\nRange: bytes=1000-1999\r\n\r\n", tok);
    n = http(req, resp, sizeof resp);
    assert(strncmp(resp, "HTTP/1.1 206", 12) == 0 && strstr(resp, "Content-Range: bytes 1000-1999/700000"));
    assert(n - (size_t)(body_of(resp) - resp) == 1000 && memcmp(body_of(resp), data + 1000, 1000) == 0);
    snprintf(req, sizeof req, "GET /file?t=%s HTTP/1.1\r\nrange: bytes=699990-\r\n\r\n", tok);
    n = http(req, resp, sizeof resp);
    assert(strstr(resp, "Content-Range: bytes 699990-699999/700000") && n - (size_t)(body_of(resp) - resp) == 10);
    snprintf(req, sizeof req, "GET /file?t=%s HTTP/1.1\r\nRange: bytes=-5\r\n\r\n", tok);
    n = http(req, resp, sizeof resp);
    assert(strstr(resp, "Content-Range: bytes 699995-699999/700000") && memcmp(body_of(resp), data + 699995, 5) == 0);
    snprintf(req, sizeof req, "GET /file?t=%s HTTP/1.1\r\nRange: bytes=800000-\r\n\r\n", tok);
    http(req, resp, sizeof resp);
    assert(strncmp(resp, "HTTP/1.1 416", 12) == 0 && strstr(resp, "Content-Range: bytes */700000"));
    // Multi-range / malformed / reversed → whole file, 200.
    const char *whole[] = { "bytes=1000-1999,3000-3999", "bytes=-", "bytes=5-2", "bytes=abc", "items=0-5" };
    for (size_t i = 0; i < sizeof whole / sizeof *whole; i++) {
        snprintf(req, sizeof req, "GET /file?t=%s HTTP/1.1\r\nRange: %s\r\n\r\n", tok, whole[i]);
        n = http(req, resp, sizeof resp);
        assert(strncmp(resp, "HTTP/1.1 200", 12) == 0 && n - (size_t)(body_of(resp) - resp) == N);
    }
    printf("PASS: ranges (a-b, a-, -n, unsatisfiable, multi/malformed -> 200 whole)\n");

    snprintf(req, sizeof req, "HEAD /file?t=%s HTTP/1.1\r\nRange: bytes=0-9\r\n\r\n", tok);
    n = http(req, resp, sizeof resp);
    assert(strstr(resp, "Content-Length: 700000") && n == (size_t)(body_of(resp) - resp));
    snprintf(req, sizeof req, "OPTIONS /file?t=%s HTTP/1.1\r\nOrigin: http://localhost:3000\r\n\r\n", tok);
    http(req, resp, sizeof resp);
    assert(strncmp(resp, "HTTP/1.0 204", 12) == 0 && strstr(resp, "Access-Control-Allow-Headers: Range"));
    http("GET /identity HTTP/1.1\r\n\r\n", resp, sizeof resp);
    assert(strstr(resp, "\"deviceId\":\"dev_test\""));
    printf("PASS: HEAD, preflight, /identity unchanged\n");

    unlink(path);
    snprintf(req, sizeof req, "GET /file?t=%s HTTP/1.1\r\n\r\n", tok);
    http(req, resp, sizeof resp);
    assert(strncmp(resp, "HTTP/1.1 404", 12) == 0);
    printf("PASS: deleted file -> 404\n");
    bridge_identity_server_close(g_lfd);
    free(data);
    return 0;
}

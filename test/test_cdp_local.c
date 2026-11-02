// Loopback CDP mux (cdp_local.c) through the real identity-server accept path:
// SHA-1/HMAC vectors, extension mutual auth, probe 200/404, client routing,
// broadcast, close propagation, wrong proof, grant, token rotation.
// Build+run: make test-cdp-local
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../cdp_local.h"
#include "../identity_server.h"

static ws_fd_t g_lfd;

static void hexs(const uint8_t *b, size_t n, char *o) { for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", b[i]); }

// One daemon-loop tick: accept on the identity port + service cdp_local.
static void tick(int ms) {
    struct pollfd p[80]; size_t n = 1;
    p[0].fd = g_lfd; p[0].events = POLLIN; p[0].revents = 0;
    cdp_local_fill_pfds(p, &n, 80);
    if (poll(p, n, ms) > 0) {
        if (p[0].revents & POLLIN) bridge_identity_server_serve(g_lfd, "dev_test");
        cdp_local_service(p, 1, n - 1);
    }
    cdp_local_tick();
}

static int dial(void) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(IDENTITY_SERVER_PORT) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    return c;
}

// Read until `\r\n\r\n` (pumping the server); returns the status code.
static int read_head(int c) {
    char buf[1024]; size_t n = 0;
    for (int i = 0; i < 200; i++) {
        tick(5);
        struct pollfd p = { .fd = c, .events = POLLIN };
        if (poll(&p, 1, 0) <= 0) continue;
        // byte by byte so frames after the head stay in the socket
        ssize_t r = recv(c, buf + n, 1, 0);
        if (r <= 0) break;
        n++; buf[n] = 0;
        if (n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0) return atoi(buf + 9);
    }
    return n > 12 ? atoi(buf + 9) : -1;
}

static int http(const char *req) {
    int c = dial();
    assert(send(c, req, strlen(req), 0) == (ssize_t)strlen(req));
    int st = read_head(c);
    close(c);
    return st;
}

static int ws_open(const char *path, const char *origin) {
    int c = dial();
    char req[1024];
    snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n%s%s%s\r\n",
             path, IDENTITY_SERVER_PORT, origin ? "Origin: " : "", origin ? origin : "", origin ? "\r\n" : "");
    assert(send(c, req, strlen(req), 0) == (ssize_t)strlen(req));
    int st = read_head(c);
    if (st != 101) { close(c); return -st; }
    return c;
}

static void ws_send(int c, const char *s, size_t n) {
    uint8_t h[14] = { 0x81 }; size_t hl;
    if (n < 126) { h[1] = 0x80 | (uint8_t)n; hl = 2; }
    else if (n < 65536) { h[1] = 0x80 | 126; h[2] = (uint8_t)(n >> 8); h[3] = (uint8_t)n; hl = 4; }
    else { h[1] = 0x80 | 127; for (int i = 0; i < 8; i++) h[2 + i] = (uint8_t)((uint64_t)n >> (56 - 8 * i)); hl = 10; }
    uint8_t m[4] = { 1, 2, 3, 4 }; memcpy(h + hl, m, 4); hl += 4;
    uint8_t *b = malloc(hl + n); memcpy(b, h, hl);
    for (size_t i = 0; i < n; i++) b[hl + i] = (uint8_t)s[i] ^ m[i & 3];
    size_t off = 0;
    while (off < hl + n) { ssize_t w = send(c, b + off, hl + n - off, 0); assert(w > 0); off += (size_t)w; tick(0); }
    free(b);
}
static void ws_say(int c, const char *s) { ws_send(c, s, strlen(s)); }

// Next frame's payload (NUL-terminated) and opcode; -1 = nothing within ~1s, 0 = EOF.
static int ws_recv(int c, char *out, size_t cap, int *op) {
    static uint8_t buf[1 << 20]; size_t n = 0; int eof = 0;
    for (int i = 0; i < 200; i++) {
        tick(5);
        struct pollfd p = { .fd = c, .events = POLLIN };
        while (!eof && poll(&p, 1, 0) > 0) {
            ssize_t r = recv(c, buf + n, sizeof buf - n, MSG_DONTWAIT);
            if (r == 0) eof = 1;
            if (r <= 0) break;
            n += (size_t)r;
        }
        if (n < 2) { if (eof) return 0; continue; }
        uint64_t len = buf[1] & 0x7f; size_t hl = 2;
        if (len == 126) { if (n < 4) continue; len = (uint64_t)buf[2] << 8 | buf[3]; hl = 4; }
        else if (len == 127) { if (n < 10) continue; len = 0; for (int k = 0; k < 8; k++) len = len << 8 | buf[2 + k]; hl = 10; }
        if (n < hl + len) continue;
        assert(!(buf[1] & 0x80));   // server frames are unmasked
        assert(n == hl + len);      // tests read one frame at a time
        *op = buf[0] & 0x0f;
        assert(len < cap);
        memcpy(out, buf + hl, len); out[len] = 0;
        return 1;
    }
    return -1;
}

static void expect(int c, const char *want) {
    char m[1 << 16]; int op = 0;
    int r = ws_recv(c, m, sizeof m, &op);
    if (r != 1 || op != 1 || strcmp(m, want) != 0) { fprintf(stderr, "want %s, got r=%d op=%d '%s'\n", want, r, op, r == 1 ? m : ""); assert(0); }
}
static void expect_close(int c, int code) {
    char m[256]; int op = 0;
    int r = ws_recv(c, m, sizeof m, &op);
    if (r != 1 || op != 8 || ((uint8_t)m[0] << 8 | (uint8_t)m[1]) != code) { fprintf(stderr, "want close %d, got r=%d op=%d\n", code, r, op); assert(0); }
}

static void mac(const char *key, const char *msg, char out[41]) {
    uint8_t d[20]; cdpl_hmac_sha1((const uint8_t *)key, strlen(key), (const uint8_t *)msg, strlen(msg), d); hexs(d, 20, out);
}
static void sha(const char *s, char out[41]) { uint8_t d[20]; cdpl_sha1((const uint8_t *)s, strlen(s), d); hexs(d, 20, out); }

static const char *SECRET = "s3cr3t-0123456789abcdef0123456789abcdef";

// Open + authenticate an extension for resource `rid`.
static int ext_auth(const char *rid, const char *secret) {
    int c = ws_open("/cdp-local/ext", "chrome-extension://abc");
    assert(c > 0);
    char m[256]; int op;
    assert(ws_recv(c, m, sizeof m, &op) == 1 && strncmp(m, "hello ", 6) == 0);
    char msg[128], p[41], a[256];
    snprintf(msg, sizeof msg, "ext|%s", m + 6); mac(secret, msg, p);
    snprintf(a, sizeof a, "auth %s en0nce %s", rid, p);
    ws_say(c, a);
    return c;
}

static int grant_cb(const char *path, char *out, size_t cap, char *err, size_t err_cap) {
    if (strcmp(path, "/ok.png") != 0) { snprintf(err, err_cap, "file_grant: not found"); return -1; }
    snprintf(out, cap, "{\"token\":\"t\",\"port\":1,\"totalSize\":3,\"type\":\"image/png\"}");
    return 0;
}

int main(void) {
    char h[41];
    sha("abc", h); assert(strcmp(h, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);
    sha("", h); assert(strcmp(h, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0);
    sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", h); assert(strcmp(h, "84983e441c3bd26ebaae4aa1f95129e5e54670f1") == 0);
    mac("key", "The quick brown fox jumps over the lazy dog", h); assert(strcmp(h, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9") == 0);

    g_lfd = bridge_identity_server_open(IDENTITY_SERVER_PORT);
    if (g_lfd == WS_INVALID_FD) { printf("SKIP: port %d taken\n", IDENTITY_SERVER_PORT); return 0; }
    cdp_local_init(grant_cb);
    bridge_identity_server_set_cdp_hook(cdp_local_accept);

    char th[41]; sha("TOKEN_A", th);
    assert(cdp_local_grant("res-a", SECRET, th) == 0);
    assert(cdp_local_grant("bad id!", SECRET, th) != 0);
    assert(cdp_local_grant("res-x", "short", th) != 0);

    // No extension yet: probe 404, upgrade 404.
    assert(http("GET /cdp-local/cdp?token=TOKEN_A HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") == 404);
    // A web page (Origin) or a rebinding Host is refused outright.
    assert(http("GET /cdp-local/cdp?token=TOKEN_A HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.com\r\n\r\n") == 403);
    assert(http("GET /cdp-local/cdp?token=TOKEN_A HTTP/1.1\r\nHost: evil.com\r\n\r\n") == 403);
    // Extension endpoint needs an extension Origin.
    assert(ws_open("/cdp-local/ext", "https://evil.com") == -403);

    // Wrong proof → 4401.
    int bad = ext_auth("res-a", "wrong-secret-0123456789abcdef0123456789");
    expect_close(bad, 4401); close(bad);
    // Unknown resource → 4401.
    bad = ext_auth("res-zzz", SECRET);
    expect_close(bad, 4401); close(bad);

    int ext = ext_auth("res-a", SECRET);
    char want[128], p[41]; mac(SECRET, "bridge|en0nce", p); snprintf(want, sizeof want, "ok %s", p);
    expect(ext, want);
    assert(cdp_local_count(1) == 1);

    assert(http("GET /cdp-local/cdp?token=TOKEN_A HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") == 200);
    assert(http("GET /cdp-local/cdp?token=TOKEN_B HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") == 404);
    assert(ws_open("/cdp-local/cdp?token=TOKEN_B", NULL) == -404);

    // Two clients; the extension sees `open`.
    int c1 = ws_open("/cdp-local/cdp?token=TOKEN_A&todoId=todo-1", NULL);
    assert(c1 > 0);
    char m[1 << 16]; int op;
    assert(ws_recv(ext, m, sizeof m, &op) == 1 && strncmp(m, "open local:", 11) == 0);
    char id1[40]; sscanf(m + 5, "%39s", id1); assert(strstr(m, " todo-1"));
    int c2 = ws_open("/cdp-local/cdp?token=TOKEN_A", NULL);
    assert(ws_recv(ext, m, sizeof m, &op) == 1 && strncmp(m, "open local:", 11) == 0);
    char id2[40]; sscanf(m + 5, "%39s", id2); assert(strcmp(id1, id2) != 0 && !strchr(m + 5, ' '));

    // Client → extension, wrapped with its id.
    ws_say(c1, "{\"id\":1,\"method\":\"Target.getTargets\"}");
    snprintf(want, sizeof want, "cdp %s\n{\"id\":1,\"method\":\"Target.getTargets\"}", id1); expect(ext, want);
    // Extension → one client.
    char r[128]; snprintf(r, sizeof r, "cdp %s\n{\"id\":1,\"result\":{}}", id1); ws_say(ext, r);
    expect(c1, "{\"id\":1,\"result\":{}}");
    char none[64]; assert(ws_recv(c2, none, sizeof none, &op) == -1);
    // Broadcast.
    ws_say(ext, "cdp *\n{\"method\":\"Target.targetCreated\"}");
    expect(c1, "{\"method\":\"Target.targetCreated\"}");
    expect(c2, "{\"method\":\"Target.targetCreated\"}");
    // Big frame (1 MB-ish, 64-bit length path) both ways.
    size_t big = 300000; char *bb = malloc(big + 64);
    int hl = snprintf(bb, 64, "cdp %s\n", id2); memset(bb + hl, 'x', big); bb[hl + big] = 0;
    ws_send(ext, bb, hl + big);
    { static char got[1 << 20]; assert(ws_recv(c2, got, sizeof got, &op) == 1 && strlen(got) == big); }
    free(bb);
    // Ping, grant.
    ws_say(ext, "ping"); expect(ext, "pong");
    ws_say(ext, "grant g1\n/ok.png"); expect(ext, "grant g1\n{\"token\":\"t\",\"port\":1,\"totalSize\":3,\"type\":\"image/png\"}");
    ws_say(ext, "grant g2\n/nope"); expect(ext, "grant g2\n!file_grant: not found");

    // Client goes away → extension hears `close`.
    close(c2);
    snprintf(want, sizeof want, "close %s", id2); expect(ext, want);
    // Extension refuses a client → it is closed 4403, no echo.
    snprintf(r, sizeof r, "close %s", id1); ws_say(ext, r);
    expect_close(c1, 4403); close(c1);
    assert(ws_recv(ext, m, sizeof m, &op) == -1);

    // Extension drop takes clients with it (4004).
    c1 = ws_open("/cdp-local/cdp?token=TOKEN_A", NULL);
    assert(ws_recv(ext, m, sizeof m, &op) == 1);
    close(ext);
    expect_close(c1, 4004); close(c1);
    for (int i = 0; i < 20; i++) tick(5);
    assert(cdp_local_count(1) == 0 && cdp_local_count(0) == 0);
    assert(http("GET /cdp-local/cdp?token=TOKEN_A HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") == 404);

    // Token rotation: re-grant with a new hash cuts the live extension (4003).
    ext = ext_auth("res-a", SECRET);
    mac(SECRET, "bridge|en0nce", p); snprintf(want, sizeof want, "ok %s", p); expect(ext, want);
    assert(cdp_local_grant("res-a", SECRET, th) == 0);   // same → kept
    assert(cdp_local_count(1) == 1);
    char th2[41]; sha("TOKEN_A2", th2);
    assert(cdp_local_grant("res-a", SECRET, th2) == 0);
    expect_close(ext, 4003); close(ext);
    for (int i = 0; i < 20; i++) tick(5);
    assert(cdp_local_count(1) == 0);

    // Auth timeout.
    int slow = ws_open("/cdp-local/ext", "moz-extension://x");
    assert(ws_recv(slow, m, sizeof m, &op) == 1);
    for (int i = 0; i < 60 && ws_recv(slow, m, sizeof m, &op) == -1; i++) {}
    assert(op == 8 && ((uint8_t)m[0] << 8 | (uint8_t)m[1]) == 4408);
    close(slow);

    cdp_local_close_all();
    bridge_identity_server_close(g_lfd);
    printf("PASS: cdp_local\n");
    return 0;
}

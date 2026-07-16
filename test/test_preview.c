// Preview relay smoke test: spins a tiny HTTP server on a random port, then
// drives bridge_preview_handle_request() and checks the emitted chunk frames.
//   1. unregistered port → terminal error chunk
//   2. small HTML response → seq0 (status/headers) + seq1 (body, done)
//   3. large body (100KB) → multiple chunks, reassembles byte-exact
//   4. set-cookie headers → setCookie array, stripped from headers
//   5. connection refused → error chunk
// Build+run: make test-preview

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../json.h"
#include "../preview.h"

// ── Tiny HTTP/1.0 server ────────────────────────────────────────────────────

static char g_srv_response[256 * 1024];
static size_t g_srv_response_len;
static int g_srv_port;

static void *server_thread(void *arg) {
    int lfd = *(int *)arg;
    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) break;
        char buf[8192];
        // Read until end-of-headers (requests in this test have no body).
        size_t n = 0;
        while (n < sizeof buf - 1) {
            long r = read(c, buf + n, sizeof buf - 1 - n);
            if (r <= 0) break;
            n += (size_t)r;
            buf[n] = 0;
            if (strstr(buf, "\r\n\r\n")) break;
        }
        (void)!write(c, g_srv_response, g_srv_response_len);
        close(c);
    }
    return NULL;
}

static int start_server(void) {
    static int lfd;
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = 0 };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(lfd, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t alen = sizeof a;
    assert(getsockname(lfd, (struct sockaddr *)&a, &alen) == 0);
    assert(listen(lfd, 8) == 0);
    pthread_t t;
    pthread_create(&t, NULL, server_thread, &lfd);
    pthread_detach(t);
    return ntohs(a.sin_port);
}

// ── Emit collector ──────────────────────────────────────────────────────────

#define MAX_CHUNKS 64
static char *g_chunks[MAX_CHUNKS];
static size_t g_chunk_lens[MAX_CHUNKS];
static int g_nchunks;

static int collect(void *ctx, const char *json, size_t len) {
    (void)ctx;
    assert(g_nchunks < MAX_CHUNKS);
    assert(len <= 64 * 1024);  // must fit a Noise frame (with tag slack)
    g_chunks[g_nchunks] = malloc(len + 1);
    memcpy(g_chunks[g_nchunks], json, len);
    g_chunks[g_nchunks][len] = 0;
    g_chunk_lens[g_nchunks] = len;
    g_nchunks++;
    return 0;
}

static void reset_chunks(void) {
    for (int i = 0; i < g_nchunks; i++) free(g_chunks[i]);
    g_nchunks = 0;
}

// Pull payload obj from chunk i.
static void chunk_payload(int i, const char **p, size_t *plen) {
    assert(json_get_obj(g_chunks[i], g_chunk_lens[i], "payload", p, plen));
    const char *t; size_t tlen;
    assert(json_get_str(g_chunks[i], g_chunk_lens[i], "type", &t, &tlen));
    assert(tlen == 27 && memcmp(t, "preview:http_response_chunk", 27) == 0);
}

static void run_req(const char *payload) {
    reset_chunks();
    bridge_preview_handle_request(payload, strlen(payload), collect, NULL);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_srv_port = start_server();
    char payload[512];

    // 1: unregistered port → single terminal error chunk
    snprintf(payload, sizeof payload,
             "{\"requestId\":\"r1\",\"port\":%d,\"method\":\"GET\",\"path\":\"/\",\"headers\":{}}", g_srv_port);
    run_req(payload);
    assert(g_nchunks == 1);
    {
        const char *p; size_t plen; chunk_payload(0, &p, &plen);
        const char *err; size_t elen;
        assert(json_get_str(p, plen, "error", &err, &elen));
        assert(memmem(err, elen, "not registered", 14));
        int done; assert(json_get_bool(p, plen, "done", &done) && done);
    }
    printf("ok 1 unregistered port rejected\n");

    bridge_preview_allow_port(g_srv_port);

    // 2: small response
    g_srv_response_len = (size_t)snprintf(g_srv_response, sizeof g_srv_response,
        "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nX-Test: yes\r\nConnection: close\r\n\r\n<h1>hi</h1>");
    run_req(payload);
    assert(g_nchunks == 2);
    {
        const char *p; size_t plen; chunk_payload(0, &p, &plen);
        long st; assert(json_get_long(p, plen, "status", &st) && st == 200);
        const char *h; size_t hlen;
        assert(json_get_obj(p, plen, "headers", &h, &hlen));
        const char *v; size_t vl;
        assert(json_get_str(h, hlen, "X-Test", &v, &vl) && vl == 3);
        assert(!json_get_str(h, hlen, "Connection", &v, &vl));  // hop-by-hop stripped
        int done; assert(json_get_bool(p, plen, "done", &done) && !done);
        long seq; assert(json_get_long(p, plen, "seq", &seq) && seq == 0);

        chunk_payload(1, &p, &plen);
        assert(json_get_long(p, plen, "seq", &seq) && seq == 1);
        assert(json_get_bool(p, plen, "done", &done) && done);
        const char *b64; size_t b64l;
        assert(json_get_str(p, plen, "bodyB64", &b64, &b64l));
        char body[64];
        size_t bl = b64_decode(b64, b64l, body, sizeof body);
        assert(bl == 11 && memcmp(body, "<h1>hi</h1>", 11) == 0);
    }
    printf("ok 2 small response\n");

    // 3: large body → chunked reassembly (100KB pattern, > 2 chunks of 32KB)
    {
        const size_t BODY = 100 * 1024;
        size_t hl = (size_t)snprintf(g_srv_response, sizeof g_srv_response,
            "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %zu\r\n\r\n", BODY);
        for (size_t i = 0; i < BODY; i++) g_srv_response[hl + i] = (char)(i * 31 + 7);
        g_srv_response_len = hl + BODY;
        run_req(payload);
        assert(g_nchunks == 1 + 4);  // 100KB / 32KB = 4 body chunks
        char *acc = malloc(BODY + 4096); size_t acc_len = 0;
        for (int i = 1; i < g_nchunks; i++) {
            const char *p; size_t plen; chunk_payload(i, &p, &plen);
            long seq; assert(json_get_long(p, plen, "seq", &seq) && seq == i);
            const char *b64; size_t b64l;
            assert(json_get_str(p, plen, "bodyB64", &b64, &b64l));
            acc_len += b64_decode(b64, b64l, acc + acc_len, BODY + 4096 - acc_len);
            int done; assert(json_get_bool(p, plen, "done", &done) && done == (i == g_nchunks - 1));
        }
        assert(acc_len == BODY);
        for (size_t i = 0; i < BODY; i++) assert(acc[i] == (char)(i * 31 + 7));
        free(acc);
    }
    printf("ok 3 chunked reassembly (100KB)\n");

    // 4: set-cookie → array, stripped from headers
    g_srv_response_len = (size_t)snprintf(g_srv_response, sizeof g_srv_response,
        "HTTP/1.0 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2\r\nContent-Type: text/plain\r\n\r\nx");
    run_req(payload);
    {
        const char *p; size_t plen; chunk_payload(0, &p, &plen);
        const char *h; size_t hlen;
        assert(json_get_obj(p, plen, "headers", &h, &hlen));
        const char *v; size_t vl;
        assert(!json_get_str(h, hlen, "Set-Cookie", &v, &vl));
        assert(memmem(p, plen, "\"setCookie\":[\"a=1; Path=/\",\"b=2\"]", 33));
    }
    printf("ok 4 set-cookie array\n");

    // 5: connection refused (allow a port nothing listens on)
    {
        int dead = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = 0 };
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(dead, (struct sockaddr *)&a, sizeof a);
        socklen_t alen = sizeof a;
        getsockname(dead, (struct sockaddr *)&a, &alen);
        close(dead);  // port now free — nothing listening
        int dport = ntohs(a.sin_port);
        bridge_preview_allow_port(dport);
        snprintf(payload, sizeof payload,
                 "{\"requestId\":\"r5\",\"port\":%d,\"method\":\"GET\",\"path\":\"/\",\"headers\":{}}", dport);
        run_req(payload);
        assert(g_nchunks == 1);
        const char *p; size_t plen; chunk_payload(0, &p, &plen);
        const char *err; size_t elen;
        assert(json_get_str(p, plen, "error", &err, &elen));
        assert(memmem(err, elen, "Nothing is listening", 20));
    }
    printf("ok 5 connection refused\n");

    printf("all preview tests passed\n");
    return 0;
}

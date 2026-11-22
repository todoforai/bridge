// Preview relay smoke test: spins a tiny HTTP server on a random port, then
// drives bridge_preview_handle_request() and checks the emitted chunk frames.
//   1. the daemon-side gate: only registered ports get served
//   2. small HTML response → seq0 (status/headers) + seq1 (body, done)
//   3. large body (100KB) → multiple chunks, reassembles byte-exact
//   4. set-cookie headers → setCookie array, stripped from headers
//   5. connection refused → error chunk
//   6. the real thing: a fetch driven through an off-loop job worker
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

#include "../jobs.h"
#include "../json.h"
#include "../preview.h"
#include "../preview_ws.h"
#include <poll.h>

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

// ── Job worker plumbing (case 6) ────────────────────────────────────────────

static int preview_job_body(const char *p, size_t n, bridge_job_emit_fn emit, void *ctx) {
    bridge_preview_handle_request(p, n, emit, ctx);
    return 0;
}

static int  g_job_frames, g_job_dones, g_job_oks;
static char g_job_first[512];

static int job_on_frame(void *c, const bridge_job_t *j, const char *d, size_t l) {
    (void)c; (void)j;
    if (g_job_frames == 0) {
        size_t k = l < sizeof g_job_first - 1 ? l : sizeof g_job_first - 1;
        memcpy(g_job_first, d, k); g_job_first[k] = '\0';
    }
    g_job_frames++;
    return 0;
}

static void job_on_done(void *c, const bridge_job_t *j, int ok, const char *e) {
    (void)c; (void)j; (void)e;
    g_job_dones++; g_job_oks += ok;
}


// ── Minimal RFC 6455 loopback echo server for preview_ws tests ──────────────
static int g_ws_srv_port = 0;
static char g_ws_seen_proto[128] = "";

static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_exact(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static void *ws_echo_thread(void *arg) {
    int lfd = *(int *)arg;
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) break;
        char hdr[4096];
        size_t hlen = 0;
        while (hlen + 1 < sizeof hdr) {
            ssize_t r = read(cfd, hdr + hlen, 1);
            if (r <= 0) break;
            hlen++;
            if (hlen >= 4 && memcmp(hdr + hlen - 4, "\r\n\r\n", 4) == 0) break;
        }
        hdr[hlen] = '\0';
        const char *ph = strstr(hdr, "Sec-WebSocket-Protocol: ");
        if (ph) {
            ph += 24;
            const char *eol = strstr(ph, "\r\n");
            size_t pl = eol ? (size_t)(eol - ph) : strlen(ph);
            if (pl >= sizeof g_ws_seen_proto) pl = sizeof g_ws_seen_proto - 1;
            memcpy(g_ws_seen_proto, ph, pl);
            g_ws_seen_proto[pl] = '\0';
        }
        const char *resp =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: dummy\r\n\r\n";
        (void)write_exact(cfd, (const uint8_t *)resp, strlen(resp));

        for (;;) {
            uint8_t h2[2];
            if (read_exact(cfd, h2, 2) != 0) break;
            uint8_t op = h2[0] & 0x0f;
            int masked = (h2[1] & 0x80) != 0;
            uint64_t plen = h2[1] & 0x7f;
            if (plen == 126) {
                uint8_t ext[2];
                if (read_exact(cfd, ext, 2) != 0) break;
                plen = ((uint64_t)ext[0] << 8) | ext[1];
            } else if (plen == 127) {
                uint8_t ext[8];
                if (read_exact(cfd, ext, 8) != 0) break;
                plen = 0;
                for (int i = 0; i < 8; i++) plen = (plen << 8) | ext[i];
            }
            uint8_t mask[4] = {0};
            if (masked && read_exact(cfd, mask, 4) != 0) break;
            uint8_t *body = plen ? malloc((size_t)plen) : NULL;
            if (plen && (!body || read_exact(cfd, body, (size_t)plen) != 0)) { free(body); break; }
            if (masked) for (size_t i = 0; i < (size_t)plen; i++) body[i] ^= mask[i & 3];

            if (op == 0x8) { free(body); break; }
            uint8_t oh[10];
            size_t ohl = 0;
            oh[ohl++] = (uint8_t)(0x80 | op);
            if (plen < 126) {
                oh[ohl++] = (uint8_t)plen;
            } else {
                oh[ohl++] = 126;
                oh[ohl++] = (uint8_t)(plen >> 8);
                oh[ohl++] = (uint8_t)(plen & 0xff);
            }
            if (write_exact(cfd, oh, ohl) != 0 || (plen && write_exact(cfd, body, (size_t)plen) != 0)) {
                free(body);
                break;
            }
            free(body);
        }
        close(cfd);
    }
    return NULL;
}

static char  *g_pws_msgs[32];
static size_t g_pws_lens[32];
static int    g_pws_n = 0;

static void pws_reset(void) {
    for (int i = 0; i < g_pws_n; i++) free(g_pws_msgs[i]);
    g_pws_n = 0;
}

static int pws_capture(void *ctx, const char *json, size_t len) {
    (void)ctx;
    assert(g_pws_n < 32);
    g_pws_msgs[g_pws_n] = malloc(len + 1);
    memcpy(g_pws_msgs[g_pws_n], json, len);
    g_pws_msgs[g_pws_n][len] = '\0';
    g_pws_lens[g_pws_n] = len;
    g_pws_n++;
    return 0;
}

static void pws_pump(preview_ws_relay_t *r, int timeout_ms) {
    struct pollfd pfds[4];
    size_t n = 0;
    preview_ws_fill_pfds(r, pfds, &n, 4);
    if (n == 0) return;
    if (poll(pfds, (nfds_t)n, timeout_ms) > 0)
        preview_ws_service(r, pfds, 0, n);
}

int main(int argc, char **argv) {
    // Job workers are this same binary, re-executed.
    if (argc >= 3 && strcmp(argv[1], "__job") == 0)
        return bridge_job_worker_main(preview_job_body);
    bridge_jobs_init_self(argv[0]);

    signal(SIGPIPE, SIG_IGN);
    g_srv_port = start_server();
    char payload[512];

    // 1: the gate the daemon applies before starting a worker. It can't live
    // in handle_request any more — that runs in a worker process which never
    // saw the registration — so this is the only thing standing between a
    // backend request and an arbitrary loopback fetch.
    snprintf(payload, sizeof payload,
             "{\"requestId\":\"r1\",\"port\":%d,\"method\":\"GET\",\"path\":\"/\",\"headers\":{}}", g_srv_port);
    {
        char err[128];
        assert(bridge_preview_authorize(payload, strlen(payload), err, sizeof err) != 0);
        assert(strstr(err, "not registered"));

        bridge_preview_allow_port(g_srv_port);
        assert(bridge_preview_authorize(payload, strlen(payload), err, sizeof err) == 0);

        // A different port stays refused, and a malformed one too.
        char other[512];
        snprintf(other, sizeof other,
                 "{\"requestId\":\"r1\",\"port\":%d,\"method\":\"GET\",\"path\":\"/\",\"headers\":{}}",
                 g_srv_port + 1);
        assert(bridge_preview_authorize(other, strlen(other), err, sizeof err) != 0);
        assert(bridge_preview_authorize("{\"requestId\":\"x\"}", 17, err, sizeof err) != 0);
    }
    printf("ok 1 only registered ports are authorized\n");

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

    // 6: end-to-end through a worker process. The cases above all run the
    // fetch in-process, which is exactly how a worker-only failure (state the
    // daemon holds but a fresh process doesn't) slips through unnoticed.
    {
        g_srv_response_len = (size_t)snprintf(g_srv_response, sizeof g_srv_response,
            "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nvia-worker");
        snprintf(payload, sizeof payload,
                 "{\"requestId\":\"r6\",\"port\":%d,\"method\":\"GET\",\"path\":\"/\",\"headers\":{}}",
                 g_srv_port);
        bridge_jobs_t jobs;
        memset(&jobs, 0, sizeof jobs);
        assert(bridge_job_start(&jobs, BRIDGE_JOB_PREVIEW, payload, strlen(payload),
                                0, 20000, "r6", 2, NULL, 0, NULL, 0) == 0);
        for (int i = 0; i < 4000 && g_job_dones == 0; i++) {
            bridge_jobs_poll(&jobs, i * 5, job_on_frame, job_on_done, NULL);
            usleep(5000);
        }
        assert(g_job_dones == 1 && g_job_oks == 1);
        assert(g_job_frames == 2);
        assert(strstr(g_job_first, "\"status\":200"));
        bridge_jobs_shutdown(&jobs);
    }
    printf("ok 6 fetch through an off-loop worker process\n");

    // 7: preview_ws rejects unregistered port
    {
        preview_ws_relay_t rel;
        preview_ws_init(&rel, pws_capture, NULL, NULL);
        pws_reset();
        const char *open_bad = "{\"streamId\":\"ws1\",\"port\":19999,\"path\":\"/\"}";
        preview_ws_on_open(&rel, open_bad, strlen(open_bad));
        assert(g_pws_n == 1);
        assert(strstr(g_pws_msgs[0], "\"type\":\"preview:ws_opened\""));
        assert(strstr(g_pws_msgs[0], "\"error\":"));
        preview_ws_close_all(&rel);
    }
    printf("ok 7 preview_ws rejects unregistered port\n");

    // 8: preview_ws open (with subprotocol) + text echo + 40KB chunked binary round-trip
    {
        int wlfd = socket(AF_INET, SOCK_STREAM, 0);
        assert(wlfd >= 0);
        int one = 1;
        setsockopt(wlfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in wa = { .sin_family = AF_INET, .sin_port = 0 };
        wa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        assert(bind(wlfd, (struct sockaddr *)&wa, sizeof wa) == 0);
        assert(listen(wlfd, 4) == 0);
        socklen_t walen = sizeof wa;
        getsockname(wlfd, (struct sockaddr *)&wa, &walen);
        g_ws_srv_port = ntohs(wa.sin_port);
        pthread_t wtid;
        pthread_create(&wtid, NULL, ws_echo_thread, &wlfd);
        pthread_detach(wtid);

        bridge_preview_allow_port(g_ws_srv_port);
        preview_ws_relay_t rel;
        preview_ws_init(&rel, pws_capture, NULL, NULL);
        pws_reset();

        char open_ok[256];
        snprintf(open_ok, sizeof open_ok,
                 "{\"streamId\":\"ws2\",\"port\":%d,\"path\":\"/hmr\",\"protocols\":[\"vite-hmr\"]}",
                 g_ws_srv_port);
        preview_ws_on_open(&rel, open_ok, strlen(open_ok));
        assert(g_pws_n == 1);
        assert(strstr(g_pws_msgs[0], "\"type\":\"preview:ws_opened\""));
        assert(!strstr(g_pws_msgs[0], "\"error\""));
        assert(strcmp(g_ws_seen_proto, "vite-hmr") == 0);

        // Text round-trip
        pws_reset();
        const char *d1 = "{\"streamId\":\"ws2\",\"binary\":false,\"text\":\"hello hmr\",\"fin\":true}";
        preview_ws_on_data(&rel, d1, strlen(d1));
        for (int i = 0; i < 40 && g_pws_n == 0; i++) pws_pump(&rel, 25);
        assert(g_pws_n == 1);
        const char *pl; size_t pll;
        assert(json_get_obj(g_pws_msgs[0], g_pws_lens[0], "payload", &pl, &pll));
        const char *b64; size_t b64l;
        assert(json_get_str(pl, pll, "dataB64", &b64, &b64l));
        char dec[64];
        size_t dl = b64_decode(b64, b64l, dec, sizeof dec);
        assert(dl == 9 && memcmp(dec, "hello hmr", 9) == 0);

        // 40KB binary round-trip: chunked in (20KB + 20KB) -> echoed -> chunked out (32KB + 8KB)
        pws_reset();
        size_t big_n = 40 * 1024;
        uint8_t *big = malloc(big_n);
        for (size_t i = 0; i < big_n; i++) big[i] = (uint8_t)(i * 31 + 7);
        char *b1 = malloc(32000), *b2 = malloc(32000);
        b64_encode(big, 20 * 1024, b1, 32000);
        b64_encode(big + 20 * 1024, 20 * 1024, b2, 32000);
        char *f1 = malloc(36000), *f2 = malloc(36000);
        snprintf(f1, 36000, "{\"streamId\":\"ws2\",\"binary\":true,\"dataB64\":\"%s\",\"fin\":false}", b1);
        snprintf(f2, 36000, "{\"streamId\":\"ws2\",\"binary\":true,\"dataB64\":\"%s\",\"fin\":true}", b2);
        preview_ws_on_data(&rel, f1, strlen(f1));
        preview_ws_on_data(&rel, f2, strlen(f2));
        free(b1); free(b2); free(f1); free(f2);

        for (int i = 0; i < 60 && g_pws_n < 2; i++) pws_pump(&rel, 25);
        assert(g_pws_n == 2);
        uint8_t *re = malloc(big_n + 64);
        size_t re_len = 0;
        for (int c = 0; c < g_pws_n; c++) {
            const char *cp; size_t cpl;
            assert(json_get_obj(g_pws_msgs[c], g_pws_lens[c], "payload", &cp, &cpl));
            int is_bin = 0, is_fin = -1;
            assert(json_get_bool(cp, cpl, "binary", &is_bin) && is_bin == 1);
            assert(json_get_bool(cp, cpl, "fin", &is_fin) && is_fin == (c == 1 ? 1 : 0));
            const char *cb; size_t cbl;
            assert(json_get_str(cp, cpl, "dataB64", &cb, &cbl));
            re_len += b64_decode(cb, cbl, re + re_len, big_n + 64 - re_len);
        }
        assert(re_len == big_n && memcmp(re, big, big_n) == 0);
        free(big); free(re);

        const char *cls = "{\"streamId\":\"ws2\",\"code\":1000}";
        preview_ws_on_close(&rel, cls, strlen(cls));
        pws_reset();
        preview_ws_close_all(&rel);
        close(wlfd);
    }
    printf("ok 8 preview_ws subprotocol + text + 40KB chunked binary round-trip\n");

    printf("all preview tests passed\n");
    return 0;
}

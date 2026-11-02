// See cdp_local.h.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cdp_local.h"
#include "json.h"
#include "noise.h"   // noise_random

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <ws2tcpip.h>
static int cl_close_fd(SOCKET s) { return closesocket(s); }
typedef int cl_ssize;
#  define cl_recv(fd, b, n) recv(fd, (char *)(b), (int)(n), 0)
#  define cl_send(fd, b, n) send(fd, (const char *)(b), (int)(n), 0)
static int cl_would_block(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
static void cl_shut_wr(SOCKET s) { shutdown(s, SD_SEND); }
#else
#  include <errno.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
static int cl_close_fd(int s) { return close(s); }
typedef ssize_t cl_ssize;
#  define cl_recv(fd, b, n) recv(fd, b, n, 0)
#  define cl_send(fd, b, n) send(fd, b, n, MSG_NOSIGNAL)
static int cl_would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static void cl_shut_wr(int s) { shutdown(s, SHUT_WR); }
#endif

// ── SHA-1 / HMAC (WS accept key, mutual auth) ──

#define ROL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
static void sha1_block(uint32_t h[5], const uint8_t *p) {
    uint32_t w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 80; i++) w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
        uint32_t t = ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

// Two-part input so HMAC needs no concatenation buffer.
static void sha1_2(const uint8_t *m1, size_t n1, const uint8_t *m2, size_t n2, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t blk[64]; size_t bl = 0;
    const uint8_t *parts[2] = {m1, m2}; size_t lens[2] = {n1, n2};
    for (int k = 0; k < 2; k++)
        for (size_t i = 0; i < lens[k]; i++) { blk[bl++] = parts[k][i]; if (bl == 64) { sha1_block(h, blk); bl = 0; } }
    uint64_t bits = (uint64_t)(n1 + n2) * 8;
    blk[bl++] = 0x80;
    if (bl > 56) { memset(blk + bl, 0, 64 - bl); sha1_block(h, blk); bl = 0; }
    memset(blk + bl, 0, 56 - bl);
    for (int i = 0; i < 8; i++) blk[63 - i] = (uint8_t)(bits >> (8 * i));
    sha1_block(h, blk);
    for (int i = 0; i < 20; i++) out[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
}

void cdpl_sha1(const uint8_t *m, size_t n, uint8_t out[20]) { sha1_2(m, n, NULL, 0, out); }

void cdpl_hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[20]) {
    uint8_t k[64] = {0}, pad[64], inner[20];
    if (klen > 64) cdpl_sha1(key, klen, k); else memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha1_2(pad, 64, msg, mlen, inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha1_2(pad, 64, inner, 20, out);
}

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[b[i] >> 4]; out[2*i+1] = d[b[i] & 15]; }
    out[2*n] = '\0';
}

// hex HMAC(secret, label + nonce) into out[41].
static void proof(const char *secret, const char *label, const char *nonce, char out[41]) {
    char msg[160]; uint8_t mac[20];
    int n = snprintf(msg, sizeof msg, "%s%s", label, nonce);
    cdpl_hmac_sha1((const uint8_t *)secret, strlen(secret), (const uint8_t *)msg, n > 0 ? (size_t)n : 0, mac);
    hex(mac, 20, out);
}

static int ct_eq(const char *a, const char *b, size_t n) {
    unsigned char r = 0;
    for (size_t i = 0; i < n; i++) r |= (unsigned char)(a[i] ^ b[i]);
    return r == 0;
}

static int safe_id(const char *s, size_t n, size_t max) {
    if (n == 0 || n > max) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ':')) return 0;
    }
    return 1;
}

// ── state ──

#define CDPL_MAX_RES 8
typedef struct {
    char id[129];          // resourceId ('' = free)
    char secret[129];
    char token_hash[41];
    int  ext;              // conns[] index of its authenticated extension, -1
} res_t;

enum { K_FREE = 0, K_EXT, K_CLI };
enum { S_AUTH = 1, S_LIVE, S_CLOSING };

typedef struct {
    ws_fd_t fd;
    int kind, state;
    int res;               // res_t index (ext: once authed; cli: its browser)
    char nonce[33];        // ext: the bnonce we sent
    char client_id[40];    // cli: "local:<hex>"
    int64_t deadline;      // S_AUTH: auth by; S_CLOSING: fd closed by
    uint8_t *rx; size_t rx_len, rx_cap;
    uint8_t *frag; size_t frag_len, frag_cap; int frag_op;   // fragmented message
    uint8_t *tx; size_t tx_len, tx_cap, tx_off;
    int shut;              // S_CLOSING: our write side is shut
} conn_t;

static res_t g_res[CDPL_MAX_RES];
static conn_t g_c[CDPL_MAX_CONNS];
static cdp_local_grant_fn g_grant;
static int g_inited;

static void init_once(void) {
    if (g_inited) return;
    g_inited = 1;
    for (int i = 0; i < CDPL_MAX_CONNS; i++) g_c[i].fd = WS_INVALID_FD;
    for (int i = 0; i < CDPL_MAX_RES; i++) g_res[i].ext = -1;
}

void cdp_local_init(cdp_local_grant_fn file_grant) { init_once(); g_grant = file_grant; }

// ── tx ──

static int tx_reserve(conn_t *c, size_t add) {
    if (c->tx_off && c->tx_off == c->tx_len) c->tx_off = c->tx_len = 0;
    if (c->tx_len + add > CDPL_TX_MAX) return -1;
    if (c->tx_len + add <= c->tx_cap) return 0;
    if (c->tx_off) { memmove(c->tx, c->tx + c->tx_off, c->tx_len - c->tx_off); c->tx_len -= c->tx_off; c->tx_off = 0; }
    if (c->tx_len + add <= c->tx_cap) return 0;
    size_t cap = c->tx_cap ? c->tx_cap : 16384;
    while (cap < c->tx_len + add) cap *= 2;
    uint8_t *n = realloc(c->tx, cap);
    if (!n) return -1;
    c->tx = n; c->tx_cap = cap;
    return 0;
}

static void conn_drop(int i);
static void conn_detach(int i);

static void tx_raw(conn_t *c, const void *p, size_t n) {
    if (tx_reserve(c, n) != 0) { conn_drop((int)(c - g_c)); return; }
    memcpy(c->tx + c->tx_len, p, n); c->tx_len += n;
}

// One unmasked server frame whose payload is a + b (b may be NULL).
static void tx_frame2(conn_t *c, uint8_t op, const void *a, size_t an, const void *b, size_t bn) {
    if (c->fd == WS_INVALID_FD || c->state == S_CLOSING) return;
    size_t n = an + bn;
    uint8_t h[10]; size_t hl;
    h[0] = (uint8_t)(0x80 | op);
    if (n < 126) { h[1] = (uint8_t)n; hl = 2; }
    else if (n < 65536) { h[1] = 126; h[2] = (uint8_t)(n >> 8); h[3] = (uint8_t)n; hl = 4; }
    else { h[1] = 127; for (int i = 0; i < 8; i++) h[2 + i] = (uint8_t)((uint64_t)n >> (56 - 8 * i)); hl = 10; }
    if (tx_reserve(c, hl + n) != 0) { conn_drop((int)(c - g_c)); return; }
    memcpy(c->tx + c->tx_len, h, hl); c->tx_len += hl;
    if (an) { memcpy(c->tx + c->tx_len, a, an); c->tx_len += an; }
    if (bn) { memcpy(c->tx + c->tx_len, b, bn); c->tx_len += bn; }
}

static void tx_text(conn_t *c, const char *s) { tx_frame2(c, WS_OP_TEXT, s, strlen(s), NULL, 0); }

static void flush(conn_t *c) {
    while (c->fd != WS_INVALID_FD && c->tx_off < c->tx_len) {
        cl_ssize w = cl_send(c->fd, c->tx + c->tx_off, c->tx_len - c->tx_off);
        if (w > 0) { c->tx_off += (size_t)w; continue; }
        if (w < 0 && cl_would_block()) return;
        conn_drop((int)(c - g_c));
        return;
    }
    // CLOSE is out: half-close and drain until the peer's EOF (or the deadline),
    // so a peer still sending never turns our close into an RST that eats it.
    if (c->fd != WS_INVALID_FD && c->state == S_CLOSING && c->tx_off == c->tx_len && !c->shut) {
        c->shut = 1;
        cl_shut_wr(c->fd);
    }
}

// Queue a CLOSE and stop taking input; the fd goes once it is flushed.
static void conn_close(int i, uint16_t code, const char *reason) {
    conn_t *c = &g_c[i];
    if (c->fd == WS_INVALID_FD || c->state == S_CLOSING) return;
    uint8_t p[2] = {(uint8_t)(code >> 8), (uint8_t)code};
    tx_frame2(c, WS_OP_CLOSE, p, 2, reason, strlen(reason));
    if (c->fd == WS_INVALID_FD) return;   // tx overflow dropped it
    c->state = S_CLOSING;
    conn_detach(i);
    c->deadline = ws_monotonic_ms() + CDPL_CLOSE_MS;
    flush(c);
}

// Closing side effects, once per conn (at CLOSE, not at fd close): an
// extension takes its clients with it, a client tells its extension.
static void conn_detach(int i) {
    conn_t *c = &g_c[i];
    if (c->kind == K_EXT && c->res >= 0 && g_res[c->res].ext == i) {
        g_res[c->res].ext = -1;
        for (int j = 0; j < CDPL_MAX_CONNS; j++)
            if (g_c[j].kind == K_CLI && g_c[j].res == c->res) { g_c[j].res = -1; conn_close(j, 4004, "resource disconnected"); }
    } else if (c->kind == K_CLI && c->res >= 0) {
        int e = g_res[c->res].ext;
        if (e >= 0) { char m[64]; snprintf(m, sizeof m, "close %s", c->client_id); tx_text(&g_c[e], m); }
    }
    c->res = -1;
}

static void conn_drop(int i) {
    conn_t *c = &g_c[i];
    if (c->fd == WS_INVALID_FD) return;
    ws_fd_t fd = c->fd;
    c->fd = WS_INVALID_FD;   // first: re-entrant drops (tx overflow inside detach) are no-ops
    cl_close_fd(fd);
    conn_detach(i);
    free(c->rx); free(c->frag); free(c->tx);
    memset(c, 0, sizeof *c);
    c->fd = WS_INVALID_FD;
    c->res = -1;
}

void cdp_local_close_all(void) {
    init_once();
    for (int i = 0; i < CDPL_MAX_CONNS; i++) conn_drop(i);
}

int cdp_local_count(int ext) {
    init_once();
    int n = 0;
    for (int i = 0; i < CDPL_MAX_CONNS; i++)
        if (g_c[i].fd != WS_INVALID_FD && g_c[i].state != S_CLOSING
            && (ext ? g_c[i].kind == K_EXT && g_c[i].state == S_LIVE : g_c[i].kind == K_CLI)) n++;
    return n;
}

// ── grants from the backend ──

static int res_find(const char *id) {
    for (int i = 0; i < CDPL_MAX_RES; i++) if (g_res[i].id[0] && strcmp(g_res[i].id, id) == 0) return i;
    return -1;
}

static void res_cut(int r, uint16_t code, const char *why) {
    if (g_res[r].ext >= 0) conn_close(g_res[r].ext, code, why);   // detach closes its clients
}

int cdp_local_grant(const char *resource_id, const char *secret, const char *token_hash) {
    init_once();
    size_t il = strlen(resource_id), sl = strlen(secret);
    if (!safe_id(resource_id, il, 128) || sl < 32 || sl > 128 || strlen(token_hash) != 40) return -1;
    int r = res_find(resource_id);
    if (r >= 0) {
        if (strcmp(g_res[r].secret, secret) != 0 || strcmp(g_res[r].token_hash, token_hash) != 0)
            res_cut(r, 4003, "cdp token rotated");
    } else {
        for (int i = 0; i < CDPL_MAX_RES && r < 0; i++) if (!g_res[i].id[0]) r = i;
        if (r < 0) { r = 0; res_cut(0, 4002, "replaced"); }   // full: evict the first slot
        g_res[r].ext = -1;
    }
    snprintf(g_res[r].id, sizeof g_res[r].id, "%s", resource_id);
    snprintf(g_res[r].secret, sizeof g_res[r].secret, "%s", secret);
    snprintf(g_res[r].token_hash, sizeof g_res[r].token_hash, "%s", token_hash);
    return 0;
}

// ── accept ──

static int res_for_token(const char *token) {
    uint8_t d[20]; char h[41];
    cdpl_sha1((const uint8_t *)token, strlen(token), d);
    hex(d, 20, h);
    for (int i = 0; i < CDPL_MAX_RES; i++)
        if (g_res[i].id[0] && g_res[i].ext >= 0 && ct_eq(g_res[i].token_hash, h, 40)) return i;
    return -1;
}

static void http_close(ws_fd_t fd, const char *status) {
    char out[160];
    int n = snprintf(out, sizeof out, "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
    (void)!cl_send(fd, out, (size_t)n);   // tiny; the socket buffer takes it whole
    cl_close_fd(fd);
}

static int slot(void) {
    for (int i = 0; i < CDPL_MAX_CONNS; i++) if (g_c[i].fd == WS_INVALID_FD) return i;
    return -1;
}

static void rand_hex(char *out, size_t bytes) {
    uint8_t b[32];
    noise_random(b, bytes);
    hex(b, bytes, out);
}

void cdp_local_accept(ws_fd_t fd, int ext, const char *ws_key, const char *token, const char *todo_id) {
    init_once();
    int r = ext ? -1 : (token && *token ? res_for_token(token) : -1);
    if (!ws_key) { http_close(fd, !ext && r >= 0 ? "200 OK" : "404 Not Found"); return; }
    if (!ext && r < 0) { http_close(fd, "404 Not Found"); return; }
    int i = slot();
    if (i < 0) { http_close(fd, "503 Service Unavailable"); return; }

    char key[128]; uint8_t d[20]; char acc[32];
    snprintf(key, sizeof key, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", ws_key);
    cdpl_sha1((const uint8_t *)key, strlen(key), d);
    b64_encode(d, 20, acc, sizeof acc);

    conn_t *c = &g_c[i];
    memset(c, 0, sizeof *c);
    c->fd = fd; c->res = -1;
    c->kind = ext ? K_EXT : K_CLI;
    char head[256];
    int hn = snprintf(head, sizeof head, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
    tx_raw(c, head, (size_t)hn);
    if (ext) {
        c->state = S_AUTH;
        c->deadline = ws_monotonic_ms() + CDPL_AUTH_MS;
        rand_hex(c->nonce, 16);
        char m[48]; snprintf(m, sizeof m, "hello %s", c->nonce);
        tx_text(c, m);
    } else {
        c->state = S_LIVE;
        c->res = r;
        char rnd[17]; rand_hex(rnd, 8);
        snprintf(c->client_id, sizeof c->client_id, "local:%s", rnd);
        char m[160];
        int tl = todo_id ? (int)strlen(todo_id) : 0;
        if (tl && !safe_id(todo_id, (size_t)tl, 64)) tl = 0;
        snprintf(m, sizeof m, "open %s%s%.*s", c->client_id, tl ? " " : "", tl, tl ? todo_id : "");
        tx_text(&g_c[g_res[r].ext], m);
    }
    flush(c);
}

// ── inbound ──

// `<verb> <a1> <a2> …\n<body>`: splits the head into up to 4 NUL-terminated words.
static int words(char *head, char **w, int max) {
    int n = 0;
    for (char *p = head; *p && n < max; ) {
        while (*p == ' ') p++;
        if (!*p) break;
        w[n++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
    }
    return n;
}

static void ext_message(int i, uint8_t *m, size_t n) {
    conn_t *c = &g_c[i];
    uint8_t *nl = memchr(m, '\n', n);
    size_t hl = nl ? (size_t)(nl - m) : n;
    if (hl > 512) { conn_close(i, 1008, "bad frame"); return; }
    char head[513]; memcpy(head, m, hl); head[hl] = '\0';
    const uint8_t *body = nl ? nl + 1 : m + n;
    size_t bl = (size_t)(m + n - body);
    char *w[4] = {0};
    int wn = words(head, w, 4);
    if (wn == 0) return;

    if (c->state == S_AUTH) {
        // auth <resourceId> <enonce> <proof>
        int r = wn == 4 && strcmp(w[0], "auth") == 0 ? res_find(w[1]) : -1;
        char want[41];
        if (r >= 0) proof(g_res[r].secret, "ext|", c->nonce, want);
        if (r < 0 || strlen(w[3]) != 40 || !ct_eq(want, w[3], 40) || !safe_id(w[2], strlen(w[2]), 64)) {
            conn_close(i, 4401, r < 0 ? "unknown resource" : "bad proof");
            return;
        }
        if (g_res[r].ext >= 0 && g_res[r].ext != i) conn_close(g_res[r].ext, 4002, "replaced");
        g_res[r].ext = i;
        c->res = r; c->state = S_LIVE;
        char ok[48], mine[41];
        proof(g_res[r].secret, "bridge|", w[2], mine);
        snprintf(ok, sizeof ok, "ok %s", mine);
        tx_text(c, ok);
        return;
    }
    if (strcmp(w[0], "cdp") == 0 && wn >= 2) {
        int all = strcmp(w[1], "*") == 0;
        for (int j = 0; j < CDPL_MAX_CONNS; j++) {
            conn_t *k = &g_c[j];
            if (k->kind != K_CLI || k->res != c->res || k->state != S_LIVE) continue;
            if (!all && strcmp(k->client_id, w[1]) != 0) continue;
            tx_frame2(k, WS_OP_TEXT, body, bl, NULL, 0);
            flush(k);
            if (!all) break;
        }
    } else if (strcmp(w[0], "close") == 0 && wn >= 2) {
        for (int j = 0; j < CDPL_MAX_CONNS; j++)
            if (g_c[j].kind == K_CLI && g_c[j].res == c->res && strcmp(g_c[j].client_id, w[1]) == 0) {
                g_c[j].res = -1;   // the extension already forgot it: no `close` echo
                conn_close(j, 4403, "refused by the browser extension");
            }
    } else if (strcmp(w[0], "grant") == 0 && wn >= 2 && safe_id(w[1], strlen(w[1]), 64)) {
        char path[4096], out[512], err[512], rh[96];
        int ok = 0;
        if (bl == 0 || bl >= sizeof path) snprintf(err, sizeof err, "file_grant: bad path");
        else if (!g_grant) snprintf(err, sizeof err, "file_grant: unavailable");
        else { memcpy(path, body, bl); path[bl] = '\0'; ok = g_grant(path, out, sizeof out, err, sizeof err) == 0; }
        int rl = snprintf(rh, sizeof rh, "grant %s\n%s", w[1], ok ? "" : "!");
        tx_frame2(c, WS_OP_TEXT, rh, (size_t)rl, ok ? out : err, strlen(ok ? out : err));
    } else if (strcmp(w[0], "ping") == 0) {
        tx_text(c, "pong");
    }
}

static void cli_message(int i, const uint8_t *m, size_t n) {
    conn_t *c = &g_c[i];
    if (c->res < 0 || g_res[c->res].ext < 0) return;
    conn_t *e = &g_c[g_res[c->res].ext];
    char h[64];
    int hl = snprintf(h, sizeof h, "cdp %s\n", c->client_id);
    tx_frame2(e, WS_OP_TEXT, h, (size_t)hl, m, n);
    if (e->fd != WS_INVALID_FD) flush(e);
}

static void on_message(int i, int op, uint8_t *m, size_t n) {
    if (op != WS_OP_TEXT) return;   // CDP is text; binary is not ours
    if (g_c[i].kind == K_EXT) ext_message(i, m, n); else cli_message(i, m, n);
}

// Parse every complete frame in rx. Returns -1 when the conn was closed.
static int parse(int i) {
    conn_t *c = &g_c[i];
    size_t off = 0;
    while (c->fd != WS_INVALID_FD && c->state != S_CLOSING) {
        uint8_t *p = c->rx + off; size_t avail = c->rx_len - off;
        if (avail < 2) break;
        int fin = p[0] & 0x80, op = p[0] & 0x0f, masked = p[1] & 0x80;
        uint64_t len = p[1] & 0x7f; size_t hl = 2;
        if (len == 126) { if (avail < 4) break; len = (uint64_t)p[2] << 8 | p[3]; hl = 4; }
        else if (len == 127) { if (avail < 10) break; len = 0; for (int k = 0; k < 8; k++) len = len << 8 | p[2 + k]; hl = 10; }
        if (!masked) { conn_close(i, 1002, "unmasked client frame"); return -1; }
        if (len > CDPL_MAX_MSG) { conn_close(i, 1009, "message too big"); return -1; }
        if (avail < hl + 4 + len) break;
        uint8_t *mask = p + hl, *pl = p + hl + 4;
        for (uint64_t k = 0; k < len; k++) pl[k] ^= mask[k & 3];
        off += hl + 4 + (size_t)len;
        if (op == WS_OP_CLOSE) { conn_close(i, 1000, ""); return -1; }
        if (op == WS_OP_PING) { tx_frame2(c, WS_OP_PONG, pl, (size_t)len, NULL, 0); continue; }
        if (op == WS_OP_PONG) continue;
        if (op == WS_OP_CONT || !fin || c->frag_len || c->frag_op) {
            if (op != WS_OP_CONT) { if (c->frag_op) { conn_close(i, 1002, "bad fragment"); return -1; } c->frag_op = op; }
            else if (!c->frag_op) { conn_close(i, 1002, "bad fragment"); return -1; }
            if (c->frag_len + len > CDPL_MAX_MSG) { conn_close(i, 1009, "message too big"); return -1; }
            if (c->frag_len + len > c->frag_cap) {
                size_t cap = c->frag_cap ? c->frag_cap : 65536;
                while (cap < c->frag_len + len) cap *= 2;
                uint8_t *nb = realloc(c->frag, cap);
                if (!nb) { conn_drop(i); return -1; }
                c->frag = nb; c->frag_cap = cap;
            }
            memcpy(c->frag + c->frag_len, pl, (size_t)len); c->frag_len += (size_t)len;
            if (fin) { int fop = c->frag_op; c->frag_op = 0; size_t fl = c->frag_len; c->frag_len = 0; on_message(i, fop, c->frag, fl); }
            continue;
        }
        on_message(i, op, pl, (size_t)len);
    }
    if (c->fd == WS_INVALID_FD) return -1;
    if (off) { memmove(c->rx, c->rx + off, c->rx_len - off); c->rx_len -= off; }
    return 0;
}

static void on_readable(int i) {
    conn_t *c = &g_c[i];
    for (int rounds = 0; rounds < 16 && c->fd != WS_INVALID_FD; rounds++) {
        if (c->rx_cap - c->rx_len < 65536) {
            size_t cap = c->rx_cap ? c->rx_cap * 2 : 131072;
            if (cap > CDPL_MAX_MSG + 65536) cap = CDPL_MAX_MSG + 65536;
            if (cap <= c->rx_len) { conn_close(i, 1009, "message too big"); return; }
            uint8_t *nb = realloc(c->rx, cap);
            if (!nb) { conn_drop(i); return; }
            c->rx = nb; c->rx_cap = cap;
        }
        cl_ssize r = cl_recv(c->fd, c->rx + c->rx_len, c->rx_cap - c->rx_len);
        if (r == 0) { conn_drop(i); return; }
        if (r < 0) { if (!cl_would_block()) conn_drop(i); return; }
        c->rx_len += (size_t)r;
        if (c->state == S_CLOSING) { c->rx_len = 0; continue; }   // drain until the peer's EOF
        if (parse(i) < 0) return;
    }
}

// ── poll integration ──

void cdp_local_fill_pfds(struct pollfd *pfds, size_t *n, size_t cap) {
    init_once();
    for (int i = 0; i < CDPL_MAX_CONNS && *n < cap; i++) {
        conn_t *c = &g_c[i];
        if (c->fd == WS_INVALID_FD) continue;
        pfds[*n].fd = c->fd;
        pfds[*n].events = (short)(POLLIN | (c->tx_off < c->tx_len ? POLLOUT : 0));
        pfds[*n].revents = 0;
        (*n)++;
    }
}

void cdp_local_service(const struct pollfd *pfds, size_t first, size_t n) {
    for (size_t k = first; k < first + n; k++) {
        if (!pfds[k].revents) continue;
        for (int i = 0; i < CDPL_MAX_CONNS; i++) {
            if (g_c[i].fd != pfds[k].fd) continue;
            if (pfds[k].revents & POLLOUT) flush(&g_c[i]);
            if (g_c[i].fd != WS_INVALID_FD && (pfds[k].revents & (POLLIN | POLLHUP | POLLERR))) on_readable(i);
            if (g_c[i].fd != WS_INVALID_FD && (pfds[k].revents & POLLNVAL)) conn_drop(i);
            break;
        }
    }
    // Messages routed to other conns were queued; push them now rather than next tick.
    for (int i = 0; i < CDPL_MAX_CONNS; i++) if (g_c[i].fd != WS_INVALID_FD && g_c[i].tx_off < g_c[i].tx_len) flush(&g_c[i]);
}

void cdp_local_tick(void) {
    int64_t now = ws_monotonic_ms();
    for (int i = 0; i < CDPL_MAX_CONNS; i++) {
        conn_t *c = &g_c[i];
        if (c->fd == WS_INVALID_FD || !c->deadline || now < c->deadline) continue;
        if (c->state == S_CLOSING) conn_drop(i);
        else if (c->state == S_AUTH) conn_close(i, 4408, "auth timeout");
    }
}

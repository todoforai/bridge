// live_preview relay, bridge side. See preview.h for the wire contract.
//
// The fetch is a minimal blocking HTTP/1.0 client: HTTP/1.0 + explicit
// `Connection: close` means the server neither chunks the body nor keeps the
// socket open, so "read to EOF" is the framing — no chunked-decoding needed.
// We also never send Accept-Encoding, so compliant servers reply identity;
// if one compresses anyway, Content-Encoding passes through and the browser
// decodes. The whole fetch is bounded by PREVIEW_FETCH_DEADLINE_MS, kept
// under both the backend's 30s relay timeout and the WS liveness window
// (the bridge loop blocks during a fetch — single-threaded by design).

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "preview.h"
#include "json.h"
#include "ws.h"   // ws_tcp_connect, ws_monotonic_ms, ws_fd_t

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <ws2tcpip.h>
#  define poll WSAPoll
static int pv_close_fd(SOCKET s) { return closesocket(s); }
static int pv_errno(void)        { return WSAGetLastError(); }
#  define PV_EINTR  WSAEINTR
#  define PV_EAGAIN WSAEWOULDBLOCK
#  define PV_INVALID INVALID_SOCKET
#else
#  include <errno.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
static int pv_close_fd(int s) { return close(s); }
static int pv_errno(void)     { return errno; }
#  define PV_EINTR  EINTR
#  define PV_EAGAIN EAGAIN
#  define PV_INVALID (-1)
#endif

#define PREVIEW_FETCH_DEADLINE_MS 20000   // < backend 30s relay, < WS_PING_IDLE_MS+slack
#define PREVIEW_CONNECT_MS        5000
#define PREVIEW_PROBE_MS          3000
#define MAX_RESPONSE_BODY         (3u * 1024 * 1024 + 512 * 1024)  // 3.5MB, mirrors edge
#define MAX_RESPONSE_HEADERS      (64 * 1024)
// Hard cap for one emitted chunk frame: must fit noise_ws_send's plaintext
// budget (64KB inbound MAX_MSG on the peer, minus AEAD tag slack). The seq-0
// frame carries all response headers JSON-escaped, so it's the one that can
// legitimately hit this — overflow becomes a terminal error, not a silently
// dropped oversized frame.
#define MAX_CHUNK_FRAME           (60 * 1024)
#define MAX_ALLOWED_PORTS         32
#define PORT_TTL_MS               (24LL * 60 * 60 * 1000)
#define BODY_CHUNK_RAW            (32 * 1024)  // ~43KB base64 + envelope < 64KB Noise cap

// ── Port allowlist ──────────────────────────────────────────────────────────

static struct { int port; int64_t expiry_ms; } g_allowed[MAX_ALLOWED_PORTS];

void bridge_preview_allow_port(int port) {
    int64_t now = ws_monotonic_ms();
    int slot = -1;
    for (int i = 0; i < MAX_ALLOWED_PORTS; i++) {
        if (g_allowed[i].port == port) { slot = i; break; }         // refresh
        if (slot < 0 && (g_allowed[i].port == 0 || g_allowed[i].expiry_ms <= now))
            slot = i;                                                // free/expired
    }
    if (slot < 0) slot = 0;  // full: clobber the first entry (32 live ports is already absurd)
    g_allowed[slot].port = port;
    g_allowed[slot].expiry_ms = now + PORT_TTL_MS;
}

static int port_allowed(int port) {
    int64_t now = ws_monotonic_ms();
    for (int i = 0; i < MAX_ALLOWED_PORTS; i++)
        if (g_allowed[i].port == port && g_allowed[i].expiry_ms > now) return 1;
    return 0;
}

int bridge_preview_probe_port(int port, char *err, size_t err_cap) {
    ws_fd_t fd = ws_tcp_connect("127.0.0.1", (uint16_t)port, PREVIEW_PROBE_MS, err, err_cap);
    if (fd == PV_INVALID) return -1;
    pv_close_fd(fd);
    return 0;
}

// ── Small helpers ───────────────────────────────────────────────────────────

// Reject bytes that would let attacker-controlled fields break HTTP framing
// (CR/LF/CTL injection). ASCII printable only.
static int clean_token(const char *s, size_t n) {
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c >= 0x7f) return 0;
    }
    return 1;
}

static int clean_value(const char *s, size_t n) {  // header values: allow space+tab
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c < 0x20 && c != '\t') || c == 0x7f) return 0;
    }
    return 1;
}

static int strieq_n(const char *a, size_t alen, const char *b) {
    size_t blen = strlen(b);
    if (alen != blen) return 0;
    for (size_t i = 0; i < alen; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
    return 1;
}

// Hop-by-hop / relay-managed request headers we never forward.
static int skip_request_header(const char *k, size_t klen) {
    static const char *drop[] = {
        "connection", "keep-alive", "transfer-encoding", "upgrade", "te",
        "trailer", "content-length", "host", "accept-encoding",
        "proxy-authorization", "proxy-connection", NULL,
    };
    for (int i = 0; drop[i]; i++)
        if (strieq_n(k, klen, drop[i])) return 1;
    return 0;
}

// Response headers that must not be echoed back through the relay.
// content-encoding stays: we don't decompress (no Accept-Encoding is sent, but
// a server may compress unconditionally) — the backend forwards it for bridge
// responses so the browser decodes.
static int skip_response_header(const char *k, size_t klen) {
    return strieq_n(k, klen, "connection")        ||
           strieq_n(k, klen, "keep-alive")        ||
           strieq_n(k, klen, "transfer-encoding") ||
           strieq_n(k, klen, "content-length")    ||
           strieq_n(k, klen, "set-cookie");
}

// ── Blocking-with-deadline socket I/O ───────────────────────────────────────

static int send_all(ws_fd_t fd, const char *p, size_t len, int64_t deadline) {
    size_t off = 0;
    while (off < len) {
        int64_t left = deadline - ws_monotonic_ms();
        if (left <= 0) return -1;
#ifdef _WIN32
        int n = send(fd, p + off, (int)(len - off), 0);
#else
        long n = send(fd, p + off, len - off, 0);
#endif
        if (n > 0) { off += (size_t)n; continue; }
        int e = pv_errno();
        if (e == PV_EINTR) continue;
        if (e != PV_EAGAIN) return -1;
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, (int)(left > 1000 ? 1000 : left)) < 0 && pv_errno() != PV_EINTR) return -1;
    }
    return 0;
}

// Read until EOF / deadline / cap. Returns bytes read, -1 on transport error,
// -2 on overflow. `stop_at` > 0 ⇒ stop early once that many bytes are in
// (headers + content-length known).
static long recv_all(ws_fd_t fd, char **buf, size_t *cap, int64_t deadline,
                     size_t max_len, size_t (*stop_at)(const char *, size_t)) {
    size_t len = 0;
    for (;;) {
        int64_t left = deadline - ws_monotonic_ms();
        if (left <= 0) return -1;
        if (len + 8192 > *cap) {
            size_t ncap = *cap * 2;
            if (ncap > max_len + 8192) ncap = max_len + 8192;
            if (len + 8192 > ncap) return -2;
            char *nb = realloc(*buf, ncap);
            if (!nb) return -1;
            *buf = nb; *cap = ncap;
        }
#ifdef _WIN32
        int n = recv(fd, *buf + len, (int)(*cap - len), 0);
#else
        long n = recv(fd, *buf + len, *cap - len, 0);
#endif
        if (n > 0) {
            len += (size_t)n;
            if (len > max_len) return -2;
            size_t want = stop_at(*buf, len);
            if (want > 0 && len >= want) return (long)len;
            continue;
        }
        if (n == 0) return (long)len;  // EOF — HTTP/1.0 framing
        int e = pv_errno();
        if (e == PV_EINTR) continue;
        if (e != PV_EAGAIN) return -1;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, (int)(left > 1000 ? 1000 : left)) < 0 && pv_errno() != PV_EINTR) return -1;
    }
}

// stop_at callback: headers + Content-Length when both are known, else 0.
static size_t response_expected_len(const char *buf, size_t len) {
    size_t hdr_len = 0;
    for (size_t i = 3; i < len; i++)
        if (memcmp(buf + i - 3, "\r\n\r\n", 4) == 0) { hdr_len = i + 1; break; }
    if (!hdr_len) return 0;
    // Scan header lines for Content-Length (case-insensitive).
    const char *p = memchr(buf, '\n', hdr_len);  // skip status line
    while (p && p < buf + hdr_len - 2) {
        const char *k = p + 1;
        const char *eol = memchr(k, '\n', hdr_len - (size_t)(k - buf));
        if (!eol) break;
        const char *colon = memchr(k, ':', (size_t)(eol - k));
        if (colon && strieq_n(k, (size_t)(colon - k), "content-length"))
            return hdr_len + (size_t)strtoul(colon + 1, NULL, 10);
        p = eol;
    }
    return 0;
}

// ── Chunk emission ──────────────────────────────────────────────────────────

static int jf_str(char *b, size_t cap, size_t *u, const char *k, const char *v, long vlen, int comma) {
    if (comma && json_emit_raw(b, cap, u, ",", 1) < 0) return -1;
    return json_emit_str(b, cap, u, k, -1) < 0 || json_emit_raw(b, cap, u, ":", 1) < 0 ||
           json_emit_str(b, cap, u, v, vlen) < 0 ? -1 : 0;
}

static int jf_raw(char *b, size_t cap, size_t *u, const char *k, const char *v, int comma) {
    if (comma && json_emit_raw(b, cap, u, ",", 1) < 0) return -1;
    return json_emit_str(b, cap, u, k, -1) < 0 || json_emit_raw(b, cap, u, ":", 1) < 0 ||
           json_emit_raw(b, cap, u, v, strlen(v)) < 0 ? -1 : 0;
}

// key/value pair where both are length-delimited byte spans.
static int jf_kv(char *b, size_t cap, size_t *u,
                 const char *k, size_t klen, const char *v, size_t vlen, int comma) {
    if (comma && json_emit_raw(b, cap, u, ",", 1) < 0) return -1;
    return json_emit_str(b, cap, u, k, (long)klen) < 0 || json_emit_raw(b, cap, u, ":", 1) < 0 ||
           json_emit_str(b, cap, u, v, (long)vlen) < 0 ? -1 : 0;
}

// Open a chunk frame: {"type":"preview:http_response_chunk","payload":{"requestId":…,"seq":N
static int chunk_open(char *b, size_t cap, size_t *u,
                      const char *rid, size_t rid_len, int seq) {
    char seq_s[16]; snprintf(seq_s, sizeof seq_s, "%d", seq);
    return json_emit_raw(b, cap, u, "{", 1) < 0 ||
           jf_str(b, cap, u, "type", "preview:http_response_chunk", -1, 0) < 0 ||
           json_emit_raw(b, cap, u, ",\"payload\":{", 12) < 0 ||
           jf_str(b, cap, u, "requestId", rid, (long)rid_len, 0) < 0 ||
           jf_raw(b, cap, u, "seq", seq_s, 1) < 0 ? -1 : 0;
}

static void send_error_chunk(preview_emit_fn emit, void *ctx,
                             const char *rid, size_t rid_len, int seq,
                             const char *message) {
    char b[1024]; size_t u = 0;
    if (chunk_open(b, sizeof b, &u, rid, rid_len, seq) < 0 ||
        jf_raw(b, sizeof b, &u, "done", "true", 1) < 0 ||
        jf_str(b, sizeof b, &u, "error", message, -1, 1) < 0 ||
        json_emit_raw(b, sizeof b, &u, "}}", 2) < 0) return;
    emit(ctx, b, u);
    fprintf(stderr, "preview error: %s\n", message);
}

// ── Request handling ────────────────────────────────────────────────────────

// Build the outbound HTTP request into a malloc'd buffer. Returns len, -1 OOM,
// -2 on invalid header content.
static long build_http_request(const char *method, size_t method_len,
                               const char *path, size_t path_len, int port,
                               const char *headers, size_t headers_len,
                               const uint8_t *body, size_t body_len,
                               char **out) {
    size_t cap = method_len + path_len + headers_len * 2 + body_len + 512;
    char *b = malloc(cap);
    if (!b) return -1;
    size_t u = (size_t)snprintf(b, cap, "%.*s %.*s HTTP/1.0\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n",
                                (int)method_len, method, (int)path_len, path, port);

    if (headers && headers_len) {
        size_t pos = 0;
        const char *k; size_t klen; const char *v; size_t vlen; json_type_t vt;
        char kbuf[256], vbuf[8192];
        while (json_obj_iter(headers, headers_len, &pos, &k, &klen, &v, &vlen, &vt)) {
            if (vt != JT_STR) continue;
            long kn = json_unescape_span(k, klen, kbuf, sizeof kbuf);
            long vn = json_unescape_span(v, vlen, vbuf, sizeof vbuf);
            if (kn <= 0 || vn < 0) continue;               // oversized/malformed: drop
            if (skip_request_header(kbuf, (size_t)kn)) continue;
            if (!clean_token(kbuf, (size_t)kn) || !clean_value(vbuf, (size_t)vn)) { free(b); return -2; }
            if (u + (size_t)kn + (size_t)vn + 8 > cap) { free(b); return -2; }
            u += (size_t)snprintf(b + u, cap - u, "%.*s: %.*s\r\n", (int)kn, kbuf, (int)vn, vbuf);
        }
    }
    if (body_len)
        u += (size_t)snprintf(b + u, cap - u, "Content-Length: %zu\r\n", body_len);
    u += (size_t)snprintf(b + u, cap - u, "\r\n");
    if (body_len) { memcpy(b + u, body, body_len); u += body_len; }
    *out = b;
    return (long)u;
}

void bridge_preview_handle_request(const char *payload, size_t payload_len,
                                   preview_emit_fn emit, void *ctx) {
    const char *rid = NULL; size_t rid_len = 0;
    if (!json_get_str(payload, payload_len, "requestId", &rid, &rid_len) ||
        rid_len == 0 || rid_len > 64 || !clean_token(rid, rid_len)) {
        fprintf(stderr, "preview: request without usable requestId — dropped\n");
        return;
    }
    #define FAIL(msg) do { send_error_chunk(emit, ctx, rid, rid_len, 0, (msg)); goto cleanup; } while (0)

    char *resp = NULL, *reqbuf = NULL;
    uint8_t *body = NULL;
    char *frame = NULL;
    ws_fd_t fd = PV_INVALID;

    long port = 0;
    if (!json_get_long(payload, payload_len, "port", &port) || port < 1 || port > 65535)
        FAIL("preview: invalid port");
    const char *method = NULL; size_t method_len = 0;
    if (!json_get_str(payload, payload_len, "method", &method, &method_len) ||
        method_len == 0 || method_len > 16 || !clean_token(method, method_len))
        FAIL("preview: invalid method");
    const char *path = NULL; size_t path_len = 0;
    if (!json_get_str(payload, payload_len, "path", &path, &path_len) ||
        path_len == 0 || path[0] != '/' || path_len > 8192 || !clean_token(path, path_len))
        FAIL("preview: invalid path");
    const char *headers = NULL; size_t headers_len = 0;
    json_get_obj(payload, payload_len, "headers", &headers, &headers_len);

    if (!port_allowed((int)port)) {
        char msg[96];
        snprintf(msg, sizeof msg, "Port %ld is not registered for preview on this device", port);
        FAIL(msg);
    }

    size_t body_len = 0;
    {
        const char *b64 = NULL; size_t b64_len = 0;
        if (json_get_str(payload, payload_len, "bodyB64", &b64, &b64_len) && b64_len > 0) {
            body = malloc(b64_len / 4 * 3 + 4);
            if (!body) FAIL("preview: out of memory");
            body_len = b64_decode(b64, b64_len, body, b64_len / 4 * 3 + 4);
            if (body_len == 0) FAIL("preview: invalid request bodyB64");
        }
    }

    int64_t deadline = ws_monotonic_ms() + PREVIEW_FETCH_DEADLINE_MS;

    char cerr[160];
    fd = ws_tcp_connect("127.0.0.1", (uint16_t)port, PREVIEW_CONNECT_MS, cerr, sizeof cerr);
    if (fd == PV_INVALID) {
        char msg[224];
        snprintf(msg, sizeof msg, "Nothing is listening on 127.0.0.1:%ld", port);
        FAIL(msg);
    }

    long req_len = build_http_request(method, method_len, path, path_len, (int)port,
                                      headers, headers_len, body, body_len, &reqbuf);
    if (req_len == -1) FAIL("preview: out of memory");
    if (req_len < 0)  FAIL("preview: malformed request headers");
    if (send_all(fd, reqbuf, (size_t)req_len, deadline) != 0)
        FAIL("preview: failed to send request to local server");

    size_t cap = 64 * 1024;
    resp = malloc(cap);
    if (!resp) FAIL("preview: out of memory");
    long resp_len = recv_all(fd, &resp, &cap, deadline,
                             MAX_RESPONSE_BODY + MAX_RESPONSE_HEADERS, response_expected_len);
    if (resp_len == -2) FAIL("Response too large for preview relay");
    if (resp_len < 0)   FAIL("preview: local server read failed or timed out");
    pv_close_fd(fd); fd = PV_INVALID;

    // ── Parse status line + headers ──
    char *hdr_end = NULL;
    for (long i = 3; i < resp_len; i++)
        if (memcmp(resp + i - 3, "\r\n\r\n", 4) == 0) { hdr_end = resp + i + 1; break; }
    if (!hdr_end) FAIL("preview: malformed response from local server (no header terminator)");
    size_t hdr_len = (size_t)(hdr_end - resp);
    const uint8_t *rbody = (const uint8_t *)resp + hdr_len;
    size_t rbody_len = (size_t)resp_len - hdr_len;
    if (rbody_len > MAX_RESPONSE_BODY) FAIL("Response too large for preview relay");

    int status = 0;
    {
        // Bounded status-line parse: resp is length-delimited, not
        // NUL-terminated, so never hand it to sscanf/str* directly.
        const char *eol = memchr(resp, '\r', hdr_len);
        char line[64] = {0};
        if (!eol || (size_t)(eol - resp) >= sizeof line) FAIL("preview: malformed status line from local server");
        memcpy(line, resp, (size_t)(eol - resp));
        if (sscanf(line, "HTTP/%*d.%*d %d", &status) != 1 || status < 100 || status > 599)
            FAIL("preview: malformed status line from local server");
    }

    // ── seq 0: status + headers + setCookie ──
    {
        size_t fcap = hdr_len * 2 + 1024;   // JSON-escape can expand
        if (fcap > MAX_CHUNK_FRAME) fcap = MAX_CHUNK_FRAME;  // overflow ⇒ terminal error below
        frame = malloc(fcap);
        if (!frame) FAIL("preview: out of memory");
        size_t u = 0;
        char st[16]; snprintf(st, sizeof st, "%d", status);
        if (chunk_open(frame, fcap, &u, rid, rid_len, 0) < 0 ||
            jf_raw(frame, fcap, &u, "status", st, 1) < 0 ||
            json_emit_raw(frame, fcap, &u, ",\"headers\":{", 12) < 0)
            FAIL("preview: response frame overflow");

        #define FRAME_OVF(expr) do { if (expr) FAIL("preview: response frame overflow"); } while (0)
        int first = 1, cookie_count = 0;
        // Two passes over the header lines: pass 0 fills "headers", pass 1
        // appends the (optional) "setCookie" array after "headers" closes.
        for (int pass = 0; pass < 2; pass++) {
            if (pass == 1) FRAME_OVF(json_emit_raw(frame, fcap, &u, "}", 1) < 0);
            const char *line = memchr(resp, '\n', hdr_len);  // skip status line
            while (line && line < resp + hdr_len - 2) {
                line++;
                const char *eol = memchr(line, '\n', hdr_len - (size_t)(line - resp));
                if (!eol) break;
                size_t ll = (size_t)(eol - line);
                if (ll && line[ll - 1] == '\r') ll--;
                const char *colon = memchr(line, ':', ll);
                if (colon) {
                    size_t klen = (size_t)(colon - line);
                    const char *v = colon + 1; size_t vlen = ll - klen - 1;
                    while (vlen && (*v == ' ' || *v == '\t')) { v++; vlen--; }
                    int is_cookie = strieq_n(line, klen, "set-cookie");
                    if (pass == 0 && !is_cookie && !skip_response_header(line, klen)) {
                        FRAME_OVF(jf_kv(frame, fcap, &u, line, klen, v, vlen, !first) < 0);
                        first = 0;
                    } else if (pass == 1 && is_cookie) {
                        FRAME_OVF(json_emit_raw(frame, fcap, &u,
                                                cookie_count ? "," : ",\"setCookie\":[",
                                                cookie_count ? 1 : 14) < 0);
                        FRAME_OVF(json_emit_str(frame, fcap, &u, v, (long)vlen) < 0);
                        cookie_count++;
                    }
                }
                line = eol;
            }
        }
        if (cookie_count) FRAME_OVF(json_emit_raw(frame, fcap, &u, "]", 1) < 0);
        #undef FRAME_OVF
        if (jf_raw(frame, fcap, &u, "done", rbody_len == 0 ? "true" : "false", 1) < 0 ||
            json_emit_raw(frame, fcap, &u, "}}", 2) < 0) FAIL("preview: response frame overflow");
        if (emit(ctx, frame, u) != 0) goto cleanup;
        free(frame); frame = NULL;
    }

    // ── seq 1..N: body chunks ──
    if (rbody_len) {
        size_t fcap = BODY_CHUNK_RAW * 2 + 512;
        frame = malloc(fcap);
        if (!frame) FAIL("preview: out of memory");
        int seq = 1;
        for (size_t off = 0; off < rbody_len; seq++) {
            size_t n = rbody_len - off > BODY_CHUNK_RAW ? BODY_CHUNK_RAW : rbody_len - off;
            int last = off + n >= rbody_len;
            size_t u = 0;
            if (chunk_open(frame, fcap, &u, rid, rid_len, seq) < 0 ||
                json_emit_raw(frame, fcap, &u, ",\"bodyB64\":\"", 12) < 0)
                FAIL("preview: chunk frame overflow");
            size_t bn = b64_encode(rbody + off, n, frame + u, fcap - u);
            if (bn == 0) FAIL("preview: chunk frame overflow");
            u += bn;
            if (json_emit_raw(frame, fcap, &u, "\"", 1) < 0 ||
                jf_raw(frame, fcap, &u, "done", last ? "true" : "false", 1) < 0 ||
                json_emit_raw(frame, fcap, &u, "}}", 2) < 0)
                FAIL("preview: chunk frame overflow");
            if (emit(ctx, frame, u) != 0) goto cleanup;
            off += n;
        }
    }

cleanup:
    if (fd != PV_INVALID) pv_close_fd(fd);
    free(resp); free(reqbuf); free(body); free(frame);
    #undef FAIL
}

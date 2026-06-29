#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "ws.h"
#include "json.h"      // b64_encode
#include "noise.h"     // noise_random for nonce + masking key

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef int socklen_t;
#  define poll WSAPoll
#  define ws_eintr   WSAEINTR
#  define ws_eagain  WSAEWOULDBLOCK
#  define ws_einprog WSAEWOULDBLOCK
#  define WS_INVALID INVALID_SOCKET
   static int ws_errno(void)        { return WSAGetLastError(); }
   static int ws_close_fd(SOCKET s) { return closesocket(s); }
   static int ws_set_nb(SOCKET s)   { u_long m = 1; return ioctlsocket(s, FIONBIO, &m); }
#else
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  define ws_eintr   EINTR
#  define ws_eagain  EAGAIN
#  define ws_einprog EINPROGRESS
#  define WS_INVALID (-1)
   static int ws_errno(void)        { return errno; }
   static int ws_close_fd(int s)    { return close(s); }
   static int ws_set_nb(int s)      {
       int f = fcntl(s, F_GETFL, 0);
       return f < 0 ? -1 : fcntl(s, F_SETFL, f | O_NONBLOCK);
   }
#endif

// Monotonic clock in ms for the liveness watchdog. We deliberately pick a clock
// that DOES advance while the machine is suspended (CLOCK_BOOTTIME on Linux,
// GetTickCount64 on Windows — both count sleep time). That way, when a laptop
// resumes from hibernation onto a now-dead half-open socket, last_recv_ms is
// already far in the past and the watchdog trips on the very next tick instead
// of waiting out the full idle window in awake-time. Falls back to
// CLOCK_MONOTONIC where BOOTTIME is unavailable (e.g. macOS), which still
// detects the dead socket, just within the idle window of awake-time after wake.
int64_t ws_monotonic_ms(void) {
#ifdef _WIN32
    return (int64_t)GetTickCount64();  // includes suspend time
#else
    struct timespec ts;
#  if defined(CLOCK_BOOTTIME)
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0)
        clock_gettime(CLOCK_MONOTONIC, &ts);
#  else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#  endif
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static void ws_set_err(ws_t *ws, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(ws->err, sizeof(ws->err), fmt, ap);
    va_end(ap);
}

// ── TCP connect with deadline ───────────────────────────────────────────────

static ws_fd_t tcp_connect(const char *host, uint16_t port, int timeout_ms,
                           char *err, size_t err_cap) {
#ifdef _WIN32
    static int wsa_inited = 0;
    if (!wsa_inited) {
        WSADATA wd;
        if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
            snprintf(err, err_cap, "WSAStartup failed");
            return WS_INVALID;
        }
        wsa_inited = 1;
    }
#endif
    char port_s[8]; snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host, port_s, &hints, &res);
    if (gai != 0) {
        snprintf(err, err_cap, "DNS lookup failed for %s: %s", host, gai_strerror(gai));
        return WS_INVALID;
    }

    ws_fd_t fd = WS_INVALID;
    int last_err = 0;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == WS_INVALID) { last_err = ws_errno(); continue; }

        // Non-blocking connect with poll()-based timeout.
        if (ws_set_nb(fd) != 0) { last_err = ws_errno(); ws_close_fd(fd); fd = WS_INVALID; continue; }
        int rc = connect(fd, rp->ai_addr, (socklen_t)rp->ai_addrlen);
        if (rc == 0) break;  // immediate
        int e = ws_errno();
        if (e != ws_einprog
#ifndef _WIN32
            && e != EINPROGRESS
#endif
        ) { last_err = e; ws_close_fd(fd); fd = WS_INVALID; continue; }

        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) { last_err = pr == 0 ? 0 : ws_errno(); ws_close_fd(fd); fd = WS_INVALID; continue; }
        int so_err = 0; socklen_t sl = sizeof(so_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&so_err, &sl) != 0 || so_err != 0) {
            last_err = so_err ? so_err : ws_errno();
            ws_close_fd(fd); fd = WS_INVALID; continue;
        }
        break;  // connected
    }
    freeaddrinfo(res);
    if (fd == WS_INVALID) {
        if (last_err == 0)
            snprintf(err, err_cap, "no response from %s:%u (timed out)", host, port);
        else
#ifdef _WIN32
            snprintf(err, err_cap, "cannot connect to %s:%u (winsock %d)", host, port, last_err);
#else
            snprintf(err, err_cap, "cannot connect to %s:%u: %s", host, port, strerror(last_err));
#endif
        return WS_INVALID;
    }

    // Set TCP_NODELAY — chatty small frames (output, control acks).
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&one, sizeof(one));
    return fd;
}

// ── HTTP/1.1 Upgrade ────────────────────────────────────────────────────────

// Send all bytes (blocking). Returns 0 / -1.
static int send_all_blocking(ws_fd_t fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
#ifdef _WIN32
        int n = send(fd, (const char *)p + off, (int)(len - off), 0);
#else
        ssize_t n = send(fd, p + off, len - off, 0);
#endif
        if (n < 0) {
            if (ws_errno() == ws_eintr) continue;
            if (ws_errno() == ws_eagain) {
                // We're still pre-upgrade in non-blocking mode — wait writable.
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                if (poll(&pfd, 1, 5000) <= 0) return -1;
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

// Read until "\r\n\r\n" is in the buffer or `cap-1` is filled. Returns total
// bytes read, or -1 on error/EOF/timeout. NUL-terminates buf at the byte after
// the last read; the response body (if any) starts after \r\n\r\n.
static long recv_http_response(ws_fd_t fd, char *buf, size_t cap, int timeout_ms) {
    size_t off = 0;
    while (off + 1 < cap) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) return -1;
#ifdef _WIN32
        int n = recv(fd, buf + off, (int)(cap - 1 - off), 0);
#else
        ssize_t n = recv(fd, buf + off, cap - 1 - off, 0);
#endif
        if (n == 0) return -1;
        if (n < 0) {
            if (ws_errno() == ws_eintr || ws_errno() == ws_eagain) continue;
            return -1;
        }
        off += (size_t)n;
        buf[off] = '\0';
        if (off >= 4 && strstr(buf, "\r\n\r\n")) return (long)off;
    }
    return -1;
}

int ws_connect(ws_t *ws, const char *host, uint16_t port, const char *path,
               size_t max_msg, int connect_timeout_ms) {
    memset(ws, 0, sizeof(*ws));
    ws->fd = WS_INVALID;
    ws->rx = malloc(max_msg);
    ws->tx_cap = max_msg + 1024;
    ws->tx = malloc(ws->tx_cap);
    if (!ws->rx || !ws->tx) {
        ws_set_err(ws, "out of memory");
        ws_close(ws);
        return -1;
    }
    ws->rx_cap = max_msg;

    ws->fd = tcp_connect(host, port, connect_timeout_ms, ws->err, sizeof(ws->err));
    if (ws->fd == WS_INVALID) { ws_close(ws); return -1; }

    // Build Upgrade request. Sec-WebSocket-Key = base64(16 random bytes).
    uint8_t nonce[16]; noise_random(nonce, sizeof(nonce));
    char key_b64[32]; b64_encode(nonce, sizeof(nonce), key_b64, sizeof(key_b64));

    char req[1024];
    int rn = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, (unsigned)port, key_b64);
    if (rn <= 0 || (size_t)rn >= sizeof(req)) {
        ws_set_err(ws, "request too large");
        ws_close(ws); return -1;
    }
    if (send_all_blocking(ws->fd, req, (size_t)rn) != 0) {
        ws_set_err(ws, "send Upgrade request failed (errno %d)", ws_errno());
        ws_close(ws); return -1;
    }

    char resp[4096];
    long resp_len = recv_http_response(ws->fd, resp, sizeof(resp), connect_timeout_ms);
    if (resp_len < 0) {
        ws_set_err(ws, "no Upgrade response (server hung up or timed out)");
        ws_close(ws); return -1;
    }
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0 && strncmp(resp, "HTTP/1.0 101", 12) != 0) {
        // Surface up to the first line.
        char line[160] = {0};
        const char *eol = strstr(resp, "\r\n");
        size_t ll = eol ? (size_t)(eol - resp) : strlen(resp);
        if (ll >= sizeof(line)) ll = sizeof(line) - 1;
        memcpy(line, resp, ll);
        ws_set_err(ws, "WS upgrade rejected: %s", line);
        ws_close(ws); return -1;
    }
    // If the server pipelined a frame after \r\n\r\n, push it into rx.
    char *body = strstr(resp, "\r\n\r\n");
    if (body) {
        body += 4;
        size_t extra = (size_t)resp_len - (size_t)(body - resp);
        if (extra > 0) {
            if (extra > ws->rx_cap) {
                ws_set_err(ws, "first frame too large");
                ws_close(ws); return -1;
            }
            memcpy(ws->rx, body, extra);
            ws->rx_len = extra;
        }
    }
    // Already non-blocking from tcp_connect. Seed the liveness clock so the
    // watchdog measures idle time from a fresh connection. Done.
    ws->last_recv_ms = ws_monotonic_ms();
    return 0;
}

void ws_close(ws_t *ws) {
    if (ws->fd != WS_INVALID) { ws_close_fd(ws->fd); ws->fd = WS_INVALID; }
    free(ws->rx); ws->rx = NULL; ws->rx_len = ws->rx_cap = 0;
    free(ws->tx); ws->tx = NULL; ws->tx_len = ws->tx_cap = 0;
    ws->closed = 1;
}

// ── Framing ─────────────────────────────────────────────────────────────────

// Append a frame to the send queue. Client→server frames MUST be masked
// (RFC 6455 §5.3). Mask key = 4 random bytes, XORed over the payload.
int ws_send_frame(ws_t *ws, uint8_t opcode, const void *data, size_t len) {
    if (ws->closed) return -1;
    // Header: 2..14 bytes (1 + 1 + ext_len up to 8 + mask 4).
    size_t hdr = 2 + 4;
    if (len > 65535) hdr += 8;
    else if (len > 125) hdr += 2;
    if (ws->tx_len + hdr + len > ws->tx_cap) return -1;

    uint8_t *p = ws->tx + ws->tx_len;
    p[0] = (uint8_t)(0x80 | (opcode & 0x0F));   // FIN=1
    if (len <= 125) {
        p[1] = (uint8_t)(0x80 | (uint8_t)len);
        p += 2;
    } else if (len <= 65535) {
        p[1] = (uint8_t)(0x80 | 126);
        p[2] = (uint8_t)(len >> 8);
        p[3] = (uint8_t)(len);
        p += 4;
    } else {
        p[1] = (uint8_t)(0x80 | 127);
        for (int i = 0; i < 8; i++) p[2 + i] = (uint8_t)(len >> (56 - 8 * i));
        p += 10;
    }
    uint8_t mask[4]; noise_random(mask, 4);
    memcpy(p, mask, 4); p += 4;
    const uint8_t *src = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) p[i] = src[i] ^ mask[i & 3];
    ws->tx_len += hdr + len;
    return 0;
}

int ws_io_out(ws_t *ws) {
    while (ws->tx_len > 0) {
#ifdef _WIN32
        int n = send(ws->fd, (const char *)ws->tx, (int)ws->tx_len, 0);
#else
        ssize_t n = send(ws->fd, ws->tx, ws->tx_len, 0);
#endif
        if (n < 0) {
            int e = ws_errno();
            if (e == ws_eintr) continue;
            if (e == ws_eagain) return 0;
            ws_set_err(ws, "send() failed (errno %d)", e);
            return -1;
        }
        memmove(ws->tx, ws->tx + n, ws->tx_len - (size_t)n);
        ws->tx_len -= (size_t)n;
    }
    return 0;
}

// Try to parse one complete frame from ws->rx. On success, copies payload
// into *pl/*pl_len (pointers into ws->rx), sets *opcode/*frame_total. Returns
// 1 if frame parsed, 0 if more bytes needed, -1 on protocol error.
static int parse_one_frame(const uint8_t *rx, size_t rx_len,
                           uint8_t *opcode, int *fin,
                           const uint8_t **pl, size_t *pl_len,
                           size_t *frame_total) {
    if (rx_len < 2) return 0;
    uint8_t b0 = rx[0], b1 = rx[1];
    *fin    = (b0 & 0x80) ? 1 : 0;
    *opcode = b0 & 0x0F;
    int masked = (b1 & 0x80) ? 1 : 0;
    if (masked) return -1;  // Server→client frames MUST NOT be masked.
    size_t plen = b1 & 0x7F;
    size_t off = 2;
    if (plen == 126) {
        if (rx_len < off + 2) return 0;
        plen = ((size_t)rx[2] << 8) | rx[3];
        off += 2;
    } else if (plen == 127) {
        if (rx_len < off + 8) return 0;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | rx[off + i];
        off += 8;
    }
    if (rx_len < off + plen) return 0;
    *pl = rx + off;
    *pl_len = plen;
    *frame_total = off + plen;
    return 1;
}

// Process buffered frames; returns 0 if all parsed cleanly (incl. CLOSE),
// -1 on protocol error. Each app frame is delivered via cb. Sets ws->closed
// on CLOSE / fatal error so the caller can break the poll loop.
static int drain_frames(ws_t *ws, ws_recv_cb cb, void *ctx) {
    for (;;) {
        uint8_t op; int fin;
        const uint8_t *pl; size_t pl_len, ftot;
        int r = parse_one_frame(ws->rx, ws->rx_len, &op, &fin, &pl, &pl_len, &ftot);
        if (r == 0) {
            // Need more bytes — but if the buffer's already full, the frame
            // exceeds rx_cap and we'd loop forever. Fail loudly.
            if (ws->rx_len >= ws->rx_cap) {
                ws_set_err(ws, "WS frame exceeds rx capacity (%zu bytes)", ws->rx_cap);
                ws->closed = 1;
                return -1;
            }
            return 0;
        }
        if (r < 0) {
            ws_set_err(ws, "WS protocol error (masked server frame)");
            ws->closed = 1;
            return -1;
        }
        if (!fin || op == WS_OP_CONT) {
            ws_set_err(ws, "fragmented WS frames not supported");
            ws->closed = 1;
            return -1;
        }

        if (op == WS_OP_PING) {
            ws_send_frame(ws, WS_OP_PONG, pl, pl_len);
        } else if (op == WS_OP_PONG) {
            // Liveness ack — nothing to do.
        } else if (op == WS_OP_CLOSE) {
            ws->have_close = 1;
            if (pl_len >= 2) ws->close_code = ((uint16_t)pl[0] << 8) | pl[1];
            size_t rl = pl_len > 2 ? pl_len - 2 : 0;
            if (rl >= sizeof(ws->close_reason)) rl = sizeof(ws->close_reason) - 1;
            if (rl) memcpy(ws->close_reason, pl + 2, rl);
            ws->close_reason[rl] = '\0';
            // Echo CLOSE back (per RFC) and stop reading further frames.
            if (!ws->sent_close) {
                ws_send_frame(ws, WS_OP_CLOSE, pl, pl_len);
                ws->sent_close = 1;
            }
            ws->closed = 1;
            // Consume the frame and stop.
            if (ftot < ws->rx_len) memmove(ws->rx, ws->rx + ftot, ws->rx_len - ftot);
            ws->rx_len -= ftot;
            return 0;
        } else {
            cb(op, pl, pl_len, ctx);
        }

        // Consume parsed frame.
        if (ftot < ws->rx_len) memmove(ws->rx, ws->rx + ftot, ws->rx_len - ftot);
        ws->rx_len -= ftot;
    }
}

int ws_io_in(ws_t *ws, ws_recv_cb cb, void *ctx) {
    // Process anything buffered first — a CLOSE may already be parseable
    // before we attempt another recv() that returns EOF.
    if (drain_frames(ws, cb, ctx) < 0) return -1;
    if (ws->closed) return 0;

    // Drain socket into rx buffer.
    for (;;) {
        if (ws->rx_len >= ws->rx_cap) break;
#ifdef _WIN32
        int n = recv(ws->fd, (char *)ws->rx + ws->rx_len, (int)(ws->rx_cap - ws->rx_len), 0);
#else
        ssize_t n = recv(ws->fd, ws->rx + ws->rx_len, ws->rx_cap - ws->rx_len, 0);
#endif
        if (n == 0) {
            // Peer closed TCP. Process anything that might have arrived just
            // before EOF (e.g. a CLOSE frame), then surface EOF.
            (void)drain_frames(ws, cb, ctx);
            if (!ws->err[0]) ws_set_err(ws, ws->have_close
                ? "peer closed connection"
                : "TCP EOF (peer closed without WS CLOSE)");
            ws->closed = 1;
            return -1;
        }
        if (n < 0) {
            int e = ws_errno();
            if (e == ws_eintr) continue;
            if (e == ws_eagain) break;
            ws_set_err(ws, "recv() failed (errno %d)", e);
            ws->closed = 1;
            return -1;
        }
        ws->rx_len += (size_t)n;
        ws->last_recv_ms = ws_monotonic_ms();
    }

    return drain_frames(ws, cb, ctx);
}

int ws_check_liveness(ws_t *ws, int idle_ms, int dead_ms) {
    if (ws->closed || ws->last_recv_ms == 0) return 0;
    int64_t now = ws_monotonic_ms();
    int64_t idle = now - ws->last_recv_ms;

    // Silent past the hard limit (incl. a PING that drew no PONG) → declare dead.
    if (idle >= dead_ms) {
        ws_set_err(ws, "no data for %llds — connection presumed dead (half-open?)",
                   (long long)(idle / 1000));
        ws->closed = 1;
        return 1;
    }

    // Idle but not yet dead: poke the peer once with a PING. last_recv_ms moving
    // (PONG or any frame) resets ping_sent_ms via the < comparison below.
    if (idle >= idle_ms && ws->ping_sent_ms <= ws->last_recv_ms) {
        // Only suppress further PINGs if this one actually made it onto the send
        // queue; under tx backpressure we'll retry next tick rather than wait
        // out the hard timeout.
        if (ws_send_frame(ws, WS_OP_PING, NULL, 0) == 0)
            ws->ping_sent_ms = now;
    }
    return 0;
}

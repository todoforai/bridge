// See shell_relay.h.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "shell_relay.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <ws2tcpip.h>
#  define poll WSAPoll
static int sr_close(SOCKET s) { return closesocket(s); }
static void sr_cloexec(SOCKET s) { SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0); }
static void sr_blocking(SOCKET s, int on) { u_long m = on ? 0 : 1; ioctlsocket(s, FIONBIO, &m); }
static void sr_shut_wr(SOCKET s) { shutdown(s, SD_SEND); }
typedef int sr_ssize;
#  define sr_recv(fd, b, n) recv(fd, (char *)(b), (int)(n), 0)
#  define sr_send(fd, b, n) send(fd, (const char *)(b), (int)(n), 0)
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
static int sr_close(int s) { return close(s); }
static void sr_cloexec(int s) { fcntl(s, F_SETFD, FD_CLOEXEC); }
static void sr_blocking(int s, int on) {
    int f = fcntl(s, F_GETFL, 0);
    if (f >= 0) fcntl(s, F_SETFL, on ? (f & ~O_NONBLOCK) : (f | O_NONBLOCK));
}
static void sr_shut_wr(int s) { shutdown(s, SHUT_WR); }
typedef ssize_t sr_ssize;
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#  define sr_recv(fd, b, n) recv(fd, b, n, 0)
#  define sr_send(fd, b, n) send(fd, b, n, MSG_NOSIGNAL)
#endif

enum {
    ST_HDR = 1,   // reading the header line
    ST_STREAM,    // forwarding bytes as SHELL_DATA
    ST_DRAIN,     // rejected: discard input until EOF, then reply err
    ST_WAIT,      // EOF seen, SHELL_END sent: waiting for SHELL_CLOSE
    ST_FETCH,     // fetch: waiting for READY / DATA / CLOSE from the backend
    ST_FLUSH,     // fetch: backend done; close once the out queue is written
};

void shell_relay_init(shell_relay_t *r, shell_send_fn send, shell_busy_fn busy, shell_ready_fn ready, void *ctx) {
    memset(r, 0, sizeof *r);
    r->listen_fd = WS_INVALID_FD;
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) r->streams[i].fd = WS_INVALID_FD;
    r->next_id = 1;
    r->send = send; r->busy = busy; r->ready = ready; r->ctx = ctx;
#ifdef _WIN32
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return;
#endif
    ws_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == WS_INVALID_FD) return;
    sr_cloexec(fd); sr_blocking(fd, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = 0 };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t alen = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 16) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) { sr_close(fd); return; }
    r->listen_fd = fd;
    r->port = ntohs(a.sin_port);
}

static void stream_free(shell_stream_t *s) {
    if (s->fd != WS_INVALID_FD) sr_close(s->fd);
    free(s->lbuf);
    free(s->outq);
    memset(s, 0, sizeof *s);
    s->fd = WS_INVALID_FD;
}

// Final answer to the client, then close. The socket is non-blocking, but the
// line is tiny and the client has stopped writing, so it fits the send buffer.
static void reply(shell_stream_t *s, const char *err) {
    char line[256];
    int n = err ? snprintf(line, sizeof line, "error: %.200s\n", *err ? err : "failed") : snprintf(line, sizeof line, "ok\n");
    if (n > 0) (void)sr_send(s->fd, line, (size_t)n);
    stream_free(s);
}

// ── fetch: bytes for the client go through a bounded out queue ──

static int sr_would_block(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

// Queue (after a direct write when nothing is queued). -1: client gone / over cap.
static int fetch_push(shell_stream_t *s, const void *p, size_t n) {
    const char *b = p;
    if (!s->outq_len) {
        sr_ssize w = sr_send(s->fd, b, n);
        if (w < 0 && !sr_would_block()) return -1;
        if (w > 0) { b += w; n -= (size_t)w; }
    }
    if (!n) return 0;
    if (s->outq_len + n > SHELL_FETCH_MAX) return -1;
    if (s->outq_len + n > s->outq_cap) {
        size_t cap = s->outq_cap ? s->outq_cap : 64 * 1024;
        while (cap < s->outq_len + n) cap *= 2;
        if (cap > SHELL_FETCH_MAX) cap = SHELL_FETCH_MAX;
        char *q = realloc(s->outq, cap);
        if (!q) return -1;
        s->outq = q; s->outq_cap = cap;
    }
    memcpy(s->outq + s->outq_len, b, n);
    s->outq_len += n;
    return 0;
}

// POLLOUT. Frees the stream when a finished fetch has written everything.
static void fetch_flush(shell_stream_t *s) {
    size_t off = 0;
    while (off < s->outq_len) {
        sr_ssize w = sr_send(s->fd, s->outq + off, s->outq_len - off);
        if (w < 0 && sr_would_block()) break;
        if (w <= 0) { stream_free(s); return; }
        off += (size_t)w;
    }
    if (off) { memmove(s->outq, s->outq + off, s->outq_len - off); s->outq_len -= off; s->deadline_ms = ws_monotonic_ms() + SHELL_IDLE_MS; }
    if (s->state == ST_FLUSH && !s->outq_len) stream_free(s);
}

// The backend is done with a fetch: a final line if no body was announced,
// then close once written. Mid-body (`err` set): close now, the client sees
// fewer bytes than announced.
static void fetch_finish(shell_stream_t *s, const char *err) {
    if (s->ready && err) { stream_free(s); return; }
    if (!s->ready) {
        char line[256];
        int n = err ? snprintf(line, sizeof line, "error: %.200s\n", *err ? err : "failed") : snprintf(line, sizeof line, "ok\n");
        if (n <= 0 || fetch_push(s, line, (size_t)n) != 0) { stream_free(s); return; }
    }
    s->state = ST_FLUSH;
    s->deadline_ms = ws_monotonic_ms() + SHELL_IDLE_MS;
    if (!s->outq_len) stream_free(s);
}

// Rejected: the reply waits for the client's EOF (so it is read, not lost to
// an RST) — but at most SHELL_DRAIN_MS. __live never reads a reply: just close.
// A fetch client never half-closes: it gets the line at once.
static void fail(shell_stream_t *s, const char *err) {
    if (s->live) { stream_free(s); return; }
    if (s->fetch) { fetch_finish(s, err); return; }
    snprintf(s->err, sizeof s->err, "%s", err);
    s->state = ST_DRAIN;
    s->deadline_ms = ws_monotonic_ms() + SHELL_DRAIN_MS;
}

void shell_relay_close_all(shell_relay_t *r) {
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) stream_free(&r->streams[i]);
    if (r->listen_fd != WS_INVALID_FD) sr_close(r->listen_fd);
    r->listen_fd = WS_INVALID_FD;
    r->port = 0;
}

void shell_relay_drop_streams(shell_relay_t *r, const char *why) {
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) {
        shell_stream_t *s = &r->streams[i];
        if (s->fd == WS_INVALID_FD) continue;
        if (s->state == ST_WAIT) reply(s, why);
        else if (s->state != ST_DRAIN && s->state != ST_FLUSH) fail(s, why);
    }
}

int shell_relay_stream_count(const shell_relay_t *r) {
    int n = 0;
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) n += r->streams[i].fd != WS_INVALID_FD;
    return n;
}

void shell_relay_fill_pfds(shell_relay_t *r, struct pollfd *pfds, size_t *n, size_t cap) {
    if (r->listen_fd != WS_INVALID_FD && *n < cap) {
        pfds[*n].fd = r->listen_fd; pfds[*n].events = POLLIN; pfds[*n].revents = 0; (*n)++;
    }
    int busy = r->busy && r->busy(r->ctx);
    for (int i = 0; i < SHELL_MAX_STREAMS && *n < cap; i++) {
        shell_stream_t *s = &r->streams[i];
        if (s->fd == WS_INVALID_FD) continue;
#ifdef _WIN32
        // WSAPoll reports POLLHUP for the client's half-close even with
        // events=0, which would drop the stream before the reply. Don't poll a
        // waiting stream: the reply or the tick deadline ends it.
        if (s->state == ST_WAIT) continue;
#endif
        // Backed-up channel: stop reading an attach (the client blocks) instead
        // of buffering. A live stream is always read (it drops lines instead).
        short ev = s->state == ST_WAIT || (busy && s->state == ST_STREAM && !s->live) ? 0 : POLLIN;
        if (s->outq_len) ev |= POLLOUT;
        pfds[*n].fd = s->fd; pfds[*n].events = ev; pfds[*n].revents = 0; (*n)++;
    }
}

static int send_simple(shell_relay_t *r, const char *type, uint32_t id) {
    char buf[96];
    int n = snprintf(buf, sizeof buf, "{\"type\":\"%s\",\"payload\":{\"streamId\":%u}}", type, id);
    return n > 0 ? r->send(r->ctx, buf, (size_t)n) : -1;
}

// END without storing anything (client gave up mid-file).
static int send_abort(shell_relay_t *r, uint32_t id) {
    char buf[96];
    int n = snprintf(buf, sizeof buf, "{\"type\":\"shell:end\",\"payload\":{\"streamId\":%u,\"abort\":true}}", id);
    return n > 0 ? r->send(r->ctx, buf, (size_t)n) : -1;
}

static int send_data(shell_relay_t *r, shell_stream_t *s, const uint8_t *p, size_t n) {
    static char buf[SHELL_DATA_CHUNK * 4 / 3 + 128];
    while (n > 0) {
        size_t c = n > SHELL_DATA_CHUNK ? SHELL_DATA_CHUNK : n;
        int h = snprintf(buf, sizeof buf, "{\"type\":\"shell:data\",\"payload\":{\"streamId\":%u,\"b64\":\"", s->id);
        size_t bl = b64_encode(p, c, buf + h, sizeof buf - (size_t)h - 4);
        if (bl == 0) return -1;
        size_t u = (size_t)h + bl;
        memcpy(buf + u, "\"}}", 3); u += 3;
        if (r->send(r->ctx, buf, u) != 0) return -1;
        p += c; n -= c;
    }
    return 0;
}

// ── live (tail shim) batching ──

static size_t count_lines(const char *p, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; i++) c += p[i] == '\n';
    return c;
}

size_t shell_live_body(char *dst, size_t cap, size_t skipped, const char *src, size_t n, size_t keep) {
    size_t lines = count_lines(src, n), o = 0, i = 0;
    for (size_t drop = lines > keep ? lines - keep : 0; drop > 0; i++) if (src[i] == '\n') { drop--; skipped++; }
    if (skipped) {
        int m = snprintf(dst, cap, "[\xe2\x80\xa6 %zu lines]\n", skipped);
        if (m > 0 && (size_t)m < cap) o = (size_t)m;
    }
    size_t col = 0;
    for (; i < n && o + 8 < cap; i++) {
        if (src[i] == '\n') { dst[o++] = '\n'; col = 0; continue; }
        if (col < SHELL_LIVE_LINE_LEN) dst[o++] = src[i];
        else if (col == SHELL_LIVE_LINE_LEN) { memcpy(dst + o, "\xe2\x80\xa6", 3); o += 3; }
        col++;
    }
    return o;
}

static void live_append(shell_stream_t *s, const uint8_t *p, size_t n) {
    if (s->llen + n > SHELL_LIVE_BUF) { s->skipped += count_lines(s->lbuf, s->llen); s->llen = 0; }
    if (n > SHELL_LIVE_BUF) { s->skipped += count_lines((const char *)p, n - SHELL_LIVE_BUF); p += n - SHELL_LIVE_BUF; n = SHELL_LIVE_BUF; }
    if (s->llen == 0) s->first_ms = ws_monotonic_ms();
    memcpy(s->lbuf + s->llen, p, n);
    s->llen += n;
}

// Send whole lines when due (rate + age/size), or everything when `final`.
static void live_flush(shell_relay_t *r, shell_stream_t *s, int final) {
    int64_t now = ws_monotonic_ms();
    s->credits += (double)(now - s->refill_ms) * SHELL_LIVE_LINES_PER_S / 1000.0;
    if (s->credits > SHELL_LIVE_LINES_PER_S) s->credits = SHELL_LIVE_LINES_PER_S;
    s->refill_ms = now;
    if (s->llen == 0) return;
    size_t n = s->llen;
    if (final) {
        if (s->lbuf[n - 1] != '\n') { if (n < SHELL_LIVE_BUF) s->lbuf[n++] = '\n'; else s->lbuf[n - 1] = '\n'; }
    } else {
        if (s->credits < 1 || (r->busy && r->busy(r->ctx))) return;
        if (s->llen < SHELL_LIVE_FLUSH_BYTES && now - s->first_ms < SHELL_LIVE_FLUSH_MS) return;
        while (n > 0 && s->lbuf[n - 1] != '\n') n--;   // whole lines only
        if (n == 0) {
            if (s->llen < SHELL_LIVE_FLUSH_BYTES) { s->first_ms = now; return; }
            s->lbuf[s->llen - 1] = '\n'; n = s->llen;  // one ≥16KB line
        }
    }
    size_t lines = count_lines(s->lbuf, n);
    size_t keep = s->credits >= 1 ? (size_t)s->credits : (final ? 1 : 0);
    if (keep > lines) keep = lines;
    static char body[SHELL_LIVE_BUF + 64];
    size_t bn = shell_live_body(body, sizeof body, s->skipped, s->lbuf, n, keep);
    if (bn) (void)send_data(r, s, (const uint8_t *)body, bn);
    s->credits -= (double)keep;
    s->skipped = 0;
    size_t rest = n < s->llen ? s->llen - n : 0;   // final may have appended '\n'
    memmove(s->lbuf, s->lbuf + n, rest);
    s->llen = rest;
    if (rest) s->first_ms = now;
}

// Header line complete: relay it as SHELL_OPEN. Every field is re-emitted
// through json_emit_str, so the client can't inject JSON.
static void open_stream(shell_relay_t *r, shell_stream_t *s, const char *hdr, size_t len) {
    static const char *const keys[] = { "kind", "token", "todoId", "blockId", "messageId", "name", "mime", "ref" };
    enum { NKEYS = sizeof keys / sizeof *keys };
    long size = -1;
    if (!json_get_long(hdr, len, "size", &size)) size = -1;
    int tty = 0;
    if (!json_get_bool(hdr, len, "tty", &tty)) tty = 0;
    char vals[NKEYS][1024];
    for (int i = 0; i < NKEYS; i++) {
        size_t vl = 0;
        if (!json_get_str_decoded(hdr, len, keys[i], vals[i], sizeof vals[i], &vl)) vals[i][0] = '\0';
    }
    s->fetch = strcmp(vals[0], "fetch") == 0;
    if (!vals[0][0] || !vals[1][0] || !vals[2][0] || !vals[3][0] || (s->fetch && !vals[7][0])) { fail(s, "bad request"); return; }
    if (!r->ready || !r->ready(r->ctx)) { fail(s, "bridge is not connected to the backend"); return; }
    s->live = strcmp(vals[0], "live") == 0;
    // An attach declares its size up front: EOF alone can't tell a finished
    // upload from a killed client, so a short (or long) stream is never stored.
    if (!s->live && !s->fetch && size < 0) { fail(s, "bad request"); return; }
    s->size = size;
    if (s->live) {
        if (!(s->lbuf = malloc(SHELL_LIVE_BUF))) { fail(s, "out of memory"); return; }
        s->credits = SHELL_LIVE_LINES_PER_S;
        s->refill_ms = ws_monotonic_ms();
    }
    char buf[SHELL_HDR_CAP * 2 + 512]; size_t u = 0;
    int n = snprintf(buf, sizeof buf, "{\"type\":\"shell:open\",\"payload\":{\"streamId\":%u", s->id);
    if (n < 0) { fail(s, "internal error"); return; }
    u = (size_t)n;
    for (int i = 0; i < NKEYS; i++) {
        if (!vals[i][0]) continue;
        char k[24]; int kn = snprintf(k, sizeof k, ",\"%s\":", keys[i]);
        if (json_emit_raw(buf, sizeof buf, &u, k, (size_t)kn) < 0 || json_emit_str(buf, sizeof buf, &u, vals[i], -1) < 0) { fail(s, "header too large"); return; }
    }
    if (!s->live && !s->fetch) {
        char k[48]; int kn = snprintf(k, sizeof k, ",\"size\":%ld", size);
        if (json_emit_raw(buf, sizeof buf, &u, k, (size_t)kn) < 0) { fail(s, "header too large"); return; }
    }
    if (s->fetch && tty && json_emit_raw(buf, sizeof buf, &u, ",\"tty\":true", 11) < 0) { fail(s, "header too large"); return; }
    if (json_emit_raw(buf, sizeof buf, &u, "}}", 2) < 0 || r->send(r->ctx, buf, u) != 0) { fail(s, "bridge is not connected to the backend"); return; }
    if (s->fetch) { s->state = ST_FETCH; s->deadline_ms = ws_monotonic_ms() + SHELL_REPLY_MS; return; }
    s->state = ST_STREAM;
    s->deadline_ms = ws_monotonic_ms() + (s->live ? SHELL_LIVE_IDLE_MS : SHELL_IDLE_MS);
}

static void on_accept(shell_relay_t *r) {
    ws_fd_t fd = accept(r->listen_fd, NULL, NULL);
    if (fd == WS_INVALID_FD) return;
    sr_cloexec(fd); sr_blocking(fd, 0);
#if defined(SO_NOSIGPIPE)
    { int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one); }  // macOS: no MSG_NOSIGNAL
#endif
    shell_stream_t *s = NULL;
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) if (r->streams[i].fd == WS_INVALID_FD) { s = &r->streams[i]; break; }
    if (!s) { (void)sr_send(fd, "error: bridge busy\n", 19); sr_close(fd); return; }
    memset(s, 0, sizeof *s);
    s->fd = fd;
    s->state = ST_HDR;
    s->deadline_ms = ws_monotonic_ms() + SHELL_HDR_MS;
    s->id = r->next_id++;
    if (r->next_id == 0 || r->next_id > 0x7fffffffu) r->next_id = 1;
}

static void on_readable(shell_relay_t *r, shell_stream_t *s) {
    uint8_t raw[SHELL_DATA_CHUNK];
    sr_ssize n = sr_recv(s->fd, raw, sizeof raw);
    if (n < 0) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) return;
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
#endif
    }
    if (s->fetch && s->state != ST_HDR) {
        // A fetch client only reads; EOF/RST from it = it gave up (killed, ^C).
        if (n > 0) return;
        if (s->state == ST_FETCH) (void)send_abort(r, s->id);
        stream_free(s);
        return;
    }
    if (n < 0) {    // client aborted (RST: over the cap, read error, killed)
        if (s->state == ST_STREAM && !s->live) (void)send_abort(r, s->id);
        else if (s->state == ST_STREAM) (void)send_simple(r, "shell:end", s->id);
        stream_free(s);
        return;
    }
    if (n == 0) {   // EOF: client half-closed
        if (s->state == ST_DRAIN) { reply(s, s->err); return; }
        if (s->state == ST_HDR) { reply(s, "bad request"); return; }
        if (s->live) {
            // The pipeline is done and doesn't wait for us: last lines, END, gone.
            live_flush(r, s, 1);
            (void)send_simple(r, "shell:end", s->id);
            stream_free(s);
            return;
        }
        if (s->got != s->size) { (void)send_abort(r, s->id); reply(s, "truncated (client stopped early)"); return; }
        if (send_simple(r, "shell:end", s->id) != 0) { reply(s, "bridge is not connected to the backend"); return; }
        s->state = ST_WAIT;
        s->deadline_ms = ws_monotonic_ms() + SHELL_REPLY_MS;
        return;
    }
    if (s->state == ST_DRAIN) return;
    size_t off = 0;
    if (s->state == ST_HDR) {
        const uint8_t *nl = memchr(raw, '\n', (size_t)n);
        size_t take = nl ? (size_t)(nl - raw) : (size_t)n;
        if (s->hdr_len + take >= sizeof s->hdr) { fail(s, "header too large"); return; }
        memcpy(s->hdr + s->hdr_len, raw, take);
        s->hdr_len += take;
        if (!nl) return;
        open_stream(r, s, s->hdr, s->hdr_len);
        if (s->state != ST_STREAM) return;   // fetch: nothing more to read
        off = take + 1;
    }
    if (s->live) {
        s->deadline_ms = ws_monotonic_ms() + SHELL_LIVE_IDLE_MS;
        if (off < (size_t)n) live_append(s, raw + off, (size_t)n - off);
        return;
    }
    s->got += (long)((size_t)n - off);
    s->deadline_ms = ws_monotonic_ms() + SHELL_IDLE_MS;
    if (s->got > s->size) { (void)send_abort(r, s->id); fail(s, "more bytes than declared"); return; }
    if (off < (size_t)n && send_data(r, s, raw + off, (size_t)n - off) != 0) {
        (void)send_abort(r, s->id);
        fail(s, "bridge is not connected to the backend");
    }
}

void shell_relay_service(shell_relay_t *r, const struct pollfd *pfds, size_t first, size_t n) {
    for (size_t k = first; k < first + n; k++) {
        const struct pollfd *p = &pfds[k];
        if (!p->revents) continue;
        if (p->fd == r->listen_fd) { if (p->revents & POLLIN) on_accept(r); continue; }
        for (int i = 0; i < SHELL_MAX_STREAMS; i++) {
            shell_stream_t *s = &r->streams[i];
            if (s->fd != p->fd || s->fd == WS_INVALID_FD) continue;
            if (p->revents & POLLOUT) { fetch_flush(s); if (s->fd == WS_INVALID_FD) break; }
            if (p->revents & (POLLIN | POLLHUP | POLLERR)) {
                // Waiting for the backend: only a full hang-up matters (client gone).
                if (s->state == ST_WAIT) { if (p->revents & (POLLHUP | POLLERR)) stream_free(s); }
                else on_readable(r, s);
            }
            break;
        }
    }
}

void shell_relay_tick(shell_relay_t *r) {
    int64_t now_ms = ws_monotonic_ms();
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) {
        shell_stream_t *s = &r->streams[i];
        if (s->fd == WS_INVALID_FD) continue;
        if (s->deadline_ms && now_ms >= s->deadline_ms) {
            if (s->state == ST_FETCH) { (void)send_abort(r, s->id); fetch_finish(s, "no answer from the backend"); }
            else if (s->state == ST_FLUSH) stream_free(s);   // client stopped reading
            else if (s->state == ST_WAIT) reply(s, "no answer from the backend");
            else if (s->state == ST_DRAIN) reply(s, s->err);
            else if (s->live) { live_flush(r, s, 1); (void)send_simple(r, "shell:end", s->id); stream_free(s); }
            else { if (s->state == ST_STREAM) (void)send_abort(r, s->id); reply(s, "timed out"); }
        }
        else if (s->live && s->state == ST_STREAM) live_flush(r, s, 0);
    }
}

void shell_relay_on_close(shell_relay_t *r, const char *payload, size_t len) {
    long id = 0;
    if (!json_get_long(payload, len, "streamId", &id) || id <= 0) return;
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) {
        shell_stream_t *s = &r->streams[i];
        if (s->fd == WS_INVALID_FD || s->id != (uint32_t)id) continue;
        char err[200]; size_t el = 0;
        int has_err = json_get_str_decoded(payload, len, "error", err, sizeof err, &el);
        if (s->state == ST_FETCH) fetch_finish(s, has_err ? err : (s->ready && s->got != s->size ? "short body" : NULL));
        else if (s->state == ST_WAIT) reply(s, has_err ? err : NULL);
        else if (s->state != ST_DRAIN && s->state != ST_FLUSH) fail(s, has_err ? err : "closed by the backend");
        return;
    }
}

static shell_stream_t *fetch_stream(shell_relay_t *r, const char *payload, size_t len) {
    long id = 0;
    if (!json_get_long(payload, len, "streamId", &id) || id <= 0) return NULL;
    for (int i = 0; i < SHELL_MAX_STREAMS; i++) {
        shell_stream_t *s = &r->streams[i];
        if (s->fd != WS_INVALID_FD && s->id == (uint32_t)id && s->fetch && s->state == ST_FETCH) return s;
    }
    return NULL;
}

void shell_relay_on_ready(shell_relay_t *r, const char *payload, size_t len) {
    shell_stream_t *s = fetch_stream(r, payload, len);
    if (!s || s->ready) return;
    long size = -1;
    char mime[128]; size_t ml = 0;
    if (!json_get_long(payload, len, "size", &size) || size < 0 || size > SHELL_FETCH_MAX - 256) { (void)send_abort(r, s->id); fetch_finish(s, "bad answer from the backend"); return; }
    if (!json_get_str_decoded(payload, len, "mime", mime, sizeof mime, &ml)) snprintf(mime, sizeof mime, "application/octet-stream");
    for (char *c = mime; *c; c++) if (*c == ' ' || *c == '\n' || *c == '\r') *c = '_';
    char line[192];
    int n = snprintf(line, sizeof line, "data %ld %s\n", size, mime);
    s->ready = 1;
    s->size = size;
    s->deadline_ms = ws_monotonic_ms() + SHELL_IDLE_MS;
    if (n <= 0 || fetch_push(s, line, (size_t)n) != 0) { (void)send_abort(r, s->id); stream_free(s); }
}

void shell_relay_on_data(shell_relay_t *r, const char *payload, size_t len) {
    shell_stream_t *s = fetch_stream(r, payload, len);
    if (!s || !s->ready) return;
    const char *b64 = NULL; size_t bl = 0;
    if (!json_get_str(payload, len, "b64", &b64, &bl)) return;
    static uint8_t raw[SHELL_DATA_CHUNK + 64];
    size_t n = b64_decode(b64, bl, raw, sizeof raw);
    if (!n) return;
    if (s->got + (long)n > s->size || fetch_push(s, raw, n) != 0) { (void)send_abort(r, s->id); stream_free(s); return; }
    s->got += (long)n;
    s->deadline_ms = ws_monotonic_ms() + SHELL_IDLE_MS;
}

// ── Client side ──────────────────────────────────────────────────────────────

int shell_client_send(ws_fd_t fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        sr_ssize w = sr_send(fd, p, n);
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

void shell_client_close(ws_fd_t fd) { sr_close(fd); }

int shell_client_send_lossy(ws_fd_t fd, const void *p, size_t n) {
    sr_blocking(fd, 0);
    sr_ssize w = sr_send(fd, p, n);
    if (w >= 0) return 0;
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK ? 0 : -1;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
#endif
}

ws_fd_t shell_client_open(const char *kind, const char *name, const char *mime, long size,
                          const char *ref, int tty, char *err, size_t err_cap) {
    const char *port_s = getenv("TODOFORAI_BRIDGE_PORT");
    const char *tok = getenv("TODOFORAI_API_TOKEN"), *todo = getenv("TODOFORAI_TODO_ID");
    const char *blk = getenv("TODOFORAI_BLOCK_ID"), *msg = getenv("TODOFORAI_MESSAGE_ID");
    long port = port_s ? strtol(port_s, NULL, 10) : 0;
    if (port <= 0 || port > 65535) { snprintf(err, err_cap, "no TODOFORAI_BRIDGE_PORT (not a bridge shell, or the bridge needs a restart)"); return WS_INVALID_FD; }
    if (!tok || !*tok || !todo || !*todo || !blk || !*blk) { snprintf(err, err_cap, "no TODOFORAI_API_TOKEN/TODO_ID/BLOCK_ID in this shell"); return WS_INVALID_FD; }
    char hdr[SHELL_HDR_CAP]; size_t u = 0;
    const char *keys[] = { "kind", "token", "todoId", "blockId", "messageId", "name", "mime", "ref" };
    const char *vals[] = { kind, tok, todo, blk, msg, name, mime, ref };
    int bad = json_emit_raw(hdr, sizeof hdr, &u, "{", 1) < 0;
    for (int i = 0, first = 1; i < 8 && !bad; i++) {
        if (!vals[i] || !*vals[i]) continue;
        char k[24]; int kn = snprintf(k, sizeof k, "%s\"%s\":", first ? "" : ",", keys[i]);
        bad = json_emit_raw(hdr, sizeof hdr, &u, k, (size_t)kn) < 0 || json_emit_str(hdr, sizeof hdr, &u, vals[i], -1) < 0;
        first = 0;
    }
    if (!bad && size >= 0) {
        char k[40]; int kn = snprintf(k, sizeof k, ",\"size\":%ld", size);
        bad = json_emit_raw(hdr, sizeof hdr, &u, k, (size_t)kn) < 0;
    }
    if (!bad && tty) bad = json_emit_raw(hdr, sizeof hdr, &u, ",\"tty\":true", 11) < 0;
    if (bad || json_emit_raw(hdr, sizeof hdr, &u, "}\n", 2) < 0) { snprintf(err, err_cap, "header too large"); return WS_INVALID_FD; }
    ws_fd_t fd = ws_tcp_connect("127.0.0.1", (uint16_t)port, 1000, err, err_cap);
    if (fd == WS_INVALID_FD) { snprintf(err, err_cap, "bridge daemon not reachable on port %ld", port); return WS_INVALID_FD; }
    sr_cloexec(fd);
    sr_blocking(fd, 1);
    if (shell_client_send(fd, hdr, u) != 0) { sr_close(fd); snprintf(err, err_cap, "bridge daemon hung up"); return WS_INVALID_FD; }
    // A stalled daemon (backend reconnecting) must not hang an upload forever.
#ifdef _WIN32
    DWORD to = SHELL_IDLE_MS;
#else
    struct timeval to = { SHELL_IDLE_MS / 1000, 0 };
#endif
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const void *)&to, sizeof to);
    return fd;
}

const char *shell_client_finish(ws_fd_t fd, int timeout_ms, char *err, size_t err_cap) {
    sr_shut_wr(fd);
    char line[256]; size_t n = 0;
    while (n + 1 < sizeof line) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, timeout_ms) <= 0) break;
        sr_ssize r = sr_recv(fd, line + n, sizeof line - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (memchr(line, '\n', n)) break;
    }
    sr_close(fd);
    line[n] = '\0';
    char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
    if (strcmp(line, "ok") == 0) return NULL;
    snprintf(err, err_cap, "%s", strncmp(line, "error: ", 7) == 0 ? line + 7 : (n ? line : "no answer from the bridge daemon"));
    return err;
}

long shell_client_recv(ws_fd_t fd, void *p, size_t n) {
    struct pollfd pf = { .fd = fd, .events = POLLIN };
    if (poll(&pf, 1, SHELL_IDLE_MS) <= 0) return -1;
    sr_ssize r = sr_recv(fd, p, n);
    return r < 0 ? -1 : (long)r;
}

int shell_client_fetch_head(ws_fd_t fd, long *size, char *mime, size_t mime_cap, char *err, size_t err_cap) {
    // Byte by byte: the body follows the line on the same socket.
    char line[256]; size_t n = 0;
    struct pollfd pf = { .fd = fd, .events = POLLIN };
    while (n + 1 < sizeof line) {
        if (poll(&pf, 1, SHELL_REPLY_MS + 5000) <= 0) break;
        sr_ssize r = sr_recv(fd, line + n, 1);
        if (r <= 0) break;
        if (line[n] == '\n') break;
        n++;
    }
    line[n] = '\0';
    if (strcmp(line, "ok") == 0) return 0;
    if (strncmp(line, "data ", 5) == 0) {
        char *end = NULL;
        *size = strtol(line + 5, &end, 10);
        if (end && *end == ' ' && *size >= 0) { snprintf(mime, mime_cap, "%s", end + 1); return 1; }
    }
    snprintf(err, err_cap, "%s", strncmp(line, "error: ", 7) == 0 ? line + 7 : (n ? line : "no answer from the bridge daemon"));
    return -1;
}

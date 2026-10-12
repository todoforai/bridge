// See adb_relay.h.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "adb_relay.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <ws2tcpip.h>
#  define poll WSAPoll
static int ar_close(SOCKET s) { return closesocket(s); }
static void ar_cloexec(SOCKET s) { SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0); }
static void ar_nonblock(SOCKET s) { u_long m = 1; ioctlsocket(s, FIONBIO, &m); }
static int ar_would_block(void) { int e = WSAGetLastError(); return e == WSAEWOULDBLOCK; }
typedef int ar_ssize;
#  define ar_recv(fd, b, n) recv(fd, (char *)(b), (int)(n), 0)
#  define ar_send(fd, b, n) send(fd, (const char *)(b), (int)(n), 0)
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#  include <unistd.h>
static int ar_close(int s) { return close(s); }
static void ar_cloexec(int s) { fcntl(s, F_SETFD, FD_CLOEXEC); }
static void ar_nonblock(int s) { int f = fcntl(s, F_GETFL, 0); if (f >= 0) fcntl(s, F_SETFL, f | O_NONBLOCK); }
static int ar_would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
typedef ssize_t ar_ssize;
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#  define ar_recv(fd, b, n) recv(fd, b, n, 0)
#  define ar_send(fd, b, n) send(fd, b, n, MSG_NOSIGNAL)
#endif

static int send_close(adb_relay_t *r, uint32_t id, const char *error);
static int outq_push(adb_stream_t *s, const uint8_t *p, size_t n);
static int flush_outq(adb_relay_t *r, adb_stream_t *s);

void adb_relay_init(adb_relay_t *r, adb_send_fn send, adb_busy_fn busy, void *ctx) {
    memset(r, 0, sizeof *r);
    r->busy = busy;
    for (int i = 0; i < ADB_MAX_LISTENERS; i++) r->listeners[i].fd = WS_INVALID_FD;
    for (int i = 0; i < ADB_MAX_STREAMS; i++) r->streams[i].fd = WS_INVALID_FD;
    r->next_id = 1;
    r->send = send;
    r->send_ctx = ctx;
}

static void stream_free(adb_stream_t *s) {
    if (s->fd != WS_INVALID_FD) ar_close(s->fd);
    free(s->outq);
    s->fd = WS_INVALID_FD; s->opened = 0; s->id = 0; s->owner = NULL;
    s->outq = NULL; s->outq_len = s->outq_cap = 0; s->remote_closed = 0;
}

void adb_relay_drop_streams(adb_relay_t *r) {
    for (int i = 0; i < ADB_MAX_STREAMS; i++) stream_free(&r->streams[i]);
}

void adb_relay_close_all(adb_relay_t *r) {
    adb_relay_drop_streams(r);
    for (int i = 0; i < ADB_MAX_LISTENERS; i++) {
        if (r->listeners[i].fd != WS_INVALID_FD) ar_close(r->listeners[i].fd);
        r->listeners[i].fd = WS_INVALID_FD;
    }
}

uint16_t adb_relay_listener(adb_relay_t *r, const char *phone, const char *port_spec,
                            char *err, size_t err_cap) {
    if (!phone || !*phone || strlen(phone) >= ADB_PHONE_CAP) { snprintf(err, err_cap, "phone name missing or too long"); return 0; }
    if (!port_spec || !*port_spec || strlen(port_spec) >= ADB_PORT_SPEC_CAP) { snprintf(err, err_cap, "bad port spec"); return 0; }
    adb_listener_t *slot = NULL;
    for (int i = 0; i < ADB_MAX_LISTENERS; i++) {
        adb_listener_t *l = &r->listeners[i];
        if (l->fd != WS_INVALID_FD && strcmp(l->phone, phone) == 0 && strcmp(l->port_spec, port_spec) == 0) return l->port;
        if (!slot && l->fd == WS_INVALID_FD) slot = l;
    }
    if (!slot) { snprintf(err, err_cap, "too many adb relays (max %d)", ADB_MAX_LISTENERS); return 0; }

    ws_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == WS_INVALID_FD) { snprintf(err, err_cap, "socket() failed"); return 0; }
    ar_cloexec(fd); ar_nonblock(fd);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = 0 };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t alen = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 16) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        ar_close(fd);
        snprintf(err, err_cap, "cannot bind a loopback port");
        return 0;
    }
    slot->fd = fd;
    slot->port = ntohs(a.sin_port);
    snprintf(slot->phone, sizeof slot->phone, "%s", phone);
    snprintf(slot->port_spec, sizeof slot->port_spec, "%s", port_spec);
    slot->last_error[0] = '\0';
    return slot->port;
}

static adb_listener_t *find_listener(adb_relay_t *r, const char *phone, const char *port_spec) {
    for (int i = 0; i < ADB_MAX_LISTENERS; i++) {
        adb_listener_t *l = &r->listeners[i];
        if (l->fd != WS_INVALID_FD && strcmp(l->phone, phone) == 0 && strcmp(l->port_spec, port_spec) == 0) return l;
    }
    return NULL;
}

const char *adb_relay_last_error(adb_relay_t *r, const char *phone, const char *port_spec) {
    adb_listener_t *l = find_listener(r, phone, port_spec);
    return l ? l->last_error : "";
}

uint16_t adb_relay_lookup(adb_relay_t *r, const char *phone, const char *port_spec) {
    adb_listener_t *l = find_listener(r, phone, port_spec);
    return l ? l->port : 0;
}

uint16_t adb_relay_forget(adb_relay_t *r, const char *phone, const char *port_spec) {
    adb_listener_t *l = find_listener(r, phone, port_spec);
    if (!l) return 0;
    uint16_t port = l->port;
    for (int i = 0; i < ADB_MAX_STREAMS; i++)
        if (r->streams[i].fd != WS_INVALID_FD && r->streams[i].owner == l) {
            (void)send_close(r, r->streams[i].id, NULL);
            stream_free(&r->streams[i]);
        }
    ar_close(l->fd); l->fd = WS_INVALID_FD;
    return port;
}

void adb_relay_fill_pfds(adb_relay_t *r, struct pollfd *pfds, size_t *n, size_t cap) {
    for (int i = 0; i < ADB_MAX_LISTENERS && *n < cap; i++) {
        if (r->listeners[i].fd == WS_INVALID_FD) continue;
        pfds[*n].fd = r->listeners[i].fd; pfds[*n].events = POLLIN; pfds[*n].revents = 0; (*n)++;
    }
    int busy = r->busy && r->busy(r->send_ctx);
    for (int i = 0; i < ADB_MAX_STREAMS && *n < cap; i++) {
        if (r->streams[i].fd == WS_INVALID_FD) continue;
        // events=0 while backed up: the fd still reports POLLHUP/POLLERR, but
        // no POLLIN, so we neither read nor grow the queue.
        short ev = busy ? 0 : POLLIN;
        if (r->streams[i].outq_len) ev |= POLLOUT;
        pfds[*n].fd = r->streams[i].fd; pfds[*n].events = ev; pfds[*n].revents = 0; (*n)++;
    }
}

static int send_close(adb_relay_t *r, uint32_t id, const char *error) {
    char buf[512]; size_t u = 0;
    int n = snprintf(buf, sizeof buf, "{\"type\":\"adb:close\",\"payload\":{\"streamId\":%u", id);
    if (n < 0) return -1;
    u = (size_t)n;
    if (error && json_emit_raw(buf, sizeof buf, &u, ",\"error\":", 9) < 0) return -1;
    if (error && json_emit_str(buf, sizeof buf, &u, error, -1) < 0) return -1;
    if (json_emit_raw(buf, sizeof buf, &u, "}}", 2) < 0) return -1;
    return r->send(r->send_ctx, buf, u);
}

static void on_accept(adb_relay_t *r, adb_listener_t *l) {
    ws_fd_t fd = accept(l->fd, NULL, NULL);
    if (fd == WS_INVALID_FD) return;
    ar_cloexec(fd); ar_nonblock(fd);
#ifndef _WIN32
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#endif
    adb_stream_t *s = NULL;
    for (int i = 0; i < ADB_MAX_STREAMS; i++) if (r->streams[i].fd == WS_INVALID_FD) { s = &r->streams[i]; break; }
    if (!s) { ar_close(fd); return; }
    s->fd = fd;
    s->owner = l;
    l->last_error[0] = '\0';
    s->id = r->next_id++;
    if (r->next_id == 0 || r->next_id > 0x7fffffffu) r->next_id = 1;
    char buf[512]; size_t u = 0;
    int n = snprintf(buf, sizeof buf, "{\"type\":\"adb:open\",\"payload\":{\"streamId\":%u,\"phone\":", s->id);
    if (n < 0) { stream_free(s); return; }
    u = (size_t)n;
    char *end = NULL;
    long num = strtol(l->port_spec, &end, 10);
    int ok = json_emit_str(buf, sizeof buf, &u, l->phone, -1) == 0
          && json_emit_raw(buf, sizeof buf, &u, ",\"port\":", 8) == 0;
    if (ok) {
        if (end && *end == '\0' && num > 0) {
            char nb[16]; int nn = snprintf(nb, sizeof nb, "%ld", num);
            ok = json_emit_raw(buf, sizeof buf, &u, nb, (size_t)nn) == 0;
        } else {
            ok = json_emit_str(buf, sizeof buf, &u, l->port_spec, -1) == 0;
        }
    }
    ok = ok && json_emit_raw(buf, sizeof buf, &u, "}}", 2) == 0;
    if (!ok || r->send(r->send_ctx, buf, u) != 0) { stream_free(s); return; }
    s->opened = 1;
}

static void on_readable(adb_relay_t *r, adb_stream_t *s) {
    uint8_t raw[ADB_DATA_CHUNK];
    ar_ssize n = ar_recv(s->fd, raw, sizeof raw);
    if (n <= 0) {
        (void)send_close(r, s->id, NULL);
        stream_free(s);
        return;
    }
    // {"type":"adb:data","payload":{"streamId":N,"b64":"..."}}
    static char buf[ADB_DATA_CHUNK * 4 / 3 + 128];
    int h = snprintf(buf, sizeof buf, "{\"type\":\"adb:data\",\"payload\":{\"streamId\":%u,\"b64\":\"", s->id);
    size_t bl = b64_encode(raw, (size_t)n, buf + h, sizeof buf - (size_t)h - 4);
    if (bl == 0) { (void)send_close(r, s->id, "encode failed"); stream_free(s); return; }
    size_t u = (size_t)h + bl;
    memcpy(buf + u, "\"}}", 3); u += 3;
    if (r->send(r->send_ctx, buf, u) != 0) { stream_free(s); }
}

void adb_relay_service(adb_relay_t *r, const struct pollfd *pfds, size_t first, size_t n) {
    for (size_t k = first; k < first + n; k++) {
        const struct pollfd *p = &pfds[k];
        if (!p->revents) continue;
        for (int i = 0; i < ADB_MAX_LISTENERS; i++)
            if (r->listeners[i].fd == p->fd) { if (p->revents & POLLIN) on_accept(r, &r->listeners[i]); goto next; }
        for (int i = 0; i < ADB_MAX_STREAMS; i++)
            if (r->streams[i].fd == p->fd) {
                adb_stream_t *s = &r->streams[i];
                if (p->revents & POLLOUT) { if (flush_outq(r, s) < 0) goto next; }
                if (p->revents & POLLIN) on_readable(r, s);
                else if (p->revents & (POLLHUP | POLLERR)) { (void)send_close(r, s->id, NULL); stream_free(s); }
                goto next;
            }
        next:;
    }
}

static adb_stream_t *find_stream(adb_relay_t *r, const char *payload, size_t len) {
    long id = 0;
    if (!json_get_long(payload, len, "streamId", &id) || id <= 0) return NULL;
    for (int i = 0; i < ADB_MAX_STREAMS; i++)
        if (r->streams[i].fd != WS_INVALID_FD && r->streams[i].id == (uint32_t)id) return &r->streams[i];
    return NULL;
}

void adb_relay_on_data(adb_relay_t *r, const char *payload, size_t len) {
    adb_stream_t *s = find_stream(r, payload, len);
    if (!s) return;
    const char *b64 = NULL; size_t b64_len = 0;
    if (!json_get_str(payload, len, "b64", &b64, &b64_len)) return;
    static uint8_t raw[ADB_DATA_CHUNK + 64];
    size_t rn = b64_decode(b64, b64_len, raw, sizeof raw);
    if (!rn) return;
    size_t off = 0;
    if (!s->outq_len) {
        // Fast path: hand straight to the kernel; queue only the remainder.
        ar_ssize w = ar_send(s->fd, raw, rn);
        if (w < 0 && !ar_would_block()) { (void)send_close(r, s->id, "local write failed"); stream_free(s); return; }
        if (w > 0) off = (size_t)w;
    }
    if (off < rn && outq_push(s, raw + off, rn - off) < 0) {
        (void)send_close(r, s->id, "local adb too slow (1MB queued)");
        stream_free(s);
    }
}

// Append to the per-stream out queue. -1 when ADB_OUTQ_MAX would be exceeded.
static int outq_push(adb_stream_t *s, const uint8_t *p, size_t n) {
    if (s->outq_len + n > ADB_OUTQ_MAX) return -1;
    if (s->outq_len + n > s->outq_cap) {
        size_t cap = s->outq_cap ? s->outq_cap : 64 * 1024;
        while (cap < s->outq_len + n) cap *= 2;
        uint8_t *q = realloc(s->outq, cap);
        if (!q) return -1;
        s->outq = q; s->outq_cap = cap;
    }
    memcpy(s->outq + s->outq_len, p, n);
    s->outq_len += n;
    return 0;
}

// Drain the out queue on POLLOUT. -1 if the stream was freed.
static int flush_outq(adb_relay_t *r, adb_stream_t *s) {
    size_t off = 0;
    while (off < s->outq_len) {
        ar_ssize w = ar_send(s->fd, s->outq + off, s->outq_len - off);
        if (w < 0 && ar_would_block()) break;
        if (w <= 0) { (void)send_close(r, s->id, "local write failed"); stream_free(s); return -1; }
        off += (size_t)w;
    }
    if (off) { memmove(s->outq, s->outq + off, s->outq_len - off); s->outq_len -= off; }
    if (!s->outq_len && s->remote_closed) { stream_free(s); return -1; }
    return 0;
}

void adb_relay_on_close(adb_relay_t *r, const char *payload, size_t len) {
    adb_stream_t *s = find_stream(r, payload, len);
    if (!s) return;
    if (s->owner) {
        size_t n = 0;
        if (!json_get_str_decoded(payload, len, "error", s->owner->last_error, sizeof s->owner->last_error, &n)) s->owner->last_error[0] = '\0';
    }
    if (s->outq_len) { s->remote_closed = 1; return; }   // EOF after the queue drains
    stream_free(s);   // peer closed → local adb sees EOF
}

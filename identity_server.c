// See identity_server.h.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "identity_server.h"
#include "json.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <ws2tcpip.h>
#  define poll WSAPoll
#  define strncasecmp _strnicmp
static int is_close_fd(SOCKET s) { return closesocket(s); }
static int is_set_nb(SOCKET s)   { u_long m = 1; return ioctlsocket(s, FIONBIO, &m); }
#else
#  include <arpa/inet.h>
#  include <strings.h>  // strncasecmp
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
static int is_close_fd(int s) { return close(s); }
static int is_set_nb(int s)   { int f = fcntl(s, F_GETFL, 0); return f < 0 ? -1 : fcntl(s, F_SETFL, f | O_NONBLOCK); }
#endif

// One absolute budget for accept→read→write: this runs on the daemon's main
// loop, so a slow local client must never hold agent traffic for long.
#define IO_BUDGET_MS 300

ws_fd_t bridge_identity_server_open(void) {
#ifdef _WIN32
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return WS_INVALID_FD;
#endif
    ws_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == WS_INVALID_FD) return WS_INVALID_FD;
    // SO_REUSEADDR only skips TIME_WAIT leftovers of our own previous
    // instance; a live listener (e.g. the bun edge) still wins the port — and
    // it names this machine just as well. (On Windows it would allow real
    // port sharing, so it is POSIX-only.)
#ifndef _WIN32
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(IDENTITY_SERVER_PORT) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 8) != 0 || is_set_nb(fd) != 0) {
        is_close_fd(fd);
        return WS_INVALID_FD;
    }
    return fd;
}

// Any https origin or a local dev server. The loopback bind is the real gate;
// this only decides whether a page may READ the (non-secret) id.
static int origin_allowed(const char *origin, size_t n) {
    return (n > 8 && memcmp(origin, "https://", 8) == 0)
        || (n > 17 && memcmp(origin, "http://localhost:", 17) == 0)
        || (n > 17 && memcmp(origin, "http://127.0.0.1:", 17) == 0);
}

static int remaining_ms(int64_t deadline) {
    int64_t r = deadline - ws_monotonic_ms();
    return r > 0 ? (int)r : 0;
}

static void send_all(ws_fd_t fd, const char *buf, size_t len, int64_t deadline) {
#if defined(SO_NOSIGPIPE)
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif
    size_t off = 0;
    while (off < len) {
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        if (poll(&p, 1, remaining_ms(deadline)) <= 0) return;
#ifdef _WIN32
        int n = send(fd, buf + off, (int)(len - off), 0);
#else
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
#endif
        if (n <= 0) return;  // peer gone or budget spent; nothing to retry within budget
        off += (size_t)n;
    }
}

// Case-insensitive header lookup; copies the value (trimmed) into `out`.
static int header_value(const char *req, const char *name, char *out, size_t cap) {
    size_t nl = strlen(name);
    for (const char *p = req; (p = strchr(p, '\n')) != NULL; ) {
        p++;
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t n = strcspn(v, "\r\n");
            if (n >= cap) return 0;
            memcpy(out, v, n); out[n] = '\0';
            return 1;
        }
    }
    return 0;
}

void bridge_identity_server_serve(ws_fd_t listen_fd, const char *device_id) {
    ws_fd_t fd = accept(listen_fd, NULL, NULL);
    if (fd == WS_INVALID_FD) return;
    int64_t deadline = ws_monotonic_ms() + IO_BUDGET_MS;
    if (is_set_nb(fd) != 0) { is_close_fd(fd); return; }

    char req[2048] = {0};
    size_t off = 0;
    int complete = 0;
    while (off + 1 < sizeof req) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, remaining_ms(deadline)) <= 0) break;
#ifdef _WIN32
        int n = recv(fd, req + off, (int)(sizeof req - 1 - off), 0);
#else
        ssize_t n = recv(fd, req + off, sizeof req - 1 - off, 0);
#endif
        if (n <= 0) break;
        off += (size_t)n;
        req[off] = '\0';
        if (strstr(req, "\r\n\r\n")) { complete = 1; break; }
    }
    if (!complete) { is_close_fd(fd); return; }

    char origin[256];
    char cors[512] = "";
    if (header_value(req, "Origin", origin, sizeof origin) && origin_allowed(origin, strlen(origin)))
        snprintf(cors, sizeof cors,
                 "Access-Control-Allow-Origin: %s\r\n"
                 "Access-Control-Allow-Private-Network: true\r\n"
                 "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
                 "Access-Control-Max-Age: 86400\r\n"
                 "Vary: Origin\r\n", origin);

    char out[1024];
    if (strncmp(req, "OPTIONS /identity ", 18) == 0) {
        snprintf(out, sizeof out, "HTTP/1.0 204 No Content\r\n%sConnection: close\r\n\r\n", cors);
    } else if (strncmp(req, "GET /identity ", 14) == 0 && device_id && device_id[0]) {
        // Only the id: the frontend already has name/os from the device list.
        char body[512]; size_t u = 0;
        int bad = json_emit_raw(body, sizeof body, &u, "{\"deviceId\":", 12) < 0
               || json_emit_str(body, sizeof body, &u, device_id, -1) < 0
               || json_emit_raw(body, sizeof body, &u, "}", 1) < 0;
        if (bad) { is_close_fd(fd); return; }
        snprintf(out, sizeof out,
                 "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
                 "%sContent-Length: %zu\r\nConnection: close\r\n\r\n%.*s", cors, u, (int)u, body);
    } else {
        snprintf(out, sizeof out, "HTTP/1.0 404 Not Found\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", cors);
    }
    send_all(fd, out, strlen(out), deadline);
    is_close_fd(fd);
}

void bridge_identity_server_close(ws_fd_t listen_fd) {
    if (listen_fd != WS_INVALID_FD) is_close_fd(listen_fd);
}

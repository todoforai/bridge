// See file_server.h.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _FILE_OFFSET_BITS 64

#include "file_server.h"
#include "policy.h"
#include "noise.h"  // noise_random

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <windows.h>
#  include <io.h>
#  include <process.h>
#  define strncasecmp _strnicmp
#  define strcasecmp  _stricmp
typedef struct _stati64 fs_stat_t;
#  define fs_fstat(fd, st) _fstati64((fd), (st))
#  define fs_isreg(st)     (((st).st_mode & _S_IFMT) == _S_IFREG)
#  define fs_close(fd)     _close(fd)
#  define FS_OPEN_FLAGS    (_O_RDONLY | _O_BINARY)
static SRWLOCK g_mu = SRWLOCK_INIT;
#  define LOCK()   AcquireSRWLockExclusive(&g_mu)
#  define UNLOCK() ReleaseSRWLockExclusive(&g_mu)
static void sock_close(ws_fd_t s) { closesocket(s); }
#else
#  include <pthread.h>
#  include <strings.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
typedef struct stat fs_stat_t;
#  define fs_fstat(fd, st) fstat((fd), (st))
#  define fs_isreg(st)     S_ISREG((st).st_mode)
#  define fs_close(fd)     close(fd)
#  define FS_OPEN_FLAGS    (O_RDONLY | O_NONBLOCK)  // a FIFO must not block the open
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#  define LOCK()   pthread_mutex_lock(&g_mu)
#  define UNLOCK() pthread_mutex_unlock(&g_mu)
static void sock_close(ws_fd_t s) { close(s); }
#endif
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

// A grant outlives one playback session (seeks re-request), so the TTL is
// generous and slides on every use. Bounded table: the oldest grant is
// evicted when full.
#define GRANT_TTL_MS     (6LL * 3600 * 1000)
#define GRANT_MAX        64
#define MAX_STREAMS      16       // concurrent serving threads
#define SEND_TIMEOUT_S   30       // a stalled reader frees its thread
#define IO_CHUNK         (256 * 1024)

typedef struct {
    char    token[FILE_GRANT_TOKEN_LEN + 1];
    char   *path;
    int64_t expires_ms;
} grant_t;

static grant_t g_grants[GRANT_MAX];
static int     g_streams;

static int64_t now_ms(void) { return ws_monotonic_ms(); }

static int token_eq(const char *a, const char *b) {
    unsigned char d = 0;
    for (int i = 0; i < FILE_GRANT_TOKEN_LEN; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

static int open_checked(const char *path, long long *size, char *err, size_t cap) {
    int fd = bridge_policy_open(path, FS_OPEN_FLAGS, 0);
    if (fd < 0) {
        if (errno == EACCES && g_policy.active) { char m[2200]; snprintf(err, cap, "%s", bridge_policy_deny_msg(path, m, sizeof m)); }
        else snprintf(err, cap, errno == ENOENT ? "file_grant: not found" : "file_grant: open failed");
        return -1;
    }
    fs_stat_t st;
    if (fs_fstat(fd, &st) != 0 || !fs_isreg(st)) {
        fs_close(fd);
        snprintf(err, cap, "file_grant: not a regular file");
        return -1;
    }
    *size = (long long)st.st_size;
    return fd;
}

int bridge_file_grant(const char *path, char *token_out, size_t token_cap,
                      long long *size_out, char *err, size_t err_cap) {
    if (token_cap < FILE_GRANT_TOKEN_LEN + 1) { snprintf(err, err_cap, "file_grant: token buffer"); return -1; }
    int fd = open_checked(path, size_out, err, err_cap);
    if (fd < 0) return -1;
    fs_close(fd);

    uint8_t rnd[FILE_GRANT_TOKEN_LEN / 2];
    if (noise_random(rnd, sizeof rnd) != 0) { snprintf(err, err_cap, "file_grant: no randomness"); return -1; }
    char fresh[FILE_GRANT_TOKEN_LEN + 1];
    for (size_t i = 0; i < sizeof rnd; i++) snprintf(fresh + 2 * i, 3, "%02x", rnd[i]);

    int64_t now = now_ms();
    LOCK();
    // Same path → same token (refreshed), so re-renders of a snippet don't
    // churn the table.
    int slot = -1, oldest = 0;
    for (int i = 0; i < GRANT_MAX; i++) {
        grant_t *g = &g_grants[i];
        if (g->path && g->expires_ms > now && strcmp(g->path, path) == 0) { slot = i; break; }
        if (slot < 0 && (!g->path || g->expires_ms <= now)) slot = i;  // free/expired; keep looking for a match
        if (g_grants[i].expires_ms < g_grants[oldest].expires_ms) oldest = i;
    }
    if (slot < 0) slot = oldest;
    grant_t *g = &g_grants[slot];
    if (!(g->path && strcmp(g->path, path) == 0 && g->expires_ms > now)) {
        char *dup = strdup(path);
        if (!dup) { UNLOCK(); snprintf(err, err_cap, "out of memory"); return -1; }
        free(g->path);
        g->path = dup;
        memcpy(g->token, fresh, sizeof fresh);
    }
    g->expires_ms = now + GRANT_TTL_MS;
    memcpy(token_out, g->token, FILE_GRANT_TOKEN_LEN + 1);
    UNLOCK();
    return 0;
}

// Copy the granted path for `token` (malloc'd) and slide its expiry.
static char *grant_lookup(const char *token) {
    char *out = NULL;
    int64_t now = now_ms();
    LOCK();
    for (int i = 0; i < GRANT_MAX; i++) {
        grant_t *g = &g_grants[i];
        if (g->path && g->expires_ms > now && token_eq(g->token, token)) {
            g->expires_ms = now + GRANT_TTL_MS;
            out = strdup(g->path);
            break;
        }
    }
    UNLOCK();
    return out;
}

static const char *mime_of(const char *path) {
    static const char *map[][2] = {
        {"mp4", "video/mp4"}, {"m4v", "video/mp4"}, {"webm", "video/webm"}, {"mov", "video/quicktime"},
        {"mp3", "audio/mpeg"}, {"wav", "audio/wav"}, {"ogg", "audio/ogg"}, {"m4a", "audio/mp4"},
        {"aac", "audio/aac"}, {"flac", "audio/flac"}, {"png", "image/png"}, {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"}, {"gif", "image/gif"}, {"webp", "image/webp"}, {"pdf", "application/pdf"},
    };
    const char *dot = strrchr(path, '.');
    if (dot && !strpbrk(dot, "/\\"))
        for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
            if (strcasecmp(dot + 1, map[i][0]) == 0) return map[i][1];
    return "application/octet-stream";
}

static int send_all(ws_fd_t fd, const char *buf, size_t len) {
    while (len) {
#ifdef _WIN32
        int n = send(fd, buf, (int)len, 0);
#else
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
#endif
        if (n <= 0) return -1;
        buf += n; len -= (size_t)n;
    }
    return 0;
}

static void respond(ws_fd_t fd, const char *status, const char *cors) {
    char out[2048];
    int n = snprintf(out, sizeof out, "HTTP/1.1 %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", status, cors);
    if (n > 0 && (size_t)n < sizeof out) send_all(fd, out, (size_t)n);
}

// Single "bytes=a-b" | "bytes=a-" | "bytes=-n". 1 = satisfiable range in
// *a..*b, 0 = no usable Range (absent, other unit, multi-range or malformed:
// serve the whole file), -1 = well-formed but unsatisfiable (416).
static int parse_range(const char *req, long long size, long long *a, long long *b) {
    const char *p = req;
    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (strncasecmp(p, "Range:", 6) == 0) break;
    }
    if (!p) return 0;
    p += 6;
    while (*p == ' ' || *p == '\t') p++;
    if (strncasecmp(p, "bytes=", 6) != 0) return 0;
    p += 6;
    long long x = -1, y = -1;
    char *end;
    if (*p >= '0' && *p <= '9') { x = strtoll(p, &end, 10); p = end; }
    if (*p != '-') return 0;
    p++;
    if (*p >= '0' && *p <= '9') { y = strtoll(p, &end, 10); p = end; }
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '\r' && *p != '\n' && *p != '\0') return 0;   // multi-range or junk
    if (x < 0 && y < 0) return 0;                           // "bytes=-"
    if (x < 0) {                                            // suffix: last y bytes
        if (y == 0 || size == 0) return -1;
        x = y > size ? 0 : size - y; y = size - 1;
    } else {
        if (y >= 0 && y < x) return 0;
        if (x >= size) return -1;
        if (y < 0 || y >= size) y = size - 1;
    }
    *a = x; *b = y;
    return 1;
}

typedef struct {
    ws_fd_t fd;
    char   *path;
    char    req[4096];
    char    cors[768];
} job_t;

static void serve_job(job_t *j) {
    ws_fd_t fd = j->fd;
    char err[256];
    long long size = 0;
    int ffd = open_checked(j->path, &size, err, sizeof err);
    if (ffd < 0) { respond(fd, "404 Not Found", j->cors); return; }

    long long a = 0, b = size - 1;
    int r = strncmp(j->req, "GET ", 4) == 0 ? parse_range(j->req, size, &a, &b) : 0;
    if (r < 0) {
        char out[2048];
        int n = snprintf(out, sizeof out, "HTTP/1.1 416 Range Not Satisfiable\r\n%sContent-Range: bytes */%lld\r\n"
                         "Content-Length: 0\r\nConnection: close\r\n\r\n", j->cors, size);
        if (n > 0 && (size_t)n < sizeof out) send_all(fd, out, (size_t)n);
        fs_close(ffd);
        return;
    }
    long long len = size ? b - a + 1 : 0;
    char head[2048], cr[96] = "";
    if (r > 0) snprintf(cr, sizeof cr, "Content-Range: bytes %lld-%lld/%lld\r\n", a, b, size);
    int hn = snprintf(head, sizeof head,
                      "HTTP/1.1 %s\r\n%sContent-Type: %s\r\nAccept-Ranges: bytes\r\n%s"
                      "Content-Length: %lld\r\nCache-Control: private, no-store\r\n"
                      "Cross-Origin-Resource-Policy: cross-origin\r\nConnection: close\r\n\r\n",
                      r > 0 ? "206 Partial Content" : "200 OK", j->cors, mime_of(j->path), cr, len);
    if (hn <= 0 || (size_t)hn >= sizeof head || send_all(fd, head, (size_t)hn) != 0 || strncmp(j->req, "HEAD ", 5) == 0) { fs_close(ffd); return; }

    char *buf = malloc(IO_CHUNK);
    if (!buf) { fs_close(ffd); return; }
    long long off = a, left = len;
    while (left > 0) {
        size_t want = left < IO_CHUNK ? (size_t)left : IO_CHUNK;
#ifdef _WIN32
        if (_lseeki64(ffd, off, SEEK_SET) < 0) break;
        int n = _read(ffd, buf, (unsigned)want);
#else
        ssize_t n = pread(ffd, buf, want, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
#endif
        if (n <= 0) break;  // truncated under us: the client sees a short body
        if (send_all(fd, buf, (size_t)n) != 0) break;
        off += n; left -= n;
    }
    free(buf);
    fs_close(ffd);
}

#ifdef _WIN32
static unsigned __stdcall job_main(void *arg)
#else
static void *job_main(void *arg)
#endif
{
    job_t *j = arg;
    serve_job(j);
#ifndef _WIN32
    shutdown(j->fd, SHUT_WR);
#endif
    sock_close(j->fd);
    free(j->path);
    free(j);
    LOCK(); g_streams--; UNLOCK();
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

void bridge_file_serve(ws_fd_t fd, const char *req, const char *cors) {
#if defined(SO_NOSIGPIPE)
    { int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one); }  // before ANY send
#endif
    // Token: 32 hex chars after "t=" in the query.
    const char *q = strchr(req, '?');
    const char *sp = strchr(req, ' ');
    const char *line_end = sp ? strchr(sp + 1, ' ') : NULL;  // end of request-target
    const char *t = NULL;
    for (const char *p = q; p && line_end && p < line_end; p = strchr(p + 1, '&')) {
        if (p[1] == 't' && p[2] == '=') { t = p + 3; break; }
    }
    char token[FILE_GRANT_TOKEN_LEN + 1];
    size_t tl = 0;
    while (t && tl < FILE_GRANT_TOKEN_LEN && ((t[tl] >= '0' && t[tl] <= '9') || (t[tl] >= 'a' && t[tl] <= 'f'))) { token[tl] = t[tl]; tl++; }
    token[tl] = '\0';
    char *path = tl == FILE_GRANT_TOKEN_LEN ? grant_lookup(token) : NULL;
    if (!path) { respond(fd, "403 Forbidden", cors); sock_close(fd); return; }

    job_t *j = calloc(1, sizeof *j);
    LOCK();
    int busy = g_streams >= MAX_STREAMS;
    if (!busy && j) g_streams++;
    UNLOCK();
    if (busy || !j) { respond(fd, "503 Service Unavailable", cors); sock_close(fd); free(path); free(j); return; }
    j->fd = fd; j->path = path;
    snprintf(j->req, sizeof j->req, "%s", req);
    snprintf(j->cors, sizeof j->cors, "%s", cors);

    // Blocking socket with a send timeout: the thread may block, the daemon
    // loop never does.
#ifdef _WIN32
    u_long nb = 0; ioctlsocket(fd, FIONBIO, &nb);
    DWORD to = SEND_TIMEOUT_S * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&to, sizeof to);
    uintptr_t h = _beginthreadex(NULL, 0, job_main, j, 0, NULL);
    if (h) { CloseHandle((HANDLE)h); return; }
#else
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    struct timeval to = { .tv_sec = SEND_TIMEOUT_S };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof to);
    pthread_t tid;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    int ok = pthread_create(&tid, &at, job_main, j) == 0;
    pthread_attr_destroy(&at);
    if (ok) return;
#endif
    // No thread: answer 503 rather than stream on the daemon loop.
    respond(fd, "503 Service Unavailable", cors);
    sock_close(fd);
    free(j->path); free(j);
    LOCK(); g_streams--; UNLOCK();
}

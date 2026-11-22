#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "preview_ws.h"
#include "preview.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PREVIEW_WS_CONNECT_MS 3000
#define PREVIEW_WS_FRAME_CAP  (56 * 1024)   // 32KB raw -> ~43.7KB b64 + envelope < 64KB Noise cap

static void emit_opened(preview_ws_relay_t *r, const char *id, const char *err) {
    char buf[512];
    size_t u = 0;
    if (json_emit_raw(buf, sizeof buf, &u, "{\"type\":\"preview:ws_opened\",\"payload\":{\"streamId\":", 50) < 0) return;
    if (json_emit_str(buf, sizeof buf, &u, id, -1) < 0) return;
    if (err && err[0]) {
        if (json_emit_raw(buf, sizeof buf, &u, ",\"error\":", 9) < 0) return;
        if (json_emit_str(buf, sizeof buf, &u, err, -1) < 0) return;
    }
    if (json_emit_raw(buf, sizeof buf, &u, "}}", 2) < 0) return;
    if (r->send) (void)r->send(r->send_ctx, buf, u);
}

static void emit_close(preview_ws_relay_t *r, const char *id, int code, const char *reason) {
    char buf[512];
    size_t u = 0;
    if (json_emit_raw(buf, sizeof buf, &u, "{\"type\":\"preview:ws_close\",\"payload\":{\"streamId\":", 49) < 0) return;
    if (json_emit_str(buf, sizeof buf, &u, id, -1) < 0) return;
    if (code >= 1000 && code < 5000) {
        char num[32];
        int n = snprintf(num, sizeof num, ",\"code\":%d", code);
        if (n > 0 && json_emit_raw(buf, sizeof buf, &u, num, (size_t)n) < 0) return;
    }
    if (reason && reason[0]) {
        if (json_emit_raw(buf, sizeof buf, &u, ",\"reason\":", 10) < 0) return;
        if (json_emit_str(buf, sizeof buf, &u, reason, -1) < 0) return;
    }
    if (json_emit_raw(buf, sizeof buf, &u, "}}", 2) < 0) return;
    if (r->send) (void)r->send(r->send_ctx, buf, u);
}

static int emit_data_chunks(preview_ws_relay_t *r, const char *id, int binary,
                            const uint8_t *data, size_t len) {
    char *frame = malloc(PREVIEW_WS_FRAME_CAP);
    char *b64 = malloc(((PREVIEW_WS_CHUNK_RAW + 2) / 3) * 4 + 4);
    if (!frame || !b64) { free(frame); free(b64); return -1; }

    size_t off = 0;
    int rc = 0;
    do {
        size_t chunk = len - off;
        if (chunk > PREVIEW_WS_CHUNK_RAW) chunk = PREVIEW_WS_CHUNK_RAW;
        int fin = (off + chunk >= len);

        size_t b64_len = chunk ? b64_encode(data + off, chunk, b64, ((PREVIEW_WS_CHUNK_RAW + 2) / 3) * 4 + 4) : 0;
        b64[b64_len] = '\0';

        size_t u = 0;
        if (json_emit_raw(frame, PREVIEW_WS_FRAME_CAP, &u, "{\"type\":\"preview:ws_data\",\"payload\":{\"streamId\":", 48) < 0 ||
            json_emit_str(frame, PREVIEW_WS_FRAME_CAP, &u, id, -1) < 0 ||
            json_emit_raw(frame, PREVIEW_WS_FRAME_CAP, &u, binary ? ",\"binary\":true" : ",\"binary\":false", binary ? 14 : 15) < 0 ||
            json_emit_raw(frame, PREVIEW_WS_FRAME_CAP, &u, ",\"dataB64\":\"", 12) < 0 ||
            json_emit_raw(frame, PREVIEW_WS_FRAME_CAP, &u, b64, b64_len) < 0 ||
            json_emit_raw(frame, PREVIEW_WS_FRAME_CAP, &u, fin ? "\",\"fin\":true}}" : "\",\"fin\":false}}", fin ? 14 : 15) < 0) {
            rc = -1;
            break;
        }
        if (r->send && r->send(r->send_ctx, frame, u) != 0) { rc = -1; break; }
        off += chunk;
    } while (off < len);

    free(frame);
    free(b64);
    return rc;
}

static void send_ws_close_best_effort(ws_t *ws, int code) {
    if (ws->fd == WS_INVALID_FD || ws->closed || ws->sent_close) return;
    uint16_t c = (code >= 1000 && code < 5000) ? (uint16_t)code : 1000;
    uint8_t pl[2] = { (uint8_t)(c >> 8), (uint8_t)(c & 0xff) };
    if (ws_send_frame(ws, WS_OP_CLOSE, pl, 2) == 0) {
        ws->sent_close = 1;
        (void)ws_io_out(ws);
    }
}

static void free_stream(preview_ws_stream_t *s, int send_close, int code) {
    if (!s->active) return;
    if (send_close) send_ws_close_best_effort(&s->ws, code);
    ws_close(&s->ws);
    free(s->rx_buf);
    memset(s, 0, sizeof *s);
    s->ws.fd = WS_INVALID_FD;
}

static preview_ws_stream_t *find_stream(preview_ws_relay_t *r, const char *id) {
    for (int i = 0; i < PREVIEW_WS_MAX_STREAMS; i++) {
        if (r->streams[i].active && strcmp(r->streams[i].id, id) == 0)
            return &r->streams[i];
    }
    return NULL;
}

static int clean_ws_path(const char *p) {
    if (!p || p[0] != '/') return 0;
    for (const unsigned char *s = (const unsigned char *)p; *s; s++) {
        if (*s <= 0x20 || *s >= 0x7f) return 0;
    }
    return 1;
}

void preview_ws_init(preview_ws_relay_t *r, preview_ws_send_fn send,
                     preview_ws_busy_fn busy, void *ctx) {
    memset(r, 0, sizeof *r);
    for (int i = 0; i < PREVIEW_WS_MAX_STREAMS; i++)
        r->streams[i].ws.fd = WS_INVALID_FD;
    r->send = send;
    r->busy = busy;
    r->send_ctx = ctx;
}

void preview_ws_close_all(preview_ws_relay_t *r) {
    for (int i = 0; i < PREVIEW_WS_MAX_STREAMS; i++)
        free_stream(&r->streams[i], 0, 1001);
}

void preview_ws_on_open(preview_ws_relay_t *r, const char *payload, size_t len) {
    char id[PREVIEW_WS_ID_CAP];
    size_t id_len = 0;
    if (!json_get_str_decoded(payload, len, "streamId", id, sizeof id, &id_len) || id_len == 0)
        return;

    char err[160] = "";
    if (bridge_preview_authorize(payload, len, err, sizeof err) != 0) {
        emit_opened(r, id, err);
        return;
    }

    long port = 0;
    if (!json_get_long(payload, len, "port", &port) || port < 1 || port > 65535) {
        emit_opened(r, id, "preview: invalid port");
        return;
    }

    char path[1024];
    size_t path_len = 0;
    if (!json_get_str_decoded(payload, len, "path", path, sizeof path, &path_len) || path_len == 0) {
        strcpy(path, "/");
    }
    if (!clean_ws_path(path)) {
        emit_opened(r, id, "preview: invalid WebSocket path");
        return;
    }

    // Optional subprotocols: ["vite-hmr", ...] -> "vite-hmr, ..."
    char protos[256] = "";
    const char *arr = NULL; size_t arr_len = 0;
    if (json_get_arr(payload, len, "protocols", &arr, &arr_len)) {
        size_t pos = 0, used = 0;
        const char *val = NULL; size_t vlen = 0; json_type_t vt;
        while (json_arr_iter(arr, arr_len, &pos, &val, &vlen, &vt) == 1) {
            if (vt != JT_STR) continue;
            char item[128];
            long ilen = json_unescape_span(val, vlen, item, sizeof item);
            if (ilen <= 0) continue;
            if (used > 0 && used + 2 < sizeof protos) { protos[used++] = ','; protos[used++] = ' '; }
            if (used + (size_t)ilen < sizeof protos) {
                memcpy(protos + used, item, (size_t)ilen);
                used += (size_t)ilen;
                protos[used] = '\0';
            }
        }
    }

    // Drop any stale stream with the same id, then allocate a free slot.
    preview_ws_stream_t *dup = find_stream(r, id);
    if (dup) free_stream(dup, 1, 1000);

    preview_ws_stream_t *slot = NULL;
    for (int i = 0; i < PREVIEW_WS_MAX_STREAMS; i++) {
        if (!r->streams[i].active) { slot = &r->streams[i]; break; }
    }
    if (!slot) {
        emit_opened(r, id, "Too many preview WebSocket connections");
        return;
    }

    memset(&slot->ws, 0, sizeof slot->ws);
    slot->ws.fd = WS_INVALID_FD;
    if (ws_connect_ex(&slot->ws, "127.0.0.1", (uint16_t)port, path,
                      protos[0] ? protos : NULL, PREVIEW_WS_MAX_MSG, PREVIEW_WS_CONNECT_MS) != 0) {
        const char *msg = slot->ws.err[0] ? slot->ws.err : "WebSocket connect failed";
        emit_opened(r, id, msg);
        ws_close(&slot->ws);
        return;
    }

    slot->active = 1;
    snprintf(slot->id, sizeof slot->id, "%s", id);
    emit_opened(r, id, NULL);
}

static int send_to_local(preview_ws_relay_t *r, preview_ws_stream_t *s,
                         int binary, const uint8_t *data, size_t len) {
    uint8_t op = binary ? WS_OP_BINARY : WS_OP_TEXT;
    if (ws_send_frame(&s->ws, op, data, len) != 0 || ws_io_out(&s->ws) < 0) {
        char id[PREVIEW_WS_ID_CAP];
        snprintf(id, sizeof id, "%s", s->id);
        free_stream(s, 0, 1011);
        emit_close(r, id, 1011, "Local WebSocket send failed");
        return -1;
    }
    return 0;
}

void preview_ws_on_data(preview_ws_relay_t *r, const char *payload, size_t len) {
    char id[PREVIEW_WS_ID_CAP];
    size_t id_len = 0;
    if (!json_get_str_decoded(payload, len, "streamId", id, sizeof id, &id_len) || id_len == 0)
        return;
    preview_ws_stream_t *s = find_stream(r, id);
    if (!s) return;

    int binary = 0;
    (void)json_get_bool(payload, len, "binary", &binary);
    int fin = 1;
    (void)json_get_bool(payload, len, "fin", &fin);

    uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    const char *raw = NULL; size_t raw_len = 0;
    if (json_get_str(payload, len, "dataB64", &raw, &raw_len)) {
        if (raw_len > 0) {
            size_t cap = (raw_len / 4 + 2) * 3;
            chunk = malloc(cap);
            if (!chunk) return;
            chunk_len = b64_decode(raw, raw_len, chunk, cap);
            if (chunk_len == 0) { free(chunk); return; }
        }
    } else if (json_get_str(payload, len, "text", &raw, &raw_len)) {
        if (raw_len > 0) {
            chunk = malloc(raw_len + 1);
            if (!chunk) return;
            long dec = json_unescape_span(raw, raw_len, (char *)chunk, raw_len + 1);
            if (dec < 0) { free(chunk); return; }
            chunk_len = (size_t)dec;
        }
    }

    if (s->rx_len == 0 && fin) {
        (void)send_to_local(r, s, binary, chunk ? chunk : (const uint8_t *)"", chunk_len);
        free(chunk);
        return;
    }

    if (s->rx_len == 0) s->rx_binary = binary;
    if (s->rx_len + chunk_len > PREVIEW_WS_MAX_MSG) {
        free(chunk);
        free_stream(s, 1, 1009);
        emit_close(r, id, 1009, "Message too large");
        return;
    }
    if (chunk_len > 0) {
        if (s->rx_len + chunk_len > s->rx_cap) {
            size_t ncap = s->rx_cap ? s->rx_cap * 2 : 65536;
            while (ncap < s->rx_len + chunk_len) ncap *= 2;
            uint8_t *nb = realloc(s->rx_buf, ncap);
            if (!nb) {
                free(chunk);
                free_stream(s, 1, 1011);
                emit_close(r, id, 1011, "Out of memory");
                return;
            }
            s->rx_buf = nb;
            s->rx_cap = ncap;
        }
        memcpy(s->rx_buf + s->rx_len, chunk, chunk_len);
        s->rx_len += chunk_len;
    }
    free(chunk);

    if (fin) {
        int b = s->rx_binary;
        size_t total = s->rx_len;
        s->rx_len = 0;
        (void)send_to_local(r, s, b, s->rx_buf ? s->rx_buf : (const uint8_t *)"", total);
    }
}

void preview_ws_on_close(preview_ws_relay_t *r, const char *payload, size_t len) {
    char id[PREVIEW_WS_ID_CAP];
    size_t id_len = 0;
    if (!json_get_str_decoded(payload, len, "streamId", id, sizeof id, &id_len) || id_len == 0)
        return;
    long code = 1000;
    (void)json_get_long(payload, len, "code", &code);
    preview_ws_stream_t *s = find_stream(r, id);
    if (s) free_stream(s, 1, (int)code);
}

void preview_ws_fill_pfds(preview_ws_relay_t *r, struct pollfd *pfds, size_t *n, size_t cap) {
    int paused = (r->busy && r->busy(r->send_ctx));
    for (int i = 0; i < PREVIEW_WS_MAX_STREAMS; i++) {
        preview_ws_stream_t *s = &r->streams[i];
        if (!s->active || s->ws.fd == WS_INVALID_FD) continue;
        if (*n >= cap) break;
        short ev = 0;
        if (!paused) ev |= POLLIN;
        if (ws_want_write(&s->ws)) ev |= POLLOUT;
        pfds[*n].fd = s->ws.fd;
        pfds[*n].events = ev;
        pfds[*n].revents = 0;
        (*n)++;
    }
}

typedef struct {
    preview_ws_relay_t  *r;
    preview_ws_stream_t *s;
    int                  send_failed;
} local_ws_ctx_t;

static void on_local_ws_msg(uint8_t opcode, const uint8_t *data, size_t len, void *vctx) {
    local_ws_ctx_t *ctx = (local_ws_ctx_t *)vctx;
    if (ctx->send_failed) return;
    if (opcode != WS_OP_TEXT && opcode != WS_OP_BINARY) return;
    if (emit_data_chunks(ctx->r, ctx->s->id, opcode == WS_OP_BINARY, data, len) != 0)
        ctx->send_failed = 1;
}

void preview_ws_service(preview_ws_relay_t *r, const struct pollfd *pfds, size_t first, size_t n) {
    for (size_t k = 0; k < n; k++) {
        const struct pollfd *p = &pfds[first + k];
        if (!p->revents) continue;

        preview_ws_stream_t *s = NULL;
        for (int i = 0; i < PREVIEW_WS_MAX_STREAMS; i++) {
            if (r->streams[i].active && r->streams[i].ws.fd == p->fd) {
                s = &r->streams[i];
                break;
            }
        }
        if (!s) continue;

        int broken = 0;
        if (p->revents & (POLLERR | POLLNVAL)) broken = 1;
        if (!broken && (p->revents & POLLOUT)) {
            if (ws_io_out(&s->ws) < 0) broken = 1;
        }
        if (!broken && (p->revents & (POLLIN | POLLHUP))) {
            local_ws_ctx_t ctx = { r, s, 0 };
            int rc = ws_io_in(&s->ws, on_local_ws_msg, &ctx);
            if (rc < 0 || s->ws.closed || ctx.send_failed) broken = 1;
        }
        if (broken) {
            char id[PREVIEW_WS_ID_CAP];
            snprintf(id, sizeof id, "%s", s->id);
            int code = s->ws.have_close ? (int)s->ws.close_code : 1000;
            char reason[160] = "";
            if (s->ws.have_close && s->ws.close_reason[0])
                snprintf(reason, sizeof reason, "%s", s->ws.close_reason);
            else if (s->ws.err[0])
                snprintf(reason, sizeof reason, "%s", s->ws.err);
            // Flush auto-PONG or CLOSE reply best-effort before closing.
            if (ws_want_write(&s->ws)) (void)ws_io_out(&s->ws);
            free_stream(s, 0, code);
            emit_close(r, id, code, reason);
        }
    }
}

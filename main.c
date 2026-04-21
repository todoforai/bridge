// TODOforAI Bridge — C runtime. TCP → WebSocket → Noise_NX → PTY relay.
//
// Protocol (inside Noise transport):
//   First encrypted msg (edge→server):
//     {"type":"auth","deviceId":"dev_...","secret":"..."}
//   Then existing v2 control messages (JSON):
//     → {"type":"identity","data":{...}}
//     ← {"type":"exec","todoId":"uuid","blockId":"..."}
//     ← {"type":"input","todoId":"uuid","blockId":"...","data":"base64"}
//     ← {"type":"resize","todoId":"uuid","rows":N,"cols":N}
//     ← {"type":"signal","todoId":"uuid","sig":N}
//     ← {"type":"kill","todoId":"uuid"}
//     → {"type":"output","todoId":"uuid","blockId":"...","data":"base64"}
//     → {"type":"exit","todoId":"uuid","blockId":"...","code":N}
//     ↔ {"type":"error","todoId":"uuid","blockId":"...","code":"ERR","message":"..."}

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "args.h"      // ketopt + cli_usage helpers
#include "conn.h"
#include "identity.h"  // BRIDGE_VERSION
#include "json.h"
#include "pty.h"
#include "update.h"
#include "util.h"

#define LOGIN_IMPLEMENTATION
#include "login.h"

// ── Defaults ────────────────────────────────────────────────────────────────

#define DEFAULT_HOST         "api.todofor.ai"
// Plain HTTP port — bridge has no TLS client; Noise provides end-to-end crypto.
#define DEFAULT_PORT         80
#define DEFAULT_PATH         "/ws/v2/bridge"
#define DEFAULT_PATH_SANDBOX "/ws/v2/bridge?deviceType=SANDBOX"
#define DEFAULT_SHELL        "/bin/sh"
#define BUF_SIZE             4096
#define MAX_SESSIONS         16
#define TODO_ID_LEN          36
#define BLOCK_ID_CAP         64
#define MAX_MSG              (64 * 1024)

// Server's Noise static public key (X25519, 32 bytes hex = 64 chars).
// Overridable via EDGE_SERVER_PUBKEY env or --server-pubkey flag.
// Same key used by sandbox-manager / browser-manager CLIs on port 4100 —
// backend uses NOISE_LOCAL_PRIVATE_KEY for both the TCP RPC server and the
// bridge WS handler.
#define DEFAULT_SERVER_PUBKEY_HEX \
    "88e38a377ee697b448ec2779b625049110e05f77587a135df45994062b6bb76a"

// ── Session ─────────────────────────────────────────────────────────────────

typedef struct {
    int active;
    char todo_id[TODO_ID_LEN + 1];
    char block_id[BLOCK_ID_CAP + 1];
    size_t block_id_len;
    bridge_pty_t pty;
} session_t;

typedef struct {
    bridge_conn_t *conn;
    session_t sessions[MAX_SESSIONS];

    uint8_t  pty_buf[BUF_SIZE];
    char     b64_buf[BUF_SIZE * 2];
    uint8_t  msg_buf[MAX_MSG];
} edge_t;

// ── Helpers ─────────────────────────────────────────────────────────────────

static int is_valid_uuid(const char *s, size_t len) {
    if (len != 36) return 0;
    for (size_t i = 0; i < 36; i++) {
        char c = s[i];
        int is_dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (is_dash) { if (c != '-') return 0; }
        else if (!isxdigit((unsigned char)c)) return 0;
    }
    return 1;
}

static session_t *find_session(edge_t *e, const char *tid, size_t tid_len) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &e->sessions[i];
        if (s->active && strlen(s->todo_id) == tid_len &&
            memcmp(s->todo_id, tid, tid_len) == 0) {
            return s;
        }
    }
    return NULL;
}

static session_t *free_slot(edge_t *e) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!e->sessions[i].active) return &e->sessions[i];
    }
    return NULL;
}

static void set_block_id(session_t *s, const char *id, size_t id_len) {
    if (!id) return;
    size_t n = id_len < BLOCK_ID_CAP ? id_len : BLOCK_ID_CAP;
    memcpy(s->block_id, id, n);
    s->block_id[n] = '\0';
    s->block_id_len = n;
}

static int send_json(edge_t *e, const char *s, size_t n) {
    return bridge_conn_send(e->conn, (const uint8_t *)s, n);
}

static int send_error(edge_t *e,
                      const char *tid, size_t tid_len,
                      const char *bid, size_t bid_len,
                      const char *code, const char *message) {
    char buf[512];
    int n;
    if (tid && bid) {
        n = snprintf(buf, sizeof(buf),
            "{\"type\":\"error\",\"todoId\":\"%.*s\",\"blockId\":\"%.*s\","
            "\"code\":\"%s\",\"message\":\"%s\"}",
            (int)tid_len, tid, (int)bid_len, bid, code, message);
    } else if (tid) {
        n = snprintf(buf, sizeof(buf),
            "{\"type\":\"error\",\"todoId\":\"%.*s\","
            "\"code\":\"%s\",\"message\":\"%s\"}",
            (int)tid_len, tid, code, message);
    } else {
        n = snprintf(buf, sizeof(buf),
            "{\"type\":\"error\",\"code\":\"%s\",\"message\":\"%s\"}",
            code, message);
    }
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
    fprintf(stderr, "error %s: %s\n", code, message);
    return 0;
}

static void send_exit(edge_t *e, session_t *s, int code) {
    char buf[256];
    int n;
    if (s->block_id_len > 0) {
        n = snprintf(buf, sizeof(buf),
            "{\"type\":\"exit\",\"todoId\":\"%s\",\"blockId\":\"%s\",\"code\":%d}",
            s->todo_id, s->block_id, code);
    } else {
        n = snprintf(buf, sizeof(buf),
            "{\"type\":\"exit\",\"todoId\":\"%s\",\"code\":%d}",
            s->todo_id, code);
    }
    if (n > 0 && (size_t)n < sizeof(buf)) send_json(e, buf, (size_t)n);
    fprintf(stderr, "PTY exited: %s code=%d\n", s->todo_id, code);
}

static void forward_pty_output(edge_t *e, session_t *s) {
    long n = bridge_pty_read(&s->pty, e->pty_buf, sizeof(e->pty_buf));
    if (n <= 0) return;

    size_t bn = b64_encode(e->pty_buf, (size_t)n, e->b64_buf);

    size_t cap = bn + 256;
    char *msg = malloc(cap);
    if (!msg) return;
    int mn;
    if (s->block_id_len > 0) {
        mn = snprintf(msg, cap,
            "{\"type\":\"output\",\"todoId\":\"%s\",\"blockId\":\"%s\",\"data\":\"%.*s\"}",
            s->todo_id, s->block_id, (int)bn, e->b64_buf);
    } else {
        mn = snprintf(msg, cap,
            "{\"type\":\"output\",\"todoId\":\"%s\",\"data\":\"%.*s\"}",
            s->todo_id, (int)bn, e->b64_buf);
    }
    if (mn > 0 && (size_t)mn < cap) send_json(e, msg, (size_t)mn);
    free(msg);
}

// ── Command dispatch ────────────────────────────────────────────────────────

static int handle_command(edge_t *e, const char *msg, size_t msg_len) {
    const char *type = NULL; size_t type_len = 0;
    if (!json_str(msg, msg_len, "type", &type, &type_len)) return 0;

    const char *tid = NULL; size_t tid_len = 0;
    int has_tid = json_str(msg, msg_len, "todoId", &tid, &tid_len);

    const char *bid = NULL; size_t bid_len = 0;
    int has_bid = json_str(msg, msg_len, "blockId", &bid, &bid_len);

    #define IS(s) (type_len == sizeof(s) - 1 && memcmp(type, s, sizeof(s) - 1) == 0)

    if (IS("exec")) {
        if (!has_tid)
            return send_error(e, NULL, 0, NULL, 0, "MISSING_TODO_ID", "exec requires todoId");
        if (!is_valid_uuid(tid, tid_len))
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "INVALID_TODO_ID", "todoId must be a valid UUID");
        if (find_session(e, tid, tid_len))
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "SESSION_EXISTS", "session already exists");
        session_t *slot = free_slot(e);
        if (!slot)
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "MAX_SESSIONS", "max 16 concurrent sessions");
        if (bridge_pty_spawn(&slot->pty, DEFAULT_SHELL) != 0)
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "SPAWN_FAILED", "failed to spawn PTY");
        slot->active = 1;
        memcpy(slot->todo_id, tid, TODO_ID_LEN);
        slot->todo_id[TODO_ID_LEN] = '\0';
        slot->block_id_len = 0;
        slot->block_id[0] = '\0';
        if (has_bid) set_block_id(slot, bid, bid_len);
        fprintf(stderr, "PTY spawned for %s\n", slot->todo_id);

    } else if (IS("input")) {
        if (!has_tid)
            return send_error(e, NULL, 0, NULL, 0, "MISSING_TODO_ID", "input requires todoId");
        session_t *s = find_session(e, tid, tid_len);
        if (!s)
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "SESSION_NOT_FOUND", "no session for todoId");
        if (has_bid) set_block_id(s, bid, bid_len);

        const char *b64 = NULL; size_t b64_len = 0;
        if (!json_str(msg, msg_len, "data", &b64, &b64_len))
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "MISSING_DATA", "input requires data");

        if (b64_len / 4 * 3 > BUF_SIZE)
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "INPUT_TOO_LARGE", "input exceeds 4096 bytes");

        uint8_t decoded[BUF_SIZE + 4];
        long dec_len = b64_decode(b64, b64_len, decoded);
        if (dec_len < 0)
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "INVALID_BASE64", "data is not valid base64");

        if (bridge_pty_write_all(&s->pty, decoded, (size_t)dec_len) != 0) {
            fprintf(stderr, "PTY write error\n");
        }

    } else if (IS("resize")) {
        if (!has_tid) return 0;
        session_t *s = find_session(e, tid, tid_len);
        if (!s) return 0;
        long rows = 24, cols = 80;
        json_int(msg, msg_len, "rows", &rows);
        json_int(msg, msg_len, "cols", &cols);
        bridge_pty_resize(&s->pty, (uint16_t)rows, (uint16_t)cols);

    } else if (IS("signal")) {
        if (!has_tid) return 0;
        session_t *s = find_session(e, tid, tid_len);
        if (!s) return 0;
        long sig = 0;
        if (!json_int(msg, msg_len, "sig", &sig))
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "MISSING_SIG", "signal requires sig");
        if (!bridge_pty_signal(&s->pty, (int)sig))
            return send_error(e, tid, tid_len, has_bid ? bid : NULL, bid_len,
                              "SIGNAL_NOT_ALLOWED", "signal not in whitelist");

    } else if (IS("kill")) {
        if (!has_tid) return 0;
        for (int i = 0; i < MAX_SESSIONS; i++) {
            session_t *s = &e->sessions[i];
            if (s->active && strlen(s->todo_id) == tid_len &&
                memcmp(s->todo_id, tid, tid_len) == 0) {
                bridge_pty_close(&s->pty);
                s->active = 0;
                fprintf(stderr, "Session killed: %s\n", s->todo_id);
                break;
            }
        }
    }

    #undef IS
    return 0;
}

// ── Main loop ───────────────────────────────────────────────────────────────

static int run(edge_t *e, const char *device_id, const char *device_secret) {
    // Auth: first encrypted message carries the device credentials
    char auth[1024];
    int an = snprintf(auth, sizeof(auth),
                      "{\"type\":\"auth\",\"deviceId\":\"%s\",\"secret\":\"%s\"}",
                      device_id, device_secret);
    if (an < 0 || (size_t)an >= sizeof(auth)) return -1;
    if (send_json(e, auth, (size_t)an) != 0) return -1;

    // Identity
    char id_json[1024];
    int id_len = bridge_identity_json(id_json, sizeof(id_json));
    if (id_len < 0) return -1;
    if (send_json(e, id_json, (size_t)id_len) != 0) return -1;
    fprintf(stderr, "Identified\n");

    for (;;) {
        for (int i = 0; i < MAX_SESSIONS; i++) {
            session_t *s = &e->sessions[i];
            if (!s->active) continue;
            int code;
            if (bridge_pty_reap(&s->pty, &code)) {
                send_exit(e, s, code);
                bridge_pty_close(&s->pty);
                s->active = 0;
            }
        }

        struct pollfd fds[1 + MAX_SESSIONS];
        int session_idx[MAX_SESSIONS];
        fds[0].fd = bridge_conn_fd(e->conn);
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        nfds_t nfds = 1;
        for (int i = 0; i < MAX_SESSIONS; i++) {
            session_t *s = &e->sessions[i];
            if (!s->active) continue;
            fds[nfds].fd = s->pty.master_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            session_idx[nfds - 1] = i;
            nfds++;
        }

        int pr = poll(fds, nfds, 100);
        if (pr < 0) { if (errno == EINTR) continue; return -1; }

        if (fds[0].revents & (POLLERR | POLLHUP)) return -1;
        if (fds[0].revents & POLLIN) {
            long n = bridge_conn_recv(e->conn, e->msg_buf, sizeof(e->msg_buf));
            if (n <= 0) return -1;
            (void)handle_command(e, (const char *)e->msg_buf, (size_t)n);
        }

        for (nfds_t k = 1; k < nfds; k++) {
            session_t *s = &e->sessions[session_idx[k - 1]];
            if (!s->active) continue;
            if (fds[k].revents & POLLIN) forward_pty_output(e, s);
            if (fds[k].revents & (POLLHUP | POLLERR)) {
                int code = bridge_pty_close(&s->pty);
                send_exit(e, s, code);
                s->active = 0;
            }
        }
    }
}

// ── Args / env ──────────────────────────────────────────────────────────────

static const char *USAGE_MAIN   = "[--host HOST] [--port PORT] [--server-pubkey HEX]";
static const char *USAGE_LOGIN  = "login [--device-name NAME] [--token TOKEN]";
static const char *USAGE_ENROLL = "enroll [--ttl SECONDS] [--device-name NAME] [--quiet]";

static int read_cmdline_token(char *out, size_t cap) {
    int fd = open("/proc/cmdline", O_RDONLY);
    if (fd < 0) return -1;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    const char *needle = "edge.token=";
    const char *p = strstr(buf, needle);
    if (!p) return -1;
    p += strlen(needle);
    size_t i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\n' && i < cap - 1) {
        out[i] = p[i]; i++;
    }
    if (i == 0) return -1;
    out[i] = '\0';
    return 0;
}

static int parse_pubkey_hex(const char *hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

// ── Noise one-shot RPC helper (reuses transport code from login.h) ──────────

// Resolve backend Noise addr + pubkey from env, with sensible defaults.
static void enroll_backend(const char **addr, const char **pub) {
    *addr = getenv("NOISE_BACKEND_ADDR");
    *pub  = getenv("NOISE_BACKEND_PUBLIC_KEY");
    if (!*addr) *addr = "api.todofor.ai:4100";
    if (!*pub)  *pub  = "88e38a377ee697b448ec2779b625049110e05f77587a135df45994062b6bb76a";
}

// Connect, handshake, send one encrypted JSON request, return decrypted reply.
// Returns response length (>= 0) or -1 on error. Writes NUL-terminated JSON
// into resp_buf (truncated to resp_cap-1 if needed).
static int noise_oneshot(const char *backend_addr, const char *backend_pub,
                         const char *req, size_t req_len,
                         char *resp_buf, size_t resp_cap) {
    login_sock_init();

    uint8_t remote_pub[32];
    if (login_hex_decode(remote_pub, 32, backend_pub) < 0) return -1;

    char host[256], port_str[16];
    const char *colon = strrchr(backend_addr, ':');
    if (!colon) return -1;
    size_t hlen = (size_t)(colon - backend_addr);
    if (hlen >= sizeof(host)) return -1;
    memcpy(host, backend_addr, hlen);
    host[hlen] = '\0';
    snprintf(port_str, sizeof(port_str), "%s", colon + 1);

    login_session_t session;
    if (login_noise_connect(&session, host, port_str, remote_pub) < 0) return -1;

    uint8_t *dec = NULL;
    int dec_len = login_noise_rpc(session.fd, &session.transport, req, req_len, &dec);
    login_sock_close(session.fd);
    if (dec_len < 0) { if (dec) free(dec); return -1; }

    size_t copy = (size_t)dec_len < resp_cap - 1 ? (size_t)dec_len : resp_cap - 1;
    memcpy(resp_buf, dec, copy);
    resp_buf[copy] = '\0';
    free(dec);
    return (int)copy;
}

// Parse device creds out of a successful enroll.redeem / login.poll response.
// Looks for the nested "device":{"id":...,"secret":...,"name":...} object.
static int parse_device_creds(const char *resp, login_credentials_t *creds) {
    memset(creds, 0, sizeof(*creds));
    const char *dev = strstr(resp, "\"device\"");
    if (!dev) return -1;
    dev = strchr(dev, '{');
    if (!dev) return -1;
    json_find_string(dev, "id",     creds->device_id,     sizeof(creds->device_id));
    json_find_string(dev, "secret", creds->device_secret, sizeof(creds->device_secret));
    json_find_string(dev, "name",   creds->device_name,   sizeof(creds->device_name));
    json_find_string(resp, "browserManagerNoiseAddr",      creds->browser_manager_noise_addr,       sizeof(creds->browser_manager_noise_addr));
    json_find_string(resp, "browserManagerNoisePublicKey", creds->browser_manager_noise_public_key, sizeof(creds->browser_manager_noise_public_key));
    json_find_string(resp, "sandboxManagerNoiseAddr",      creds->sandbox_manager_noise_addr,       sizeof(creds->sandbox_manager_noise_addr));
    json_find_string(resp, "sandboxManagerNoisePublicKey", creds->sandbox_manager_noise_public_key, sizeof(creds->sandbox_manager_noise_public_key));
    return (creds->device_id[0] && creds->device_secret[0]) ? 0 : -1;
}

// Redeem an enrollment token for fresh device credentials and save them.
static int redeem_enroll_token(const char *token, const char *device_name) {
    const char *addr, *pub;
    enroll_backend(&addr, &pub);

    uint8_t id_bytes[4]; char id_hex[9];
    noise_random(id_bytes, 4);
    login_hex_encode(id_hex, id_bytes, 4);

    char req[1024];
    int n;
    if (device_name && *device_name) {
        char name_esc[256];
        if (json_escape_buf(name_esc, sizeof(name_esc), device_name) != 0) {
            fprintf(stderr, "error: device name too long\n"); return -1;
        }
        n = snprintf(req, sizeof(req),
            "{\"id\":\"%s\",\"type\":\"cli.enroll.redeem\","
            "\"payload\":{\"token\":\"%s\",\"deviceName\":\"%s\"}}",
            id_hex, token, name_esc);
    } else {
        n = snprintf(req, sizeof(req),
            "{\"id\":\"%s\",\"type\":\"cli.enroll.redeem\","
            "\"payload\":{\"token\":\"%s\"}}",
            id_hex, token);
    }
    if (n < 0 || (size_t)n >= sizeof(req)) { fprintf(stderr, "error: token too long\n"); return -1; }

    char resp[LOGIN_CONFIG_MAX];
    int rn = noise_oneshot(addr, pub, req, (size_t)n, resp, sizeof(resp));
    if (rn < 0) { fprintf(stderr, "error: enroll redeem request failed\n"); return -1; }

    if (json_envelope_is_error(resp)) {
        char err_msg[256];
        json_find_string(resp, "message", err_msg, sizeof(err_msg));
        fprintf(stderr, "error: %s\n", err_msg[0] ? err_msg : resp);
        return -1;
    }

    login_credentials_t creds;
    if (parse_device_creds(resp, &creds) < 0) {
        fprintf(stderr, "error: unexpected response: %s\n", resp);
        return -1;
    }
    if (login_save_credentials(&creds) < 0) {
        fprintf(stderr, "error: failed to save credentials\n");
        return -1;
    }
    char path[1024];
    login_config_path(path, sizeof(path));
    fprintf(stderr, "\033[32m\xe2\x9c\x85 Enrolled as %s (device %s). Credentials saved to %s\033[0m\n",
            creds.device_name, creds.device_id, path);
    return 0;
}

// ── login subcommand ────────────────────────────────────────────────────────

static int cmd_login(int argc, char **argv) {
    const char *device_name = NULL;
    const char *token       = NULL;
    ko_longopt_t longopts[] = {
        { "help",        ko_no_argument,       'h' },
        { "device-name", ko_required_argument, 'n' },
        { "token",       ko_required_argument, 't' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hn:t:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "bridge", USAGE_LOGIN); return 0; }
        else if (c == 'n') device_name = opt.arg;
        else if (c == 't') token = opt.arg;
        else cli_parse_error("bridge", USAGE_LOGIN, argc, argv, &opt, c);
    }
    if (!device_name) device_name = getenv("EDGE_DEVICE_NAME");
    if (!token)       token       = getenv("EDGE_ENROLL_TOKEN");

    // Non-interactive path: redeem an enrollment token minted by another bridge
    // (or by the backend via `cli.enroll.mint` / REST). No browser, no polling.
    if (token && *token) {
        return redeem_enroll_token(token, device_name) == 0 ? 0 : 1;
    }

    const char *addr, *pub;
    enroll_backend(&addr, &pub);
    return login_device_flow(addr, pub, "bridge", device_name) == 0 ? 0 : 1;
}

// ── enroll subcommand ───────────────────────────────────────────────────────

static int cmd_enroll(int argc, char **argv) {
    long ttl_sec = 300;
    const char *device_name = NULL;
    int quiet = 0;
    ko_longopt_t longopts[] = {
        { "help",        ko_no_argument,       'h' },
        { "ttl",         ko_required_argument, 'T' },
        { "device-name", ko_required_argument, 'n' },
        { "quiet",       ko_no_argument,       'q' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hT:n:q", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "bridge", USAGE_ENROLL); return 0; }
        else if (c == 'T') ttl_sec = atol(opt.arg);
        else if (c == 'n') device_name = opt.arg;
        else if (c == 'q') quiet = 1;
        else cli_parse_error("bridge", USAGE_ENROLL, argc, argv, &opt, c);
    }

    // Must have device creds on disk — only a logged-in bridge can mint.
    login_credentials_t creds;
    memset(&creds, 0, sizeof(creds));
    if (login_load_credentials(&creds) < 0 || !creds.device_id[0] || !creds.device_secret[0]) {
        fprintf(stderr, "error: no device credentials found. Run `bridge login` first.\n");
        return 1;
    }

    const char *addr, *pub;
    enroll_backend(&addr, &pub);

    uint8_t id_bytes[4]; char id_hex[9];
    noise_random(id_bytes, 4);
    login_hex_encode(id_hex, id_bytes, 4);

    char req[1024];
    int n = snprintf(req, sizeof(req),
        "{\"id\":\"%s\",\"type\":\"cli.enroll.mint\","
        "\"payload\":{\"deviceId\":\"%s\",\"secret\":\"%s\",\"ttlSec\":%ld}}",
        id_hex, creds.device_id, creds.device_secret, ttl_sec);
    if (n < 0 || (size_t)n >= sizeof(req)) { fprintf(stderr, "error: request too long\n"); return 1; }

    char resp[LOGIN_CONFIG_MAX];
    int rn = noise_oneshot(addr, pub, req, (size_t)n, resp, sizeof(resp));
    if (rn < 0) { fprintf(stderr, "error: mint request failed\n"); return 1; }

    if (json_envelope_is_error(resp)) {
        char err_msg[256];
        json_find_string(resp, "message", err_msg, sizeof(err_msg));
        fprintf(stderr, "error: %s\n", err_msg[0] ? err_msg : resp);
        return 1;
    }

    char token[256], expires[32];
    json_find_string(resp, "token",     token,   sizeof(token));
    json_find_string(resp, "expiresIn", expires, sizeof(expires));
    if (!token[0]) { fprintf(stderr, "error: no token in response: %s\n", resp); return 1; }

    if (quiet) {
        // Script-friendly: just the token on stdout.
        printf("%s\n", token);
    } else {
        fprintf(stderr, "\033[1m\xf0\x9f\x94\x91 Enrollment token (expires in %s s):\033[0m\n", expires[0] ? expires : "?");
        printf("%s\n", token);
        fprintf(stderr, "\n\033[2mRun on the new host:\033[0m\n");
        fprintf(stderr, "  bridge login --token %s%s%s\n",
                token,
                device_name ? " --device-name " : "",
                device_name ? device_name : "");
    }
    return 0;
}

// ── main ────────────────────────────────────────────────────────────────────

static void print_help(void) {
    printf("bridge " BRIDGE_VERSION " — TODOforAI edge agent\n\n"
           "Usage:\n"
           "  bridge %s\n"
           "  bridge %s\n"
           "  bridge %s\n"
           "  bridge --version | -v\n"
           "  bridge --help    | -h\n\n"
           "Env: EDGE_HOST, EDGE_PORT, EDGE_SERVER_PUBKEY, EDGE_DEVICE_NAME\n",
           USAGE_MAIN, USAGE_LOGIN, USAGE_ENROLL);
}

int main(int argc, char **argv) {
    // If a new binary was staged next to us (by a prior `exec` update command),
    // swap it in before we do anything else. See update.h.
    bridge_update_swap_on_start(argv[0]);

    // Subcommand dispatch (must come before option parsing so `bridge login -h`
    // shows the login-specific usage).
    if (argc >= 2 && strcmp(argv[1], "login") == 0) {
        return cmd_login(argc - 1, argv + 1);
    }
    if (argc >= 2 && strcmp(argv[1], "enroll") == 0) {
        return cmd_enroll(argc - 1, argv + 1);
    }

    const char *host = NULL, *port_s = NULL, *pubkey_hex = NULL;
    ko_longopt_t longopts[] = {
        { "help",          ko_no_argument,       'h' },
        { "version",       ko_no_argument,       'v' },
        { "host",          ko_required_argument, 'H' },
        { "port",          ko_required_argument, 'p' },
        { "server-pubkey", ko_required_argument, 'k' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hvH:p:k:", longopts)) >= 0) {
        if      (c == 'h') { print_help(); return 0; }
        else if (c == 'v') { printf("%s\n", BRIDGE_VERSION); return 0; }
        else if (c == 'H') host = opt.arg;
        else if (c == 'p') port_s = opt.arg;
        else if (c == 'k') pubkey_hex = opt.arg;
        else cli_parse_error("bridge", USAGE_MAIN, argc, argv, &opt, c);
    }

    // Load saved device credentials from `bridge login`
    login_credentials_t saved_creds;
    memset(&saved_creds, 0, sizeof(saved_creds));
    (void)login_load_credentials(&saved_creds);

    if (!saved_creds.device_id[0] || !saved_creds.device_secret[0]) {
        fprintf(stderr, "No device credentials found. Run `bridge login [--device-name NAME]` first.\n\n");
        print_help();
        return 1;
    }

    if (!host) host = getenv("EDGE_HOST");
    if (!host) host = DEFAULT_HOST;

    if (!port_s) port_s = getenv("EDGE_PORT");
    uint16_t port = DEFAULT_PORT;
    if (port_s) {
        int p = atoi(port_s);
        if (p > 0 && p <= 65535) port = (uint16_t)p;
    }

    if (!pubkey_hex) pubkey_hex = getenv("EDGE_SERVER_PUBKEY");
    if (!pubkey_hex) pubkey_hex = DEFAULT_SERVER_PUBKEY_HEX;

    uint8_t server_pubkey[32];
    if (parse_pubkey_hex(pubkey_hex, server_pubkey) != 0) {
        fprintf(stderr, "invalid server pubkey (need 64 hex chars)\n");
        return 1;
    }

    // /proc/cmdline fallback (for kernel-driven sandbox boot) routes to sandbox path.
    char cmdline_tok[512];
    int from_cmdline = (read_cmdline_token(cmdline_tok, sizeof(cmdline_tok)) == 0);
    (void)cmdline_tok; // cmdline token path is obsolete — device credentials are used instead
    const char *path = from_cmdline ? DEFAULT_PATH_SANDBOX : DEFAULT_PATH;

    fprintf(stderr, "Connecting to %s:%u (noise) as device %s...\n", host, (unsigned)port, saved_creds.device_id);

    bridge_conn_t *conn = bridge_conn_open(host, port, path, server_pubkey);
    if (!conn) { fprintf(stderr, "connect failed\n"); return 1; }
    fprintf(stderr, "Connected\n");

    edge_t *e = calloc(1, sizeof(*e));
    if (!e) { bridge_conn_close(conn); return 1; }
    e->conn = conn;

    int rc = run(e, saved_creds.device_id, saved_creds.device_secret);

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (e->sessions[i].active) bridge_pty_close(&e->sessions[i].pty);
    }
    bridge_conn_close(conn);
    free(e);

    if (rc != 0) fprintf(stderr, "Disconnected\n");
    return rc == 0 ? 0 : 1;
}

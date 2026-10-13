// CLI subcommands: login / logout / enroll / whoami / help.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "subcmd.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "args.h"
#include "identity.h"
#include "noise.h"

#define LOGIN_IMPLEMENTATION
#include "login.h"

// --host / --port / --ttl are dev flags, parsed but omitted from help.
const char *USAGE_MAIN = "";

static void resolve_backend_addr(const char *host, const char *port_s,
                                 char *addr_buf, size_t addr_cap) {
    // Precedence: --host flag → saved profile creds → env → prod default.
    login_credentials_t saved;
    (void)login_load_credentials(&saved);
    if (!host && saved.backend_host[0]) host = saved.backend_host;

    if (!host)   host   = getenv("NOISE_BACKEND_HOST");
    if (!port_s) port_s = getenv("NOISE_BACKEND_PORT");

    if (!host) host = LOGIN_DEFAULT_BACKEND_HOST;
    if (!port_s) {
        port_s = login_is_local_host(host) ? LOGIN_DEV_NOISE_PORT : LOGIN_DEFAULT_NOISE_PORT;
        fprintf(stderr, "[bridge] no port specified for host=%s, defaulting to %s (set NOISE_BACKEND_PORT or --port to override)\n", host, port_s);
    }
    snprintf(addr_buf, addr_cap, "%s:%s", host, port_s);
}

// Extract nested "device":{...} and optional "user":{...} from a response.
static int parse_device_creds(const char *resp, login_credentials_t *creds) {
    memset(creds, 0, sizeof(*creds));
    const char *dev = strstr(resp, "\"device\"");
    if (!dev) return -1;
    dev = strchr(dev, '{');
    if (!dev) return -1;
    json_find_string(dev, "id",     creds->device_id,     sizeof(creds->device_id));
    json_find_string(dev, "secret", creds->device_secret, sizeof(creds->device_secret));
    json_find_string(dev, "name",   creds->device_name,   sizeof(creds->device_name));
    // Top-level apiToken (dst_…): a ready-to-use device-session token so
    // credentials.json is complete before the daemon reconnects. Optional —
    // older backends omit it and the daemon fills it in via subagent_token.
    json_find_string(resp, "apiToken", creds->api_token, sizeof(creds->api_token));
    const char *usr = strstr(resp, "\"user\"");
    if (usr && (usr = strchr(usr, '{'))) {
        json_find_string(usr, "id",    creds->user_id,    sizeof(creds->user_id));
        json_find_string(usr, "email", creds->user_email, sizeof(creds->user_email));
        json_find_string(usr, "name",  creds->user_name,  sizeof(creds->user_name));
    }
    return (creds->device_id[0] && creds->device_secret[0]) ? 0 : -1;
}

// Redeem an enrollment token for device credentials and save them.
// Backend pubkey is learned via TOFU on the handshake and persisted with creds.
static int redeem_enroll_token(const char *token, const char *device_name,
                               const char *host, const char *port_s) {
    char addr_buf[280];
    resolve_backend_addr(host, port_s, addr_buf, sizeof(addr_buf));

    uint8_t id_bytes[4]; char id_hex[9];
    noise_random(id_bytes, 4);
    login_hex_encode(id_hex, id_bytes, 4);

    char identity[1024];
    int ilen = bridge_identity_json(identity, sizeof(identity), 1);
    if (ilen < 0) { fprintf(stderr, "error: failed to gather identity\n"); return -1; }

    char name_field[300] = "";
    if (device_name && *device_name) {
        // Device name doubles as the agent's tool-call alias suffix
        // (`bash_<name>`), so it must be a clean identifier: letters, digits
        // and `_` only (no `-`), starting alphanumeric, max 64. Reject here
        // for a clear message instead of letting the backend 400.
        size_t dlen = strlen(device_name);
        if (dlen > 64 || !isalnum((unsigned char)device_name[0])) {
            fprintf(stderr, "error: device name must start with a letter or number and be <=64 chars\n"); return -1;
        }
        for (size_t i = 0; i < dlen; i++) {
            char c = device_name[i];
            if (!isalnum((unsigned char)c) && c != '_') {
                fprintf(stderr, "error: device name can only contain letters, numbers and underscores\n"); return -1;
            }
        }
        char name_esc[256];
        if (json_escape_buf(name_esc, sizeof(name_esc), device_name) != 0) {
            fprintf(stderr, "error: device name too long\n"); return -1;
        }
        snprintf(name_field, sizeof(name_field), ",\"deviceName\":\"%s\"", name_esc);
    }

    char req[2048];
    int n = snprintf(req, sizeof(req),
        "{\"id\":\"%s\",\"type\":\"cli.enroll.redeem\","
        "\"payload\":{\"token\":\"%s\"%s,\"identity\":%s}}",
        id_hex, token, name_field, identity);
    if (n < 0 || (size_t)n >= sizeof(req)) { fprintf(stderr, "error: payload too long\n"); return -1; }

    char resp[LOGIN_CONFIG_MAX];
    char learned_pub[65] = {0};
    int rn = login_oneshot_rpc(addr_buf, NULL, req, (size_t)n, resp, sizeof(resp), learned_pub);
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

    // Persist backend host + TOFU pubkey so the daemon reconnects without flags.
    const char *bcolon = strrchr(addr_buf, ':');
    size_t bhlen = bcolon ? (size_t)(bcolon - addr_buf) : strlen(addr_buf);
    if (bhlen >= sizeof(creds.backend_host)) bhlen = sizeof(creds.backend_host) - 1;
    memcpy(creds.backend_host, addr_buf, bhlen);
    creds.backend_host[bhlen] = '\0';
    snprintf(creds.backend_pubkey, sizeof(creds.backend_pubkey), "%s", learned_pub);

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

int bridge_login_run(const char *device_name, const char *token,
                     const char *host, const char *port_s) {
    // Already logged in? Reuse — `logout` first to switch user/device.
    login_credentials_t existing;
    memset(&existing, 0, sizeof(existing));
    if (login_load_credentials(&existing) == 0
        && existing.device_id[0] && existing.device_secret[0]) {
        const char *who = existing.user_email[0] ? existing.user_email
                        : existing.user_name[0]  ? existing.user_name
                        : "(unknown user)";
        fprintf(stderr,
            "\033[33mAlready logged in as %s (device %s). Reusing existing credentials.\033[0m\n"
            "Run `todoforai-bridge logout` first to switch user/device.\n",
            who, existing.device_id);
        return 0;
    }

    // Token: non-interactive (sandbox /init, scripted installs).
    // No token: interactive device-code flow + browser.
    if (token && *token) {
        return redeem_enroll_token(token, device_name, host, port_s) == 0 ? 0 : 1;
    }
    char addr_buf[280];
    resolve_backend_addr(host, port_s, addr_buf, sizeof(addr_buf));
    // Send identity (incl. machine_id) so the backend dedupes by stable host
    // id — same path as enroll redeem. Without this, logout+login on the same
    // PC mints a fresh Device row every time. Best-effort: if gathering fails
    // (e.g. truncation on weird hosts), log in without it — backend just falls
    // back to create-new, same as old bridges.
    char identity[1024];
    const char *identity_arg = bridge_identity_json(identity, sizeof(identity), 1) >= 0
                                 ? identity : NULL;
    return login_device_flow(addr_buf, "bridge", device_name, identity_arg) == 0 ? 0 : 1;
}

int cmd_login(int argc, char **argv) {
    // Note: --profile is intentionally undocumented (advanced/dev multi-account).
    static const char *USAGE = "login [--device-name NAME] [--token TOKEN] [--no-browser]";
    const char *device_name = NULL;
    const char *token       = NULL;
    const char *host        = NULL;
    const char *port_s      = NULL;
    const char *profile     = NULL;
    ko_longopt_t longopts[] = {
        { "help",          ko_no_argument,       'h' },
        { "device-name",   ko_required_argument, 'n' },
        { "token",         ko_required_argument, 't' },
        { "host",          ko_required_argument, 'H' },
        { "port",          ko_required_argument, 'p' },
        { "profile",       ko_required_argument, 'P' },
        { "no-browser",    ko_no_argument,       'B' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hn:t:H:p:P:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE); return CMD_RC_HELP; }
        else if (c == 'B') login_set_open_browser(0);
        else if (c == 'n') device_name = opt.arg;
        else if (c == 't') token = opt.arg;
        else if (c == 'H') host = opt.arg;
        else if (c == 'p') port_s = opt.arg;
        else if (c == 'P') profile = opt.arg;
        else cli_parse_error("todoforai-bridge", USAGE, argc, argv, &opt, c);
    }
    // Mirror the daemon: a local --host with no explicit --profile logs into
    // the "dev" profile so dev creds land in the same place the daemon reads.
    if (!profile && login_is_local_host(host)) profile = "dev";
    if (profile && login_set_profile(profile) < 0) return 2;
    return bridge_login_run(device_name, token, host, port_s);
}

// ── enroll subcommand ───────────────────────────────────────────────────────

int cmd_enroll(int argc, char **argv) {
    static const char *USAGE = "enroll";
    long ttl_sec = 300;
    const char *host    = NULL;
    const char *port_s  = NULL;
    ko_longopt_t longopts[] = {
        { "help",          ko_no_argument,       'h' },
        { "ttl",           ko_required_argument, 'T' },
        { "host",          ko_required_argument, 'H' },
        { "port",          ko_required_argument, 'p' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hT:H:p:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE); return 0; }
        else if (c == 'T') ttl_sec = atol(opt.arg);
        else if (c == 'H') host = opt.arg;
        else if (c == 'p') port_s = opt.arg;
        else cli_parse_error("todoforai-bridge", USAGE, argc, argv, &opt, c);
    }

    // Only a logged-in bridge can mint enrollment tokens.
    login_credentials_t creds;
    memset(&creds, 0, sizeof(creds));
    if (login_load_credentials(&creds) < 0 || !creds.device_id[0] || !creds.device_secret[0]) {
        fprintf(stderr, "error: no device credentials found. Run `todoforai-bridge login` first.\n");
        return 1;
    }
    if (!creds.backend_pubkey[0]) {
        fprintf(stderr, "error: credentials are missing backend pubkey. Run `todoforai-bridge logout && todoforai-bridge login` to refresh.\n");
        return 1;
    }

    char addr_buf[280];
    resolve_backend_addr(host, port_s, addr_buf, sizeof(addr_buf));

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
    int rn = login_oneshot_rpc(addr_buf, creds.backend_pubkey, req, (size_t)n, resp, sizeof(resp), NULL);
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

    fprintf(stderr, "\033[1m\xf0\x9f\x94\x91 Enrollment token (expires in %s s):\033[0m\n", expires[0] ? expires : "?");
    printf("%s\n", token);
    fprintf(stderr, "\n\033[2mRun on the new host:\033[0m\n");
    fprintf(stderr, "  todoforai-bridge login --token %s\n", token);
    return 0;
}

// ── whoami subcommand ───────────────────────────────────────────────────────

int cmd_whoami(int argc, char **argv) {
    static const char *USAGE = "whoami";
    const char *profile = NULL;
    ko_longopt_t longopts[] = {
        { "help",    ko_no_argument,       'h' },
        { "profile", ko_required_argument, 'P' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hP:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE); return 0; }
        else if (c == 'P') profile = opt.arg;
        else cli_parse_error("todoforai-bridge", USAGE, argc, argv, &opt, c);
    }
    if (profile && login_set_profile(profile) < 0) return 2;
    return login_print_whoami("todoforai-bridge");
}

// ── logout ──────────────────────────────────────────────────────────────────

int cmd_logout(int argc, char **argv) {
    static const char *USAGE = "logout";
    const char *profile = NULL;
    ko_longopt_t longopts[] = {
        { "help",    ko_no_argument,       'h' },
        { "profile", ko_required_argument, 'P' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hP:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE); return 0; }
        else if (c == 'P') profile = opt.arg;
        else cli_parse_error("todoforai-bridge", USAGE, argc, argv, &opt, c);
    }
    if (profile && login_set_profile(profile) < 0) return 2;
    return login_logout("todoforai-bridge");
}

// ── help ────────────────────────────────────────────────────────────────────

void print_help(void) {
    printf("todoforai-bridge " BRIDGE_VERSION " — TODO for AI bridge\n\n"
           "Usage: todoforai-bridge [command] [options]\n\n"
           "  (no args)            run the bridge (logs in on first run)\n"
           "  login                log in this device  [--token T] [--device-name NAME] [--no-browser]\n"
           "  logout               remove credentials\n"
           "  whoami               show current user/device\n"
           "  enroll               print a token to provision another device\n"
           "  update               install the latest release\n"
           "  policy               confine the backend to listed workspaces on this device\n"
           "  config               keep-awake on|off: no system sleep while agents work\n\n"
           "      --kill           replace a bridge already running for this device\n"
           "      --mayfly TODO    ephemeral session scoped to that todo (used by tfa-cli --isolated)\n"
           "      --workspace P    workspace root for --mayfly (default: cwd)\n"
           "      --session-token T  authenticate --mayfly with a token instead of this\n"
           "                       device's credentials (env: TODOFORAI_MAYFLY_TOKEN)\n"
           "  -h, --help           show this help\n"
           "  -v, --version        print version\n\n"
           "Docs: https://docs.todofor.ai\n");
}

// ---------------------------------------------------------------------------
// `__adb connect|pair|disconnect <phone>[:port] [args…]` — target of the
// adb() shell shim the daemon prepends to every RUN (ADB_SHIM_FMT, main.c).
// Asks the daemon's loopback server (GET /adb?phone=&port=) for the relay
// port and execs the real adb against 127.0.0.1:<port>. Anything that
// already looks like host:port (digits/dots/colons only) is passed through
// untouched, so `adb connect 192.168.1.5:5555` keeps working.
// ---------------------------------------------------------------------------
#ifndef _WIN32
#include "identity_server.h"  // IDENTITY_SERVER_PORT*
#include "json.h"
#include "ws.h"               // ws_tcp_connect
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

// Stock adb targets: `host:port`, `host` (default 5555), IPv6 `[::1]:5555`,
// `vsock:…`, `localfilesystem:…`, `emulator-5554`, `localhost`, `*.local`.
// A phone name has spaces or chars no hostname has (e.g. the apostrophe in
// "Marcell's S24"), or no dot/colon at all — but "localhost"/"emulator-N"
// are not phone names. Anything hostname-shaped goes to the real adb.
static int looks_like_hostport(const char *s) {
    if (!*s) return 0;
    if (strncmp(s, "vsock:", 6) == 0 || strncmp(s, "localfilesystem:", 16) == 0 || strncmp(s, "emulator-", 9) == 0) return 1;
    if (strcmp(s, "localhost") == 0) return 1;
    int has_sep = 0;
    for (const char *c = s; *c; c++) {
        if (*c == '.' || *c == ':') has_sep = 1;
        else if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || *c == '-' || *c == '[' || *c == ']' || *c == '_')) return 0;
    }
    return has_sep;
}

static int url_encode(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const char *c = in; *c; c++) {
        unsigned char ch = (unsigned char)*c;
        int safe = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
        if (safe) { if (o + 1 >= cap) return -1; out[o++] = (char)ch; }
        else { if (o + 4 >= cap) return -1; o += (size_t)snprintf(out + o, cap - o, "%%%02X", ch); }
    }
    out[o] = '\0';
    return 0;
}

// Returns relay port, or 0 with err. `last_err` (optional) receives the
// backend's most recent close reason for this relay.
static uint16_t ask_daemon(uint16_t srv_port, const char *phone, const char *pspec, char *err, size_t err_cap,
                           char *last_err, size_t last_err_cap, int forget) {
    char enc[256];
    if (url_encode(phone, enc, sizeof enc) != 0) { snprintf(err, err_cap, "phone name too long"); return 0; }
    ws_fd_t fd = ws_tcp_connect("127.0.0.1", srv_port, 1000, err, err_cap);
    if (fd == WS_INVALID_FD) { snprintf(err, err_cap, "bridge daemon not running on this machine"); return 0; }
    char req[512];
    int n = snprintf(req, sizeof req, "GET /adb?phone=%s&port=%s%s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", enc, pspec, forget ? "&forget=1" : "");
    size_t off = 0;
    while (off < (size_t)n) {
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        if (poll(&p, 1, 1000) <= 0) break;
        ssize_t w = send(fd, req + off, (size_t)n - off, 0);
        if (w <= 0) break;
        off += (size_t)w;
    }
    char resp[1024] = {0}; size_t rl = 0;
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 3000) <= 0) break;
        ssize_t r = recv(fd, resp + rl, sizeof resp - 1 - rl, 0);
        if (r <= 0) break;
        rl += (size_t)r;
        if (rl + 1 >= sizeof resp) break;
    }
    close(fd);
    const char *body = strstr(resp, "\r\n\r\n");
    if (!body) { snprintf(err, err_cap, "bad reply from bridge daemon"); return 0; }
    body += 4;
    if (strncmp(resp, "HTTP/1.0 200", 12) != 0) { snprintf(err, err_cap, "%s", *body ? body : "bridge refused"); return 0; }
    long port = 0;
    if (!json_get_long(body, strlen(body), "port", &port) || port <= 0 || port > 65535) { snprintf(err, err_cap, "bad reply from bridge daemon"); return 0; }
    if (last_err) { size_t ln = 0; if (!json_get_str_decoded(body, strlen(body), "lastError", last_err, last_err_cap, &ln)) last_err[0] = 0; }
    return (uint16_t)port;
}

// Dial the relay once and see whether the far end hangs up at once (phone
// offline, dial refused): adbd never speaks first, so a quick EOF is a
// refusal. Returns 1 if refused.
static int probe_refused(uint16_t port) {
    char err[64];
    ws_fd_t fd = ws_tcp_connect("127.0.0.1", port, 1000, err, sizeof err);
    if (fd == WS_INVALID_FD) return 1;
    struct pollfd p = { .fd = fd, .events = POLLIN };
    int refused = 0;
    // Only an EOF/error within the window counts; silence is a live adbd.
    if (poll(&p, 1, 1500) > 0) { char b[8]; refused = recv(fd, b, sizeof b, MSG_PEEK) <= 0; }
    close(fd);
    return refused;
}

int cmd_adb(int argc, char **argv) {
    // argv: [__adb, verb, target, rest…]
    if (argc < 2) { fprintf(stderr, "usage: adb connect|pair|disconnect <phone>\n"); return 2; }
    const char *verb = argv[1];
    char *target = argc >= 3 ? argv[2] : NULL;
    char *exec_argv[64];
    int ea = 0;
    exec_argv[ea++] = "adb";
    exec_argv[ea++] = (char *)verb;
    char hostport[64];
    if (target && !looks_like_hostport(target)) {
        // "<phone>" — connect uses adbd's connect port, pair its pairing port.
        const char *pspec = strcmp(verb, "pair") == 0 ? "pair" : "connect";
        if (strlen(target) >= 64) { fprintf(stderr, "adb %s: phone name too long\n", verb); return 1; }
        uint16_t srv = IDENTITY_SERVER_PORT;
        const char *api = getenv("TODOFORAI_API_URL");
        if (api && (strstr(api, "localhost") || strstr(api, "127.0.0.1"))) srv = IDENTITY_SERVER_PORT_LOCAL;
        char err[256], last[192] = "";
        if (strcmp(verb, "disconnect") == 0) {
            // Drop the relay listener; the real adb forgets 127.0.0.1:<port>.
            uint16_t port = ask_daemon(srv, target, pspec, err, sizeof err, NULL, 0, 1);
            if (!port) { fprintf(stderr, "adb disconnect %s: %s\n", target, err); return 1; }
            snprintf(hostport, sizeof hostport, "127.0.0.1:%u", port);
            exec_argv[ea++] = hostport;
            exec_argv[ea] = NULL;
            execvp("adb", exec_argv);
            fprintf(stderr, "adb: not found in PATH (install Android platform-tools)\n");
            return 127;
        }
        uint16_t port = ask_daemon(srv, target, pspec, err, sizeof err, NULL, 0, 0);
        if (!port) { fprintf(stderr, "adb %s %s: %s\n", verb, target, err); return 1; }
        if (probe_refused(port)) {
            if (ask_daemon(srv, target, pspec, err, sizeof err, last, sizeof last, 0))
                fprintf(stderr, "adb %s %s: %s\n", verb, target, last[0] ? last : "phone did not answer");
            else
                fprintf(stderr, "adb %s %s: phone did not answer\n", verb, target);
            return 1;
        }
        snprintf(hostport, sizeof hostport, "127.0.0.1:%u", port);
        exec_argv[ea++] = hostport;
        for (int i = 3; i < argc && ea < 62; i++) exec_argv[ea++] = argv[i];
    } else {
        for (int i = 2; i < argc && ea < 62; i++) exec_argv[ea++] = argv[i];
    }
    exec_argv[ea] = NULL;
    execvp("adb", exec_argv);
    fprintf(stderr, "adb: not found in PATH (install Android platform-tools)\n");
    return 127;
}
#endif  // !_WIN32

#ifndef _WIN32
// ── `<bridge> __live` — tee stdin to stdout, POST batches to the backend ──
// The tail() shim (main.c) runs `cmd | <bridge> __live | command tail …` so a
// `| tail -N` that would sit silent until EOF still shows lines in the chat
// block. Display-only: the backend relays them as BLOCK_SH_MSG_RESULT and never
// stores them, so the tool result is unchanged. Never breaks the pipe: without
// env/curl or on any POST failure it is a plain `cat`.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>

#define LIVE_FLUSH_MS    200
#define LIVE_FLUSH_BYTES (16 * 1024)
#define LIVE_BUF_CAP     (64 * 1024)   // overflow while a POST is in flight → drop

static int64_t live_now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int write_all(int fd, const char *p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

// Fork a poster: it pipes `body` to curl's stdin and the auth header to fd 3
// (`-H @/dev/fd/3`, so the token never shows in `ps`). Returns its pid or -1.
static pid_t live_post(const char *url, const char *hdr, const char *body, size_t n) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    // Let go of the pipeline at once: holding its stdout would keep tail's
    // input open (and its final print waiting) until the POST finishes.
    { int dn = open("/dev/null", O_RDWR);
      if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); } }
    int bp[2], hp[2];
    if (pipe(bp) || pipe(hp)) _exit(1);
    pid_t c = fork();
    if (c == 0) {
        // Pipe fds may sit on 0..3 themselves: dup2 into place, then close
        // only the leftovers above 3, or we would close what we just placed.
        if (hp[0] == 0) { int t = dup(hp[0]); close(hp[0]); hp[0] = t; }
        dup2(bp[0], 0); dup2(hp[0], 3);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); if (dn > 3) close(dn); }
        int fds[4] = { bp[0], bp[1], hp[0], hp[1] };
        for (int i = 0; i < 4; i++) if (fds[i] > 3) close(fds[i]);
        execlp("curl", "curl", "-sS", "-m", "3", "-X", "POST", "-H", "@/dev/fd/3",
               "-H", "Content-Type: text/plain; charset=utf-8", "--data-binary", "@-", url, (char *)NULL);
        _exit(127);
    }
    close(bp[0]); close(hp[0]);
    if (c > 0) { write_all(hp[1], hdr, strlen(hdr)); close(hp[1]); write_all(bp[1], body, n); }
    close(bp[1]); close(hp[1]);
    int st; if (c > 0) waitpid(c, &st, 0);
    _exit(0);
}

int cmd_live(int argc, char **argv) {
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);  // EPIPE instead: stop like cat would, but say so via rc
    const char *tok = getenv("TODOFORAI_API_TOKEN"), *api = getenv("TODOFORAI_API_URL");
    const char *todo = getenv("TODOFORAI_TODO_ID"), *msg = getenv("TODOFORAI_MESSAGE_ID");
    const char *blk = getenv("TODOFORAI_BLOCK_ID");
    char url[1024], hdr[256];
    int post = tok && *tok && api && *api && todo && *todo && msg && *msg && blk && *blk;
    if (post) {
        int u = snprintf(url, sizeof url, "%s/dst/v1/shell/live?todoId=%s&messageId=%s&blockId=%s", api, todo, msg, blk);
        int h = snprintf(hdr, sizeof hdr, "x-api-key: %s\n", tok);
        post = u > 0 && (size_t)u < sizeof url && h > 0 && (size_t)h < sizeof hdr;
    }
    static char in[16 * 1024], buf[LIVE_BUF_CAP];
    size_t blen = 0;
    pid_t inflight = 0;
    int out_ok = 1;  // stdout still writable
    int64_t first = 0;  // ms when the oldest unsent byte arrived
    for (;;) {
        if (inflight > 0) {
            pid_t w = waitpid(inflight, NULL, WNOHANG);
            if (w == inflight || (w < 0 && errno == ECHILD)) inflight = 0;
        }
        int timeout = -1;
        if (post && blen > 0) {
            int64_t left = first + LIVE_FLUSH_MS - live_now_ms();
            timeout = left < 0 ? 0 : (int)left;
        }
        if (inflight > 0 && (timeout < 0 || timeout < 50)) timeout = 50;  // reap / retry the poster
        struct pollfd p = { .fd = 0, .events = POLLIN };
        int pr = poll(&p, 1, timeout);
        if (pr < 0 && errno != EINTR) break;
        if (pr > 0) {
            ssize_t r = read(0, in, sizeof in);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            if (write_all(1, in, (size_t)r) < 0) { out_ok = 0; break; }  // reader gone
            if (post) {
                if (blen + (size_t)r > sizeof buf) blen = 0;  // display-only: drop the backlog
                if (blen == 0) first = live_now_ms();
                memcpy(buf + blen, in, (size_t)r); blen += (size_t)r;
            }
        }
        if (!post || blen == 0 || inflight > 0) continue;
        if (blen < LIVE_FLUSH_BYTES && live_now_ms() - first < LIVE_FLUSH_MS) continue;
        // Prefer whole lines; a ≥16KB newline-less run (or an overflow drop) may split UTF-8.
        size_t n = blen;
        while (n > 0 && buf[n - 1] != '\n') n--;
        if (n == 0) { if (blen < LIVE_FLUSH_BYTES) { first = live_now_ms(); continue; } n = blen; }
        pid_t pid = live_post(url, hdr, buf, n);
        if (pid < 0) { post = 0; continue; }
        inflight = pid;
        memmove(buf, buf + n, blen - n); blen -= n;
        if (blen) first = live_now_ms();
    }
    // EOF: hand the rest off and return at once — the pipeline (and tail's
    // final print) must not wait on the network. The poster is orphaned.
    if (post && out_ok && blen > 0) live_post(url, hdr, buf, blen);
    return out_ok ? 0 : 141;  // 128+SIGPIPE, what cat reports under pipefail
}
#endif  // !_WIN32

// CLI subcommands: login / enroll / whoami / help.
// Extracted from main.c. The daemon path stays in main.c.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "subcmd.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"      // ketopt + cli_usage helpers
#include "identity.h"  // BRIDGE_VERSION, bridge_identity_json
#include "noise.h"     // noise_random

#define LOGIN_IMPLEMENTATION
#include "login.h"

// ── Usage strings ────────────────────────────────────────────────────────────

// NOTE: --host / --port / --server-pubkey are developmental flags (override
// backend address + Noise static pubkey). --ttl overrides enroll token TTL
// (default 300s). All still parsed below, but intentionally omitted from help
// to keep the public surface minimal.
const char *USAGE_MAIN          = "";
static const char *USAGE_LOGIN  = "login [--device-name NAME] [--token TOKEN]";
static const char *USAGE_ENROLL = "enroll";
static const char *USAGE_WHOAMI = "whoami";
static const char *USAGE_LOGOUT = "logout";

// ── Noise one-shot RPC helper (reuses transport code from login.h) ──────────

// True if host is a local/dev address (uses dev-port defaults).
// Matches localhost, IPv6 loopback, and any RFC1918 private range — covers
// every dev/sandbox setup (10.x sandbox gateway, 172.16/12 docker, 192.168.x LAN).
static int is_local_host(const char *h) {
    if (!h) return 0;
    if (strcmp(h, "localhost") == 0 || strcmp(h, "::1") == 0 || strcmp(h, "[::1]") == 0) return 1;
    if (strncmp(h, "127.", 4) == 0)     return 1;          // 127.0.0.0/8
    if (strncmp(h, "10.", 3)  == 0)     return 1;          // 10.0.0.0/8
    if (strncmp(h, "192.168.", 8) == 0) return 1;          // 192.168.0.0/16
    if (strncmp(h, "172.", 4) == 0) {                      // 172.16.0.0/12
        int o2 = atoi(h + 4);
        if (o2 >= 16 && o2 <= 31) return 1;
    }
    return 0;
}

// Resolve backend Noise addr + pubkey.
// Precedence: CLI flag > env (NOISE_BACKEND_HOST / _PORT / _PUBKEY) > saved
// login backendHost > prod defaults. `host`/`port_s`/`pub_hex` may be NULL.
static void enroll_backend(const char *host, const char *port_s, const char *pub_hex,
                           char *addr_buf, size_t addr_cap,
                           const char **addr, const char **pub) {
    if (!host)   host   = getenv("NOISE_BACKEND_HOST");
    if (!port_s) port_s = getenv("NOISE_BACKEND_PORT");

    // Saved host from prior `login` (may be empty for prod).
    login_credentials_t saved;
    (void)login_load_credentials(&saved);
    if (!host && saved.backend_host[0]) host = saved.backend_host;

    if (!host) host = LOGIN_DEFAULT_BACKEND_HOST;
    if (!port_s) {
        port_s = is_local_host(host) ? "14100" : LOGIN_DEFAULT_NOISE_PORT;
        fprintf(stderr, "[bridge] no port specified for host=%s, defaulting to %s (set NOISE_BACKEND_PORT or --port to override)\n", host, port_s);
    }
    snprintf(addr_buf, addr_cap, "%s:%s", host, port_s);
    *addr = addr_buf;

    *pub = pub_hex ? pub_hex : getenv("NOISE_BACKEND_PUBKEY");
    if (!*pub) *pub = LOGIN_DEFAULT_BACKEND_PUBKEY;
}

// Connect, handshake, send one encrypted JSON request, return decrypted reply.
// Returns response length (>= 0) or -1 on error. Writes NUL-terminated JSON
// into resp_buf (truncated to resp_cap-1 if needed). Prints actionable
// diagnostics to stderr on TCP / handshake failures.
static int noise_oneshot(const char *backend_addr, const char *backend_pub,
                         const char *req, size_t req_len,
                         char *resp_buf, size_t resp_cap) {
    login_sock_init();

    uint8_t remote_pub[32];
    if (login_hex_decode(remote_pub, 32, backend_pub) < 0) {
        fprintf(stderr, "error: invalid backend public key (need 64 hex chars)\n");
        return -1;
    }

    char host[256], port_str[16];
    const char *colon = strrchr(backend_addr, ':');
    if (!colon) { fprintf(stderr, "error: invalid backend address (missing port): %s\n", backend_addr); return -1; }
    size_t hlen = (size_t)(colon - backend_addr);
    if (hlen >= sizeof(host)) { fprintf(stderr, "error: host too long\n"); return -1; }
    memcpy(host, backend_addr, hlen);
    host[hlen] = '\0';
    snprintf(port_str, sizeof(port_str), "%s", colon + 1);

    login_session_t session;
    int conn_rc = login_noise_connect(&session, host, port_str, remote_pub);
    if (conn_rc == -1) {
        fprintf(stderr,
            "error: cannot reach %s (TCP connect failed).\n"
            "  - Is the backend running and listening on this host:port?\n"
            "  - Check firewall / network. Try: nc -zv %s %s\n",
            backend_addr, host, port_str);
        return -1;
    }
    if (conn_rc < 0) {
        fprintf(stderr,
            "error: connected to %s but Noise handshake failed.\n"
            "  - Wrong --server-pubkey for this server (most common cause).\n"
            "  - Server identity changed — check backend logs for\n"
            "    '[noise] Server public key: <hex>' and pass it via\n"
            "    --server-pubkey <hex> (or NOISE_BACKEND_PUBLIC_KEY).\n"
            "  - --port should be the Noise-TCP RPC port (14100 dev, 4100 prod),\n"
            "    NOT the HTTP/WS bridge port (4000 dev, 80/443 prod).\n",
            backend_addr);
        return -1;
    }

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
// Looks for the nested "device":{...} and optional "user":{...} objects.
static int parse_device_creds(const char *resp, login_credentials_t *creds) {
    memset(creds, 0, sizeof(*creds));
    const char *dev = strstr(resp, "\"device\"");
    if (!dev) return -1;
    dev = strchr(dev, '{');
    if (!dev) return -1;
    json_find_string(dev, "id",     creds->device_id,     sizeof(creds->device_id));
    json_find_string(dev, "secret", creds->device_secret, sizeof(creds->device_secret));
    json_find_string(dev, "name",   creds->device_name,   sizeof(creds->device_name));
    const char *usr = strstr(resp, "\"user\"");
    if (usr && (usr = strchr(usr, '{'))) {
        json_find_string(usr, "id",    creds->user_id,    sizeof(creds->user_id));
        json_find_string(usr, "email", creds->user_email, sizeof(creds->user_email));
        json_find_string(usr, "name",  creds->user_name,  sizeof(creds->user_name));
    }
    return (creds->device_id[0] && creds->device_secret[0]) ? 0 : -1;
}

// Redeem an enrollment token for fresh device credentials and save them.
// The redeemer self-describes via identity gathered from the host (uname,
// /etc/os-release, sandbox marker, …). Backend derives `deviceType` from
// `identity.deviceType` and stores the rest as device metadata.
static int redeem_enroll_token(const char *token,
                               const char *host, const char *port_s, const char *pub_hex) {
    const char *addr, *pub;
    char addr_buf[280];
    enroll_backend(host, port_s, pub_hex, addr_buf, sizeof(addr_buf), &addr, &pub);

    uint8_t id_bytes[4]; char id_hex[9];
    noise_random(id_bytes, 4);
    login_hex_encode(id_hex, id_bytes, 4);

    char identity[1024];
    int ilen = bridge_identity_json(identity, sizeof(identity), 1);
    if (ilen < 0) { fprintf(stderr, "error: failed to gather identity\n"); return -1; }

    char req[2048];
    int n = snprintf(req, sizeof(req),
        "{\"id\":\"%s\",\"type\":\"cli.enroll.redeem\","
        "\"payload\":{\"token\":\"%s\",\"identity\":%s}}",
        id_hex, token, identity);
    if (n < 0 || (size_t)n >= sizeof(req)) { fprintf(stderr, "error: payload too long\n"); return -1; }

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

int cmd_login(int argc, char **argv) {
    const char *device_name = NULL;
    const char *token       = NULL;
    const char *host        = NULL;
    const char *port_s      = NULL;
    const char *pub_hex     = NULL;
    ko_longopt_t longopts[] = {
        { "help",          ko_no_argument,       'h' },
        { "device-name",   ko_required_argument, 'n' },
        { "token",         ko_required_argument, 't' },
        { "host",          ko_required_argument, 'H' },
        { "port",          ko_required_argument, 'p' },
        { "server-pubkey", ko_required_argument, 'k' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hn:t:H:p:k:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE_LOGIN); return 0; }
        else if (c == 'n') device_name = opt.arg;
        else if (c == 't') token = opt.arg;
        else if (c == 'H') host = opt.arg;
        else if (c == 'p') port_s = opt.arg;
        else if (c == 'k') pub_hex = opt.arg;
        else cli_parse_error("todoforai-bridge", USAGE_LOGIN, argc, argv, &opt, c);
    }

    // Already logged in? Reuse existing creds — to switch user/device run logout first.
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

    // Token path: non-interactive enrollment via short-lived token (sandbox
    // /init, scripted installs). Interactive path: device-code flow + browser.
    // Both fall through to the daemon in main(), so `bridge login [...]`
    // behaves identically to `bridge` after creds are obtained.
    if (token && *token) {
        return redeem_enroll_token(token, host, port_s, pub_hex) == 0 ? 0 : 1;
    }
    const char *addr, *pub;
    char addr_buf[280];
    enroll_backend(host, port_s, pub_hex, addr_buf, sizeof(addr_buf), &addr, &pub);
    return login_device_flow(addr, pub, "bridge", device_name) == 0 ? 0 : 1;
}

// ── enroll subcommand ───────────────────────────────────────────────────────

int cmd_enroll(int argc, char **argv) {
    long ttl_sec = 300;
    const char *host    = NULL;
    const char *port_s  = NULL;
    const char *pub_hex = NULL;
    ko_longopt_t longopts[] = {
        { "help",          ko_no_argument,       'h' },
        { "ttl",           ko_required_argument, 'T' },
        { "host",          ko_required_argument, 'H' },
        { "port",          ko_required_argument, 'p' },
        { "server-pubkey", ko_required_argument, 'k' },
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hT:H:p:k:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE_ENROLL); return 0; }
        else if (c == 'T') ttl_sec = atol(opt.arg);
        else if (c == 'H') host = opt.arg;
        else if (c == 'p') port_s = opt.arg;
        else if (c == 'k') pub_hex = opt.arg;
        else cli_parse_error("todoforai-bridge", USAGE_ENROLL, argc, argv, &opt, c);
    }

    // Must have device creds on disk — only a logged-in bridge can mint.
    login_credentials_t creds;
    memset(&creds, 0, sizeof(creds));
    if (login_load_credentials(&creds) < 0 || !creds.device_id[0] || !creds.device_secret[0]) {
        fprintf(stderr, "error: no device credentials found. Run `todoforai-bridge login` first.\n");
        return 1;
    }

    const char *addr, *pub;
    char addr_buf[280];
    enroll_backend(host, port_s, pub_hex, addr_buf, sizeof(addr_buf), &addr, &pub);

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

    fprintf(stderr, "\033[1m\xf0\x9f\x94\x91 Enrollment token (expires in %s s):\033[0m\n", expires[0] ? expires : "?");
    printf("%s\n", token);
    fprintf(stderr, "\n\033[2mRun on the new host:\033[0m\n");
    fprintf(stderr, "  todoforai-bridge login --token %s\n", token);
    return 0;
}

// ── whoami subcommand ───────────────────────────────────────────────────────

int cmd_whoami(int argc, char **argv) {
    ko_longopt_t longopts[] = {{ "help", ko_no_argument, 'h' }, { 0, 0, 0 }};
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "h", longopts)) >= 0) {
        if (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE_WHOAMI); return 0; }
        cli_parse_error("todoforai-bridge", USAGE_WHOAMI, argc, argv, &opt, c);
    }
    return login_print_whoami("todoforai-bridge");
}

// ── logout ──────────────────────────────────────────────────────────────────

int cmd_logout(int argc, char **argv) {
    ko_longopt_t longopts[] = {{ "help", ko_no_argument, 'h' }, { 0, 0, 0 }};
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "h", longopts)) >= 0) {
        if (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE_LOGOUT); return 0; }
        cli_parse_error("todoforai-bridge", USAGE_LOGOUT, argc, argv, &opt, c);
    }
    char path[1024];
    if (login_config_path(path, sizeof(path)) < 0) {
        fprintf(stderr, "error: failed to resolve config path\n");
        return 1;
    }
    if (remove(path) != 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "Not logged in (no credentials at %s).\n", path);
            return 0;
        }
        fprintf(stderr, "error: failed to remove %s: %s\n", path, strerror(errno));
        return 1;
    }
    fprintf(stderr, "\033[32m\xe2\x9c\x85 Logged out. Removed %s\033[0m\n", path);
    return 0;
}

// ── help ────────────────────────────────────────────────────────────────────

void print_help(void) {
    printf("todoforai-bridge " BRIDGE_VERSION " — TODO for AI bridge\n\n"
           "Usage:\n"
           "  todoforai-bridge\n"
           "      Run the bridge. Auto-launches login on first run.\n"
           "  todoforai-bridge %s\n"
           "      Authenticate this device, then run the agent. --token redeems\n"
           "      a one-time enrollment token (non-interactive).\n"
           "  todoforai-bridge %s\n"
           "      Remove saved device credentials.\n"
           "  todoforai-bridge %s\n"
           "      Print a one-time enrollment token for provisioning another device.\n"
           "  todoforai-bridge %s\n"
           "      Show the logged-in user and device.\n"
           "  todoforai-bridge version | --version | -v\n"
           "  todoforai-bridge --help  | -h\n",
           USAGE_LOGIN, USAGE_LOGOUT, USAGE_ENROLL, USAGE_WHOAMI);
}

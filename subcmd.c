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
    static const char *USAGE = "login [--device-name NAME] [--token TOKEN]";
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
        { 0, 0, 0 }
    };
    ketopt_t opt = KETOPT_INIT;
    int c;
    while ((c = ketopt(&opt, argc, argv, 1, "hn:t:H:p:P:", longopts)) >= 0) {
        if      (c == 'h') { cli_usage(stdout, "todoforai-bridge", USAGE); return CMD_RC_HELP; }
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
           "  login                log in this device  [--token T] [--device-name NAME]\n"
           "  logout               remove credentials\n"
           "  whoami               show current user/device\n"
           "  enroll               print a token to provision another device\n\n"
           "  -h, --help           show this help\n"
           "  -v, --version        print version\n\n"
           "Docs: https://docs.todofor.ai\n");
}

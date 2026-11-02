// Loopback CDP fast path: agent-browser on this machine ↔ the TODOforAI
// browser extension on this machine, without the backend round trip.
//
// The cloud path is agent-browser → wss://api…/ws/v2/cdp → backend → the
// extension's resource socket: every CDP command costs two internet round
// trips (~100 ms), and agent-browser's connect attaches every tab one by one.
// When both ends run here, the bridge muxes them over its identity port.
//
// Trust: the loopback port is no gate (any local process may dial it).
//  - The backend mints a secret S per (browser, this bridge) and hands it to
//    us over Noise (function `cdp_local` {resourceId, secret, tokenHash}) and
//    to the extension over its resource socket (CDP_LOCAL). Extension and
//    bridge prove S to each other (HMAC-SHA1 over fresh nonces), so a process
//    squatting the port can neither drive the browser nor pose as it.
//  - A CDP client presents the browser's cdpToken, like on the cloud path;
//    we keep only tokenHash = hex SHA1(token) and route by it. Grantee tokens
//    hash differently and stay on the cloud path, where access is checked.
//    The guard only dials us when TODOFORAI_CDP_LOCAL_PORT is in its env,
//    which a RUN gets only from the bridge holding the port (not a squatter).
//
//   GET /cdp-local/ext (Origin chrome-/moz-extension://)  — the extension
//   GET /cdp-local/cdp?token=…[&todoId=…] (no Origin)     — agent-browser.
//       Without Upgrade it is the guard's probe: 200 when an authenticated
//       extension serves that token, else 404 (→ the cloud URL).
//
// Bridge↔extension text frames are `<verb> <args>` + optional `\n<body>`, so
// routing never parses CDP JSON:
//   → hello <bnonce>
//   ← auth <resourceId> <enonce> <hex HMAC(S, "ext|"+bnonce)>
//   → ok <hex HMAC(S, "bridge|"+enonce)>      (extension checks it, else closes)
//   → open <clientId> [todoId]  /  → close <clientId>
//   → cdp <clientId>\n<frame>   /  ← cdp <clientId|*>\n<frame>
//   ← close <clientId>                      (extension refuses a client)
//   ← grant <rid>\n<path>  → grant <rid>\n{token,port,totalSize} | !<error>
//   ← ping → pong
// An extension that goes away takes its clients with it (close 4004), like the
// backend's "resource disconnected"; a client that goes away is `close`d.
#ifndef BRIDGE_CDP_LOCAL_H
#define BRIDGE_CDP_LOCAL_H

#include "ws.h"  // ws_fd_t, struct pollfd (winsock2 on Windows)
#ifndef _WIN32
#  include <poll.h>
#endif
#include <stddef.h>
#include <stdint.h>

#define CDPL_MAX_CONNS   64                    // extensions + clients
#define CDPL_MAX_MSG     (64u * 1024 * 1024)   // one WS message (screenshots are big)
#define CDPL_TX_MAX      (256u * 1024 * 1024)  // queued for one slow peer, then drop it
#define CDPL_AUTH_MS     5000                  // extension: upgrade → auth
#define CDPL_CLOSE_MS    2000                  // our CLOSE queued → fd closed anyway

// `grant <rid>\n<path>` from the extension: same token mint as the backend's
// `file_grant` call. Writes {"token","port","totalSize","type"} to out, or
// returns -1 with err set.
typedef int (*cdp_local_grant_fn)(const char *path, char *out, size_t cap, char *err, size_t err_cap);
void cdp_local_init(cdp_local_grant_fn file_grant);
// Backend's `cdp_local` call. Same resource again keeps its live extension
// unless tokenHash changed (token rotated → its clients are cut). 0 / -1.
int  cdp_local_grant(const char *resource_id, const char *secret, const char *token_hash);
// Identity-server hook (identity_server.h): takes ownership of `fd`, a
// non-blocking socket whose request head was already read. `ext` = the
// /cdp-local/ext endpoint; else token/todo_id come from the /cdp-local/cdp
// query. ws_key NULL (no Upgrade) = probe: answered with 200/404 and closed.
void cdp_local_accept(ws_fd_t fd, int ext, const char *ws_key, const char *token, const char *todo_id);
void cdp_local_fill_pfds(struct pollfd *pfds, size_t *n, size_t cap);
void cdp_local_service(const struct pollfd *pfds, size_t first, size_t n);
void cdp_local_tick(void);   // deadlines; call every loop
// One poll() of the identity listener + mux for `ms` while the main loop is
// not running (backend reconnect backoff): local clients keep working.
void cdp_local_idle_serve(ws_fd_t listen_fd, const char *device_id, int ms);
void cdp_local_close_all(void);
int  cdp_local_count(int ext);  // live extensions (ext=1) / clients (ext=0)

// Exposed for tests.
void cdpl_sha1(const uint8_t *m, size_t n, uint8_t out[20]);
void cdpl_hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[20]);

#endif

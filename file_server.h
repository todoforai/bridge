// Direct loopback file streaming: GET /file?t=<token> on the identity port.
//
// The relay path (read_file_b64 → backend → frontend) moves 45KB chunks over
// Noise and the snippet iframe must assemble the WHOLE file before a <video>
// can play. When the browser runs on this very machine it can instead fetch
// http://127.0.0.1:43127/file?t=… directly (the frontend's parent page does,
// see frontend/docs/snippet-file-downloads.md). HTTP Range is supported so a
// future direct <video src> can start instantly and seek.
//
// Auth: the loopback bind is NOT a gate (any local page/process can connect),
// so every file needs a capability token. Tokens are minted only by the
// `file_grant` function call — i.e. by the backend over the authenticated
// Noise channel, after it checked the user may read on this device. A token
// names exactly one path; serving re-opens through bridge_policy_open, so the
// device policy still applies. Tokens live in memory only (lost on restart;
// the frontend then falls back to the relay).
//
// Serving runs on a detached thread per request: the daemon loop only reads
// the request head (its usual 300ms budget) and hands the socket over.
#ifndef BRIDGE_FILE_SERVER_H
#define BRIDGE_FILE_SERVER_H

#include <stddef.h>
#include "ws.h"  // ws_fd_t

#define FILE_GRANT_TOKEN_LEN 32  // hex chars (16 random bytes)

// Mint (or refresh) a token for `path`, which must open via the device policy
// as a regular file. Writes the NUL-terminated token to `token_out` (cap >=
// FILE_GRANT_TOKEN_LEN+1) and the file size to `*size_out`. Returns 0, or -1
// with `err` set ("file_grant: not found" is stable text — the backend tries
// the next workspace root on it).
int bridge_file_grant(const char *path, char *token_out, size_t token_cap,
                      long long *size_out, char *err, size_t err_cap);

// Called by the identity server for a request line starting with
// "GET /file?" or "HEAD /file?". Takes ownership of `fd` (always closes it,
// possibly later on a worker thread). `cors` = response CORS header lines
// (may be empty).
void bridge_file_serve(ws_fd_t fd, const char *req, const char *cors);

#endif

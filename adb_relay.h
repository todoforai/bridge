// ADB relay: loopback listeners that pipe stock `adb` onto a phone's adbd
// through the Noise channel (ADB_OPEN/ADB_DATA/ADB_CLOSE frames — see
// packages/shared-fbe bridgeProtocol.ts and mobile/plan/android-device-link.md).
//
// `adb connect "Marcell's S24"` in an agent shell hits the adb() shim →
// `<bridge> __adb connect …` → GET /adb?phone=…&port=connect on the loopback
// identity server → the daemon opens (or reuses) a 127.0.0.1:<port> listener
// for that phone+port and answers {"port":N} → the subcommand execs
// `adb connect 127.0.0.1:N`. Every TCP connection accepted on N is one
// stream; bytes are opaque (adb's TLS is end-to-end).
#ifndef BRIDGE_ADB_RELAY_H
#define BRIDGE_ADB_RELAY_H

#include "ws.h"  // ws_fd_t, struct pollfd (winsock2 on Windows)
#ifndef _WIN32
#  include <poll.h>
#endif
#include <stddef.h>
#include <stdint.h>

#define ADB_MAX_LISTENERS 8
#define ADB_MAX_STREAMS   32
#define ADB_PHONE_CAP     64
#define ADB_PORT_SPEC_CAP 16
#define ADB_DATA_CHUNK    (40 * 1024)   // raw bytes per ADB_DATA (b64 stays < 64KB Noise cap)
#define ADB_OUTQ_MAX      (1024 * 1024) // per-stream bytes queued for a slow local adb before we drop it

typedef struct {
    ws_fd_t fd;                       // listening socket or WS_INVALID_FD
    uint16_t port;                    // bound loopback port
    char phone[ADB_PHONE_CAP];        // device name or id, as typed
    char port_spec[ADB_PORT_SPEC_CAP];// "connect" | "pair" | "<n>"
    char last_error[160];             // latest ADB_CLOSE error for a stream of ours ("" = none)
} adb_listener_t;

typedef struct {
    ws_fd_t fd;                       // accepted local socket, WS_INVALID_FD when free
    uint32_t id;                      // streamId on the wire
    int opened;                       // ADB_OPEN sent
    adb_listener_t *owner;
    // Bytes from the phone not yet accepted by the (non-blocking) local
    // socket; drained on POLLOUT. Bounded by ADB_OUTQ_MAX.
    uint8_t *outq; size_t outq_len, outq_cap;
    int remote_closed;                // peer CLOSE seen: free once outq drains
} adb_stream_t;

// Sends one JSON text frame on the Noise channel. Returns 0 on success.
typedef int (*adb_send_fn)(void *ctx, const char *json, size_t len);
// Backpressure: 1 while the channel's send queue is backed up — streams are
// then not polled for input, so the local adb blocks instead of us buffering.
typedef int (*adb_busy_fn)(void *ctx);

typedef struct {
    adb_listener_t listeners[ADB_MAX_LISTENERS];
    adb_stream_t streams[ADB_MAX_STREAMS];
    uint32_t next_id;
    adb_send_fn send;
    adb_busy_fn busy;
    void *send_ctx;
} adb_relay_t;

void adb_relay_init(adb_relay_t *r, adb_send_fn send, adb_busy_fn busy, void *ctx);
void adb_relay_close_all(adb_relay_t *r);

// Find-or-create the listener for phone+port_spec. Returns the loopback port
// (>0) or 0 with `err` filled.
uint16_t adb_relay_listener(adb_relay_t *r, const char *phone, const char *port_spec,
                            char *err, size_t err_cap);
// Last backend-reported close error for that listener's streams (e.g. "phone
// not online"); "" when none. Lets `__adb` explain a refused connect.
const char *adb_relay_last_error(adb_relay_t *r, const char *phone, const char *port_spec);
// Loopback port of an existing listener (0 = none) — `adb disconnect <name>`.
uint16_t adb_relay_lookup(adb_relay_t *r, const char *phone, const char *port_spec);
// Drop the listener and its streams. Returns the port it had (0 = none).
uint16_t adb_relay_forget(adb_relay_t *r, const char *phone, const char *port_spec);

// poll() integration: append our fds to pfds[*n] (cap = total slots) …
void adb_relay_fill_pfds(adb_relay_t *r, struct pollfd *pfds, size_t *n, size_t cap);
// … then, after poll(), service the same slots (accept / read / EOF).
void adb_relay_service(adb_relay_t *r, const struct pollfd *pfds, size_t first, size_t n);

// Frames from the backend. `payload` spans the JSON payload object.
void adb_relay_on_data(adb_relay_t *r, const char *payload, size_t len);
void adb_relay_on_close(adb_relay_t *r, const char *payload, size_t len);

// Drop every stream (backend connection lost); listeners stay so a reconnect
// keeps `adb connect` working.
void adb_relay_drop_streams(adb_relay_t *r);

#endif

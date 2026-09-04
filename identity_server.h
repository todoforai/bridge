// Loopback identity endpoint — how a web frontend learns which paired device
// is the machine it is running on.
//
// https://todofor.ai can fetch http://127.0.0.1:43127/identity (loopback is a
// secure context, so this is not mixed content; Chrome asks the user once for
// "local network access"). We answer {deviceId, name} and the frontend reports
// deviceId as ClientContext.localDeviceId — the backend keeps it only if it is
// one of the user's own devices, so a spoofed answer buys nothing. CORS is
// scoped to todofor.ai / localhost:3000 origins; any other site can at most
// see that the port is open.
//
// Same port the bun edge's browser-extension bridge uses: whichever daemon
// holds it answers, and either answer names a device on this machine.
#ifndef BRIDGE_IDENTITY_SERVER_H
#define BRIDGE_IDENTITY_SERVER_H

#include "ws.h"  // ws_fd_t, WS_INVALID_FD

#define IDENTITY_SERVER_PORT 43127

// Bind + listen on 127.0.0.1:IDENTITY_SERVER_PORT (non-blocking). Returns the
// listening fd, or the platform invalid fd when the port is taken — the bridge
// runs fine without it, so callers just skip polling.
ws_fd_t bridge_identity_server_open(void);

// Accept and answer one pending connection (call on POLLIN of the listen fd).
// The whole exchange shares one ~300ms budget, so a slow local client can
// never stall the daemon loop for longer than that.
void bridge_identity_server_serve(ws_fd_t listen_fd, const char *device_id);

void bridge_identity_server_close(ws_fd_t listen_fd);

#endif

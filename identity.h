#ifndef BRIDGE_IDENTITY_H
#define BRIDGE_IDENTITY_H

#include <stddef.h>

#define BRIDGE_VERSION "0.1.0"

// Build identity JSON into out. Returns length written, or -1 on overflow.
// `top_level`: when non-zero, emit just the inner data object (for embedding
// in other payloads like enroll redeem). When zero, wrap as a control message.
int bridge_identity_json(char *out, size_t out_cap, int top_level);

// Populate provided buffers with identity strings. Returns 0.
// Caller-owned buffers: caller must ensure each is large enough.
typedef struct {
    char os[65];             // uname.sysname: "Linux", "Darwin", …
    char arch[65];           // uname.machine
    char hostname[65];
    char kernel[65];         // uname.release
    char distro[65];         // "ubuntu", "debian", "macos", "windows" — best-effort
    char distro_version[32]; // "22.04", "14.5", "10.0.19045"
    char device_type[16];    // matches DeviceType enum: "PC", "SANDBOX", "UNKNOWN"
    char user[64];
    char shell[128];
    char home[256];
    char cwd[512];
} bridge_identity_t;

void bridge_identity_gather(bridge_identity_t *id);

#endif

#ifndef BRIDGE_IDENTITY_H
#define BRIDGE_IDENTITY_H

#include <stddef.h>

#define BRIDGE_VERSION "0.1.0"

// Build identity JSON into out. Returns length written, or -1 on overflow.
int bridge_identity_json(char *out, size_t out_cap);

// Populate provided buffers with identity strings. Returns 0.
// Caller-owned buffers: caller must ensure each is large enough.
typedef struct {
    char os[65];
    char arch[65];
    char hostname[65];
    char kernel[65];
    char user[64];
    char shell[128];
    char home[256];
    char cwd[512];
} bridge_identity_t;

void bridge_identity_gather(bridge_identity_t *id);

#endif

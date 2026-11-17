#ifndef BRIDGE_WEBFETCH_H
#define BRIDGE_WEBFETCH_H
#include <stddef.h>

typedef int (*webfetch_relay_fn)(const char *name, int argc, char **argv, const char *input, size_t size);
int cmd_webfetch(int argc, char **argv, webfetch_relay_fn relay);
#endif

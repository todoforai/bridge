#ifndef WEBFETCH_ALLOC_H
#define WEBFETCH_ALLOC_H
#include <stdio.h>
#include <stdlib.h>

/* Converter only runs in the short-lived CLI, never in the daemon. */
static inline void *md_alloc(void *p) {
    if (!p) { fputs("tfa-webfetch: out of memory\n", stderr); exit(1); }
    return p;
}
#endif

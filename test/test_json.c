// json.c robustness: deep nesting from a hostile peer must be rejected, not
// recursed into until the stack is gone. Also pins the happy path so the depth
// cap can't silently break normal frames.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

static int fails = 0;
#define CHECK(cond, label) do { \
    int ok_ = (cond); printf("  %-44s %s\n", label, ok_ ? "ok" : "FAIL"); \
    if (!ok_) fails++; } while (0)

// {"k":[[[[...]]]],"v":"x"} with `n` nested arrays.
static char *nested(size_t n) {
    char *s = malloc(2 * n + 32);
    size_t o = 0;
    o += (size_t)sprintf(s + o, "{\"k\":");
    for (size_t i = 0; i < n; i++) s[o++] = '[';
    for (size_t i = 0; i < n; i++) s[o++] = ']';
    o += (size_t)sprintf(s + o, ",\"v\":\"x\"}");
    s[o] = '\0';
    return s;
}

int main(void) {
    const char *v; size_t vl;

    printf("nesting:\n");
    char *shallow = nested(16);
    CHECK(json_get_str(shallow, strlen(shallow), "v", &v, &vl) == 1 && vl == 1 && *v == 'x',
          "16 levels: key after nest still found");
    free(shallow);

    char *deep = nested(100000);
    CHECK(json_get_str(deep, strlen(deep), "v", &v, &vl) == 0,
          "100k levels: rejected (no stack overflow)");
    free(deep);

    printf("\nobjects:\n");
    const char *obj = "{\"a\":{\"b\":{\"c\":1}},\"d\":true}";
    int b = 0;
    CHECK(json_get_bool(obj, strlen(obj), "d", &b) == 1 && b == 1, "key after nested object");

    printf("\n%s\n", fails ? "FAILED" : "all ok");
    return fails ? 1 : 0;
}

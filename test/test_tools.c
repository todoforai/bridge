// bridge_scan_tools + custom_tools.json smoke test.
// Points $HOME at a temp dir with a crafted custom_tools.json, feeds a small
// catalog, asserts: hidden catalog tool dropped, description/label overrides
// attached, non-catalog binary probed via `command -v`, unsafe names skipped.
#define _POSIX_C_SOURCE 200809L
#include "tools.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("ok   %s\n", msg); \
    else { printf("FAIL %s\n", msg); fails++; } \
} while (0)

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    fputs(content, f);
    fclose(f);
}

// b64-encode a command for a catalog line.
static void enc(const char *cmd, char *out, size_t cap) {
    if (!b64_encode((const uint8_t *)cmd, strlen(cmd), out, cap)) exit(1);
}

int main(void) {
    // Sandbox HOME
    char home[] = "/tmp/bridge-test-tools-XXXXXX";
    if (!mkdtemp(home)) { perror("mkdtemp"); return 1; }
    char dir[512], cfg[512];
    snprintf(dir, sizeof(dir), "%s/.todoforai", home);
    mkdir(dir, 0755);
    snprintf(cfg, sizeof(cfg), "%s/custom_tools.json", dir);
    setenv("HOME", home, 1);

    write_file(cfg,
        "{\n"
        "  \"echotool\": {\"enabled\": false},\n"
        "  \"lstool\":   {\"description\": \"my ls\", \"label\": \"LS\"},\n"
        "  \"sh\":       {\"description\": \"custom shell CLI\"},\n"
        "  \"no-such-bin-xyz\": {\"description\": \"ghost\"},\n"
        "  \"bad;name\": {\"description\": \"evil\"}\n"
        "}\n");

    // Catalog: echotool (hidden by custom), lstool (override), plainver (untouched)
    char v[512], entries[2048];
    size_t n = 0;
    enc("echo v1", v, sizeof(v));
    n += (size_t)snprintf(entries + n, sizeof(entries) - n, "echotool\t%s\t\n", v);
    n += (size_t)snprintf(entries + n, sizeof(entries) - n, "lstool\t%s\t\n", v);
    n += (size_t)snprintf(entries + n, sizeof(entries) - n, "plainver\t%s\t", v);

    char out[16384];
    bridge_scan_stats_t st;
    int len = bridge_scan_tools(entries, n, out, sizeof(out), &st);
    CHECK(len > 0, "scan returns JSON");
    if (len <= 0) return 1;
    printf("---\n%.*s\n---\n", len, out);

    CHECK(strstr(out, "\"echotool\"") == NULL, "disabled catalog tool dropped");
    CHECK(strstr(out, "\"plainver\":{\"installed\":true") != NULL, "plain catalog tool probed");
    CHECK(strstr(out, "\"lstool\"") && strstr(out, "\"description\":\"my ls\"") && strstr(out, "\"label\":\"LS\""),
          "catalog tool carries description+label overrides");
    // `sh` exists on every POSIX box → command -v succeeds
    CHECK(strstr(out, "\"sh\":{\"installed\":true") != NULL, "non-catalog binary found via command -v");
    CHECK(strstr(out, "custom shell CLI") != NULL, "non-catalog binary carries description");
    CHECK(strstr(out, "no-such-bin-xyz") == NULL, "missing binary not reported installed");
    CHECK(strstr(out, "bad;name") == NULL, "unsafe name skipped");

    // Duplicate key: last value wins (JSON.parse parity)
    write_file(cfg,
        "{\"echotool\": {\"enabled\": false}, \"echotool\": {\"label\": \"Echo\"}}\n");
    len = bridge_scan_tools(entries, n, out, sizeof(out), &st);
    CHECK(len > 0 && strstr(out, "\"echotool\"") && strstr(out, "\"label\":\"Echo\""),
          "duplicate key: last wins (tool visible with label)");

    // Malformed file → all-or-nothing: nothing applied
    write_file(cfg, "{\"echotool\": {\"enabled\": false}, \"lstool\": ");
    len = bridge_scan_tools(entries, n, out, sizeof(out), &st);
    CHECK(len > 0 && strstr(out, "\"echotool\":{\"installed\":true") != NULL,
          "malformed config ignored entirely (no partial apply)");

    // No config file at all → plain catalog behavior
    unlink(cfg);
    len = bridge_scan_tools(entries, n, out, sizeof(out), &st);
    CHECK(len > 0 && strstr(out, "\"echotool\":{\"installed\":true") != NULL,
          "without config: catalog tool back to normal");

    printf("%s\n", fails ? "FAILED" : "PASSED");
    return fails ? 1 : 0;
}

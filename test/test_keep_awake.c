// Keep-awake: idle timer (pure), config.json round-trip under a scratch
// config dir, and — when systemd-inhibit works here — that the hold really
// shows up in `systemd-inhibit --list` and goes away on release.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "keep_awake.h"
#include "policy.h"

static int fails = 0;
#define CHECK(c, l) do { int ok_ = (c); printf("  %-52s %s\n", l, ok_ ? "ok" : "FAIL"); if (!ok_) fails++; } while (0)

static int inhibit_listed(void) {
    FILE *p = popen("systemd-inhibit --list --no-pager 2>/dev/null | grep -c 'TODOforAI task running'", "r");
    if (!p) return -1;
    int n = -1;
    if (fscanf(p, "%d", &n) != 1) n = -1;
    pclose(p);
    return n;
}

int main(void) {
    const int64_t G = KEEP_AWAKE_GRACE_MS;
    printf("idle timer\n");
    keep_awake_timer_t t = {0};
    CHECK(!keep_awake_want(&t, 0, 1, 0),           "disabled: never held, even when busy");
    CHECK(!keep_awake_want(&t, 1, 0, 0),           "enabled + idle from start: not held");
    CHECK( keep_awake_want(&t, 1, 1, 1000),        "busy: held");
    CHECK( keep_awake_want(&t, 1, 0, 1000 + G - 1),"idle < grace: still held");
    CHECK( keep_awake_want(&t, 1, 1, 1000 + G - 1),"busy again: held, grace restarts");
    CHECK( keep_awake_want(&t, 1, 0, 1000 + 2*G - 2),"grace measured from last busy tick");
    CHECK(!keep_awake_want(&t, 1, 0, 1000 + 2*G - 1),"idle ≥ grace: released");
    CHECK(!keep_awake_want(&t, 1, 0, 1000 + 9*G),  "stays released while idle");
    CHECK( keep_awake_want(&t, 1, 1, 1000 + 9*G),  "next task: held again");
    CHECK(!keep_awake_want(&t, 0, 1, 1000 + 9*G),  "disabled mid-task: released at once");

    printf("config.json\n");
    char tmpl[] = "/tmp/ka-test-XXXXXX";
    if (!mkdtemp(tmpl)) { perror("mkdtemp"); return 1; }
    setenv("XDG_CONFIG_HOME", tmpl, 1);
    setenv("HOME", tmpl, 1);   // macOS ignores XDG: never touch the real config
    CHECK(keep_awake_load() == 0,                   "no file: off");
    CHECK(keep_awake_save(1) == 0 && keep_awake_load() == 1, "save on → load on");
    CHECK(keep_awake_save(0) == 0 && keep_awake_load() == 0, "save off → load off");
    char dir[512], path[600];
    if (bridge_config_dir(dir, sizeof dir) != 0) { puts("no config dir"); return 1; }
    snprintf(path, sizeof path, "%s/config.json", dir);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL,                                "config.json in scratch dir");
    if (f) { fputs("{\"keep_awake\": \"yes\"}", f); fclose(f); }
    CHECK(keep_awake_load() == 0,                   "non-boolean: off");
    f = fopen(path, "w");
    if (f) { fputs("garbage", f); fclose(f); }
    CHECK(keep_awake_load() == 0,                   "garbage: off");

    printf("daemon flow\n");
    keep_awake_save(0);
    CHECK(!keep_awake_tick(0, 0) || !keep_awake_active(), "default off: no hold");
    keep_awake_tick(1, 10);
    CHECK(!keep_awake_active(),                     "off + busy: no hold");
    keep_awake_tick(0, 20);
    CHECK(keep_awake_set(1) == 1 && keep_awake_enabled(), "set(1) reports change, persists");
    CHECK(keep_awake_load() == 1,                   "set(1) wrote config.json");

    int before = inhibit_listed();
    int changed = keep_awake_tick(1, 100);
    CHECK(changed && keep_awake_active(),           "busy: hold taken, change reported");
    char js[96]; keep_awake_state_json(js, sizeof js);
    CHECK(strstr(js, "\"enabled\":true,\"active\":true") != NULL, "state json: enabled+active");
    usleep(300 * 1000);   // let systemd-inhibit register with logind
    keep_awake_tick(1, 200);
    int during = inhibit_listed();
    if (before < 0 || !keep_awake_active()) {
        printf("  (no working sleep inhibitor here — skipping OS checks)\n");
    } else {
        CHECK(during == before + 1,                 "systemd-inhibit --list shows the hold");
        keep_awake_tick(0, 300);
        CHECK(keep_awake_active(),                  "idle within grace: still held");
        CHECK(keep_awake_tick(0, 300 + G) && !keep_awake_active(), "after grace: released");
        usleep(200 * 1000);
        CHECK(inhibit_listed() == before,           "inhibitor gone from --list");
        keep_awake_tick(1, 10 * G);
        CHECK(keep_awake_active(),                  "next task: held again");
        keep_awake_save(0);
        CHECK(keep_awake_tick(1, 10 * G + 30000) && !keep_awake_active(), "config off mid-task: released ≤30s");
        keep_awake_set(1);
        keep_awake_tick(1, 10 * G + 30001);
        CHECK(keep_awake_release() == 1 && !keep_awake_active(), "release(): drops the hold now");
    }

    char cmd[600]; snprintf(cmd, sizeof cmd, "rm -rf %s", tmpl); (void)!system(cmd);
    printf(fails ? "FAILED (%d)\n" : "all ok\n", fails);
    return fails ? 1 : 0;
}

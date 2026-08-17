// Auto-update gating: which (running version, latest release) pairs may
// replace the binary unattended. Pure version/env logic — no download, no
// exit — so it runs anywhere.
//
// Compiled twice (see `make test-update`): once with a release BRIDGE_VERSION,
// once with a dev one, because "a dev build never auto-updates" is a property
// of the version baked in at compile time.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "update.h"

static int fails = 0;

static void check(const char *latest, int expect, const char *label) {
    int got = bridge_update_wanted(latest);
    printf("  %-36s %s\n", label, got == expect ? "ok" : "FAIL");
    if (got != expect) {
        printf("      got %d, expected %d (latest=%s)\n", got, expect, latest ? latest : "(null)");
        fails++;
    }
}

int main(void) {
    // A dev/dirty build must never be swapped for a release behind the user's
    // back, so every case below collapses to "no update" on such a build.
    int dev = strpbrk(BRIDGE_VERSION, "-+") != NULL;
    printf("running as %s (%s build)\n", BRIDGE_VERSION, dev ? "dev" : "release");

    // A supervisor is what makes exit-to-apply safe; fake systemd's marker.
    setenv("INVOCATION_ID", "test", 1);
    unsetenv("TODOFORAI_NO_AUTO_UPDATE");

    printf("\nnewer releases:\n");
    check("v1.5.8", !dev, "newer patch");
    check("v1.6.0", !dev, "newer minor");
    check("v2.0.0", !dev, "newer major");

    printf("\nnot an upgrade:\n");
    check("v1.5.7",  0, "same version");
    check("v1.5.6",  0, "older — never downgrade");
    check("v1.4.99", 0, "older minor");
    check("v0.9.9",  0, "older major");

    printf("\nrefused input:\n");
    check(NULL,         0, "null");
    check("",           0, "empty");
    check("garbage",    0, "unparseable");
    check("v1.5",       0, "truncated semver");
    check("v1.6.0-rc1", 0, "prerelease — never unattended");

    printf("\nopt-outs:\n");
    setenv("TODOFORAI_NO_AUTO_UPDATE", "1", 1);
    check("v9.9.9", 0, "TODOFORAI_NO_AUTO_UPDATE=1");
    unsetenv("TODOFORAI_NO_AUTO_UPDATE");

    unsetenv("INVOCATION_ID");
    // getppid()==1 is itself a supervised signal, so this case only means
    // anything when the harness has a normal parent (make, a shell).
    if (getppid() != 1) check("v9.9.9", 0, "unsupervised — nothing restarts us");

    printf(fails ? "\n%d FAILURE(S)\n" : "\nall passed\n", fails);
    return fails != 0;
}

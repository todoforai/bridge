// Device policy: path prefix checks (symlink / `..` escapes) and, on Linux
// with Landlock, that a jailed PTY child really can't read outside the
// workspaces. Runs under a scratch $HOME so the real policy is untouched.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include "policy.h"
#include "pty.h"

static int fails = 0;
#define CHECK(c, l) do { int ok_ = (c); printf("  %-52s %s\n", l, ok_ ? "ok" : "FAIL"); if (!ok_) fails++; } while (0)

static void touch(const char *p, const char *s) { FILE *f = fopen(p, "w"); if (f) { fputs(s, f); fclose(f); } }

// Run `cmd` in a bridge PTY (jailed if policy says so), return its stdout.
static int run_pty(const char *cmd, const char *cwd, char *out, size_t cap) {
    bridge_pty_t p; memset(&p, 0, sizeof p);
    if (bridge_pty_spawn(&p, "/bin/sh", cwd, 1) != 0) return -1;
    char line[1024];
    snprintf(line, sizeof line, "%s; echo __RC=$?; exit\n", cmd);
    bridge_pty_write_all(&p, line, strlen(line));
    size_t u = 0;
    for (int i = 0; i < 200 && u + 1 < cap; i++) {
        struct pollfd pf = { p.master_fd, POLLIN, 0 };
        if (poll(&pf, 1, 50) <= 0) { int code; if (bridge_pty_reap(&p, &code)) break; continue; }
        ssize_t n = read(p.master_fd, out + u, cap - 1 - u);
        if (n <= 0) { int code; if (bridge_pty_reap(&p, &code)) break; continue; }
        u += (size_t)n;
    }
    out[u] = '\0';
    bridge_pty_close(&p);
    return 0;
}

int main(void) {
    // Not under /tmp: the jail grants /tmp read-write, which would make a
    // /tmp-rooted scratch $HOME reachable and void the test.
    char t[512];
    const char *real_home = getenv("HOME");
    snprintf(t, sizeof t, "%s/.cache/bridge-policytest.XXXXXX", real_home ? real_home : "/var/tmp");
    if (!mkdtemp(t)) { perror("mkdtemp"); return 1; }
    char ws[600], other[600], secret[600], link[700], cfg[600];
    snprintf(ws, sizeof ws, "%s/ws", t);        mkdir(ws, 0700);
    snprintf(other, sizeof other, "%s/other", t); mkdir(other, 0700);
    snprintf(secret, sizeof secret, "%s/.ssh", t); mkdir(secret, 0700);
    snprintf(link, sizeof link, "%s/link", ws);  symlink(other, link);
    snprintf(cfg, sizeof cfg, "%s/cfg", t);
    char f[800];
    snprintf(f, sizeof f, "%s/id_rsa", secret); touch(f, "PRIVATE");
    snprintf(f, sizeof f, "%s/in.txt", ws);     touch(f, "inside");
    snprintf(f, sizeof f, "%s/out.txt", other); touch(f, "outside");
    setenv("HOME", t, 1);
    setenv("XDG_CONFIG_HOME", cfg, 1);

    printf("inactive:\n");
    bridge_policy_load();
    CHECK(!g_policy.active, "no file → inactive");
    CHECK(bridge_policy_path_allowed("/etc/passwd"), "inactive allows everything");

    // Write a policy through the CLI path (also covers save/parse).
    char *argv_init[] = { "policy", "init", ws, NULL };
    CHECK(cmd_policy(3, argv_init) == 0, "policy init");
    bridge_policy_load();
    CHECK(g_policy.active && g_policy.n == 1 && g_policy.jail, "reloaded: active, 1 ws, jail on");

    printf("\nprefix checks:\n");
    snprintf(f, sizeof f, "%s/in.txt", ws);          CHECK(bridge_policy_path_allowed(f), "file in ws");
    snprintf(f, sizeof f, "%s/new/deep/x.c", ws);    CHECK(bridge_policy_path_allowed(f), "not-yet-existing path under ws");
    snprintf(f, sizeof f, "%s", ws);                 CHECK(bridge_policy_path_allowed(f), "ws itself");
    snprintf(f, sizeof f, "%s2/x", ws);              CHECK(!bridge_policy_path_allowed(f), "sibling with same prefix (ws2)");
    snprintf(f, sizeof f, "%s/../other/out.txt", ws);CHECK(!bridge_policy_path_allowed(f), ".. escape");
    snprintf(f, sizeof f, "%s/link/out.txt", ws);    CHECK(!bridge_policy_path_allowed(f), "symlink escape");
    snprintf(f, sizeof f, "%s/id_rsa", secret);      CHECK(!bridge_policy_path_allowed(f), "$HOME/.ssh");
    CHECK(!bridge_policy_path_allowed("~/.ssh/id_rsa"), "~ expansion then deny");
    CHECK(!bridge_policy_path_allowed("relative/x"), "relative path denied");
    char em[2200];
    bridge_policy_deny_msg("/x", em, sizeof em);
    CHECK(strstr(em, "policy add \"/x\"") != NULL, "deny message names the fix command");
    CHECK(strcmp(bridge_policy_default_cwd(), ws) == 0, "default cwd = first workspace");

    printf("\npolicy_open:\n");
    snprintf(f, sizeof f, "%s/in.txt", ws);
    int fd = bridge_policy_open(f, O_RDONLY, 0);
    CHECK(fd >= 0, "opens file in ws"); if (fd >= 0) close(fd);
    // Dangling symlink inside ws pointing outside: canon() can't resolve the
    // missing target, so a naive open(O_CREAT) would create it outside.
    snprintf(f, sizeof f, "%s/dangling", ws);
    char target[700]; snprintf(target, sizeof target, "%s/created-outside", other);
    symlink(target, f);
    fd = bridge_policy_open(f, O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) close(fd);
    CHECK(access(target, F_OK) != 0, "dangling symlink → no file created outside ws");
    snprintf(f, sizeof f, "%s/link/out.txt", ws);
    fd = bridge_policy_open(f, O_RDONLY, 0);
    CHECK(fd < 0, "symlinked dir escape refused by open"); if (fd >= 0) close(fd);
    snprintf(f, sizeof f, "%s/id_rsa", secret);
    fd = bridge_policy_open(f, O_RDONLY, 0);
    CHECK(fd < 0 && errno == EACCES, "outside → EACCES"); if (fd >= 0) close(fd);
    snprintf(f, sizeof f, "%s/new/deep.txt", ws);
    fd = bridge_policy_open(f, O_WRONLY | O_CREAT, 0600);
    CHECK(fd < 0 && errno == ENOENT, "missing parent inside ws → ENOENT (not EACCES)"); if (fd >= 0) close(fd);

    printf("\nfail closed:\n");
    char pj[700]; snprintf(pj, sizeof pj, "%s/todoforai/policy.json", cfg);
    touch(pj, "{\"workspaces\":[\"/x\",123]}");
    bridge_policy_load();
    CHECK(g_policy.active && g_policy.broken, "non-string entry → broken");
    CHECK(!bridge_policy_path_allowed("/x"), "broken denies even listed ws");
    CHECK(bridge_policy_jail_child() == -1, "broken: jail refuses (child would _exit)");
    touch(pj, "{}");
    bridge_policy_load();
    CHECK(g_policy.broken, "{} → broken (no workspaces array)");
    touch(pj, "{\"jail\":\"yes\",\"workspaces\":[]}");
    bridge_policy_load();
    CHECK(g_policy.broken, "jail as string → broken");
    touch(pj, "{\"workspaces\":[\"/a\"");
    bridge_policy_load();
    CHECK(g_policy.broken, "truncated array → broken");
    char cfgws[700]; snprintf(cfgws, sizeof cfgws, "{\"workspaces\":[\"%s\"]}", cfg);
    touch(pj, cfgws);
    bridge_policy_load();
    CHECK(g_policy.broken, "workspace covering the config dir → broken");
    char *argv_add[] = { "policy", "add", cfg, NULL };
    touch(pj, "{\"workspaces\":[]}");
    CHECK(cmd_policy(3, argv_add) != 0, "policy add <config dir> refused");
    touch(pj, "{\"jail\":false,\"workspaces\":[]}");
    bridge_policy_load();
    CHECK(g_policy.active && !g_policy.broken && !g_policy.jail && g_policy.n == 0, "empty ws list + jail:false is valid");
    touch(pj, "");
    bridge_policy_load();
    CHECK(g_policy.active && g_policy.broken, "empty file → broken, not inactive");
    touch(pj, "{\"jail\":false,\"workspaces\":[]} trailing");
    bridge_policy_load();
    CHECK(g_policy.broken, "trailing garbage → broken");
    touch(pj, "{\"workspaces\":[]");
    bridge_policy_load();
    CHECK(g_policy.broken, "unclosed object → broken");
    touch(pj, "{\"jail\":null,\"workspaces\":[]}");
    bridge_policy_load();
    CHECK(g_policy.broken, "jail:null → broken");
    touch(pj, "{\"jail\":true,\"jail\":false,\"workspaces\":[]}");
    bridge_policy_load();
    CHECK(g_policy.broken, "duplicate jail key → broken");
    touch(pj, "{\"workspaces\":[],\"extra\":1}");
    bridge_policy_load();
    CHECK(g_policy.broken, "unknown key → broken");
    touch(pj, "{\"jail\":false,\"workspaces\":[123]}");
    bridge_policy_load();
    CHECK(g_policy.broken && bridge_policy_jail_child() == -1, "broken + jail:false still refuses shells");
    char inner[700]; snprintf(inner, sizeof inner, "{\"workspaces\":[\"%s/todoforai/sub\"]}", cfg);
    touch(pj, inner);
    bridge_policy_load();
    CHECK(g_policy.broken, "workspace inside the config dir → broken");
    // restore the real one for the jail tests
    char *argv_init2[] = { "policy", "init", ws, NULL };
    unlink(pj);
    cmd_policy(3, argv_init2);
    bridge_policy_load();

#ifdef __linux__
    printf("\nlandlock jail (PTY child):\n");
    char out[8192];
    char cmd[2048];
    snprintf(cmd, sizeof cmd, "cat %s/in.txt", ws);
    run_pty(cmd, ws, out, sizeof out);
    CHECK(strstr(out, "inside") != NULL, "reads inside ws");
    snprintf(cmd, sizeof cmd, "cat %s/id_rsa 2>&1", secret);
    run_pty(cmd, ws, out, sizeof out);
    CHECK(strstr(out, "PRIVATE") == NULL, "cannot read $HOME/.ssh (Landlock)");
    snprintf(cmd, sizeof cmd, "cat %s/todoforai/policy.json 2>/dev/null && echo POLICY_READ", cfg);
    run_pty(cmd, ws, out, sizeof out);
    CHECK(strstr(out, "POLICY_READ") == NULL, "cannot read policy.json from the jail");
    snprintf(cmd, sizeof cmd, "ls %s 2>/dev/null && echo HOME_LISTED", t);
    run_pty(cmd, ws, out, sizeof out);
    CHECK(strstr(out, "HOME_LISTED") == NULL, "cannot list $HOME");
    snprintf(cmd, sizeof cmd, "echo hi > %s/w.txt && cat %s/w.txt", ws, ws);
    run_pty(cmd, ws, out, sizeof out);
    CHECK(strstr(out, "\nhi") != NULL || strstr(out, "hi\r") != NULL, "writes inside ws");
    snprintf(cmd, sizeof cmd, "echo x > %s/w.txt 2>/dev/null && echo WROTE_OUTSIDE", other);
    run_pty(cmd, ws, out, sizeof out);
    CHECK(strstr(out, "WROTE_OUTSIDE") == NULL, "cannot write outside ws");
    run_pty("ls /usr/bin >/dev/null && echo TOOLS_OK", ws, out, sizeof out);
    CHECK(strstr(out, "TOOLS_OK") != NULL, "system dirs readable");
    run_pty("echo t > /tmp/policytest.scratch && echo TMP_OK", ws, out, sizeof out);
    CHECK(strstr(out, "TMP_OK") != NULL, "/tmp writable");
    unlink("/tmp/policytest.scratch");
#endif

    char rm[700]; snprintf(rm, sizeof rm, "rm -rf '%s'", t); (void)system(rm);
    printf("\n%s\n", fails ? "FAILED" : "all ok");
    return fails ? 1 : 0;
}

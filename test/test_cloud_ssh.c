// Native cloud SSH (cloud_ssh.c): input validation, ssh_config conflict
// detection, rendering, and the real ssh-keygen / `ssh -G` path.
//
// Never touches the real ~/.ssh: every apply runs against a mkdtemp dir with
// `ssh -F <tmp>/config`, and HOME is pointed at the temp dir as well.
//
// Build/run: make test-cloud-ssh
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "../cloud_ssh.h"
#include "../json.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static const char *UUID = "0f8fad5b-d9cb-469f-a165-70867728950e";
static char HOSTKEY[96];

static void make_hostkey(char *out, unsigned char fill) {
    unsigned char blob[51] = { 0,0,0,11, 's','s','h','-','e','d','2','5','5','1','9', 0,0,0,32 };
    memset(blob + 19, fill, 32);
    strcpy(out, "ssh-ed25519 ");
    b64_encode(blob, sizeof blob, out + 12, 80);
}

static int vs(int (*f)(const char *, size_t), const char *s) { return f(s, strlen(s)); }

static int parse(const char *json, cloud_ssh_cfg_t *c) {
    const char *err;
    return cloud_ssh_parse_config(json, strlen(json), c, &err);
}

static void cfg_json(char *out, size_t cap, const char *host, const char *port, const char *user,
                     const char *key, const char *id) {
    snprintf(out, cap, "{\"type\":\"cloud_ssh_config\",\"host\":\"%s\",\"port\":%s,\"user\":\"%s\","
                       "\"hostKey\":\"%s\",\"cloudDeviceId\":\"%s\"}", host, port, user, key, id);
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *b = calloc(1, 1 << 20);
    size_t n = fread(b, 1, (1 << 20) - 1, f);
    b[n] = '\0';
    fclose(f);
    return b;
}

static void spit(const char *path, const char *s) {
    FILE *f = fopen(path, "wb"); assert(f); fputs(s, f); fclose(f);
}

static char *pj(const cloud_ssh_env_t *env, const char *name) {
    static char b[4][1024]; static int i;
    i = (i + 1) % 4;
    snprintf(b[i], sizeof b[i], "%s/%s", env->dir, name);
    return b[i];
}

static void fresh_env(cloud_ssh_env_t *env, const char *root, const char *sub) {
    memset(env, 0, sizeof *env);
    snprintf(env->dir, sizeof env->dir, "%s/%s", root, sub);
    env->use_F = 1;
    env->skip_connect = 1;
}

static cloud_ssh_cfg_t base_cfg(const char *host, long port, const char *profile) {
    cloud_ssh_cfg_t c; memset(&c, 0, sizeof c);
    snprintf(c.host, sizeof c.host, "%s", host);
    c.port = port;
    snprintf(c.host_key, sizeof c.host_key, "%s", HOSTKEY);
    snprintf(c.device_id, sizeof c.device_id, "%s", UUID);
    snprintf(c.profile, sizeof c.profile, "%s", profile);
    return c;
}

static void test_validators(void) {
    CHECK(vs(cloud_ssh_valid_host, "ssh.todofor.ai"));
    CHECK(vs(cloud_ssh_valid_host, "10.0.0.5"));
    CHECK(vs(cloud_ssh_valid_host, "2001:db8::1"));
    CHECK(!vs(cloud_ssh_valid_host, ""));
    CHECK(!vs(cloud_ssh_valid_host, "-oProxyCommand=sh"));
    CHECK(!vs(cloud_ssh_valid_host, "a b"));
    CHECK(!vs(cloud_ssh_valid_host, "host\nProxyCommand x"));
    CHECK(!vs(cloud_ssh_valid_host, "%h.evil"));
    CHECK(!vs(cloud_ssh_valid_host, "a\"b"));
    CHECK(!vs(cloud_ssh_valid_host, "a..b"));
    CHECK(!vs(cloud_ssh_valid_host, "a.-b"));
    CHECK(!vs(cloud_ssh_valid_host, "[::1]"));
    CHECK(!vs(cloud_ssh_valid_host, "g::1"));
    CHECK(!vs(cloud_ssh_valid_host, "host#x"));
    char big[300]; memset(big, 'a', 254); big[254] = '\0';
    CHECK(!vs(cloud_ssh_valid_host, big));

    CHECK(strlen(HOSTKEY) == 12 + 68);
    CHECK(vs(cloud_ssh_valid_ed25519, HOSTKEY));
    char k[128];
    snprintf(k, sizeof k, "%s comment", HOSTKEY);                 CHECK(!vs(cloud_ssh_valid_ed25519, k));
    snprintf(k, sizeof k, "%s=", HOSTKEY);                        CHECK(!vs(cloud_ssh_valid_ed25519, k));
    snprintf(k, sizeof k, "%.79s", HOSTKEY);                      CHECK(!vs(cloud_ssh_valid_ed25519, k));
    snprintf(k, sizeof k, "ssh-rsa %s", HOSTKEY + 12);            CHECK(!vs(cloud_ssh_valid_ed25519, k));
    snprintf(k, sizeof k, "ssh-ed25519  %s", HOSTKEY + 12);       CHECK(!vs(cloud_ssh_valid_ed25519, k));
    snprintf(k, sizeof k, "%s", HOSTKEY); k[40] = '\\';           CHECK(!vs(cloud_ssh_valid_ed25519, k));
    snprintf(k, sizeof k, "%s", HOSTKEY); k[40] = '-';            CHECK(!vs(cloud_ssh_valid_ed25519, k));
    // Right length, wrong inner key type.
    unsigned char blob[51] = { 0,0,0,11, 's','s','h','-','e','d','2','5','5','1','8', 0,0,0,32 };
    strcpy(k, "ssh-ed25519 "); b64_encode(blob, 51, k + 12, 100);
    CHECK(!vs(cloud_ssh_valid_ed25519, k));

    CHECK(vs(cloud_ssh_valid_uuid, UUID));
    CHECK(!vs(cloud_ssh_valid_uuid, "0f8fad5b-d9cb-469f-a165-70867728950"));
    CHECK(!vs(cloud_ssh_valid_uuid, "0f8fad5b-d9cb-469f-a165-70867728950g"));
    CHECK(!vs(cloud_ssh_valid_uuid, "0f8fad5b/d9cb-469f-a165-70867728950e"));
}

static void test_parse(void) {
    char j[1024]; cloud_ssh_cfg_t c;
    cfg_json(j, sizeof j, "ssh.todofor.ai", "2222", "root", HOSTKEY, UUID);
    CHECK(parse(j, &c) == 0 && c.port == 2222 && strcmp(c.host, "ssh.todofor.ai") == 0 &&
          strcmp(c.device_id, UUID) == 0 && strcmp(c.host_key, HOSTKEY) == 0 && !c.profile[0]);

    const char *bad_ports[] = { "0", "65536", "\"22\"", "22.5", "-1", "022", "1e3", "true", "99999999999" };
    for (size_t i = 0; i < sizeof bad_ports / sizeof *bad_ports; i++) {
        cfg_json(j, sizeof j, "h.example", bad_ports[i], "root", HOSTKEY, UUID);
        CHECK(parse(j, &c) != 0);
    }
    cfg_json(j, sizeof j, "h.example", "22", "workspace", HOSTKEY, UUID);          CHECK(parse(j, &c) != 0);
    cfg_json(j, sizeof j, "h.example", "22", "root", HOSTKEY, "not-a-uuid");   CHECK(parse(j, &c) != 0);
    cfg_json(j, sizeof j, "h.ex\\nProxyCommand x", "22", "root", HOSTKEY, UUID); CHECK(parse(j, &c) != 0);
    cfg_json(j, sizeof j, "h.example", "22", "r\\u006fot", HOSTKEY, UUID);     CHECK(parse(j, &c) != 0);
    char k2[128]; snprintf(k2, sizeof k2, "%.40s\\u002b%s", HOSTKEY, HOSTKEY + 41);
    cfg_json(j, sizeof j, "h.example", "22", "root", k2, UUID);                CHECK(parse(j, &c) != 0);
    CHECK(parse("{\"host\":\"h\"", &c) != 0);
    // Missing field.
    snprintf(j, sizeof j, "{\"host\":\"h.example\",\"port\":22,\"user\":\"root\",\"cloudDeviceId\":\"%s\"}", UUID);
    CHECK(parse(j, &c) != 0);
    // Job payload round-trip incl. profile; hostile profile rejected.
    cfg_json(j, sizeof j, "h.example", "22", "root", HOSTKEY, UUID);
    CHECK(parse(j, &c) == 0);
    strcpy(c.profile, "dev");
    char pl[1024];
    CHECK(cloud_ssh_build_payload(&c, pl, sizeof pl) > 0);
    cloud_ssh_cfg_t c2;
    CHECK(parse(pl, &c2) == 0 && strcmp(c2.profile, "dev") == 0 && c2.port == 22);
    snprintf(j, sizeof j, "{\"host\":\"h.example\",\"port\":22,\"user\":\"root\",\"hostKey\":\"%s\","
                          "\"cloudDeviceId\":\"%s\",\"profile\":\"../x\"}", HOSTKEY, UUID);
    CHECK(parse(j, &c2) != 0);

    char r[200];
    CHECK(cloud_ssh_ready_json(UUID, 1, r, sizeof r) > 0 &&
          strcmp(r, "{\"type\":\"cloud_ssh_ready\",\"cloudDeviceId\":\"0f8fad5b-d9cb-469f-a165-70867728950e\",\"ready\":true}") == 0);
    CHECK(cloud_ssh_ready_json(UUID, 0, r, sizeof r) > 0 && strstr(r, "\"ready\":false}"));
}

static int defines(const char *t) { return cloud_ssh_user_defines_alias(t, strlen(t)); }

static void test_alias_detection(void) {
    CHECK(defines("Host tfa-cloud\n  HostName x\n"));
    CHECK(defines("host foo tfa-cloud\n"));
    CHECK(defines("  HOST=tfa-cloud\n"));
    CHECK(defines("Host \"tfa-cloud\"\n"));
    CHECK(defines("Host a,tfa-cloud\n"));
    CHECK(defines("Host !tfa-cloud\n"));                  // conservative: any mention
    CHECK(defines("Match host tfa-cloud exec true\n"));
    CHECK(defines("Match originalhost tfa-cloud\n"));
    CHECK(!defines("# Host tfa-cloud\n"));
    CHECK(!defines("HostName tfa-cloud\n"));
    CHECK(!defines("Host tfa-cloud-other\n"));
    CHECK(!defines("Host *\n  User me\n"));
    CHECK(!defines("Match host tfa-cloud-x\n"));
    CHECK(!defines(""));
}

static void test_render(void) {
    cloud_ssh_cfg_t c = base_cfg("h.example", 2222, "");
    char out[4096];
    CHECK(cloud_ssh_render_config("/home/u/.ssh", &c, out, sizeof out) > 0);
    const char *must[] = {
        "Host tfa-cloud\n", "  HostName h.example\n", "  Port 2222\n", "  User root\n",
        "  IdentityFile \"/home/u/.ssh/tfa_cloud\"\n", "  IdentitiesOnly yes\n", "  IdentityAgent none\n",
        "  UserKnownHostsFile \"/home/u/.ssh/tfa_cloud_known_hosts\"\n",
        "  HostKeyAlias tfa-cloud-0f8fad5b-d9cb-469f-a165-70867728950e\n",
        "  StrictHostKeyChecking yes\n", "  ForwardAgent no\n", "  ForwardX11 no\n",
        "  ProxyCommand none\n", "  ProxyJump none\n", "  ControlMaster no\n", "  ControlPersist no\n",
        "  PasswordAuthentication no\n", "  KbdInteractiveAuthentication no\n", "# profile=default ",
        "  ControlPath none\n",
    };
    for (size_t i = 0; i < sizeof must / sizeof *must; i++) CHECK(strstr(out, must[i]) != NULL);
    // The block is closed so the rest of ~/.ssh/config stays global.
    size_t ol = strlen(out);
    CHECK(ol > 8 && strcmp(out + ol - 8, "Host *\n\n") != 0 && strcmp(out + ol - 7, "Host *\n") == 0);
    CHECK(cloud_ssh_render_config("/x", &c, out, 64) < 0);
}

static int apply(const cloud_ssh_env_t *env, const cloud_ssh_cfg_t *c, char *err) {
    return cloud_ssh_apply(env, c, err, 512);
}

static void test_apply(const char *root) {
    cloud_ssh_env_t env; char err[512]; struct stat st, st2;
    cloud_ssh_cfg_t c = base_cfg("127.0.0.1", 2222, "default");

    // Fresh: creates dir, key pair, managed files, Include; preserves user config.
    fresh_env(&env, root, "fresh");
    mkdir(env.dir, 0700);
    spit(pj(&env, "config"), "Host *\n  User someone\n  ProxyCommand nc %h %p\n");
    chmod(pj(&env, "config"), 0644);
    CHECK(apply(&env, &c, err) == 0);
    if (err[0]) fprintf(stderr, "  apply: %s\n", err);
    char *cfg = slurp(pj(&env, "config"));
    char inc[1200]; snprintf(inc, sizeof inc, "Include \"%s/tfa_cloud_config\"\n", env.dir);
    CHECK(cfg && strstr(cfg, inc) && strstr(cfg, inc) < strstr(cfg, "Host *"));
    CHECK(cfg && strstr(cfg, "Host *\n  User someone\n  ProxyCommand nc %h %p\n"));
    CHECK(stat(pj(&env, "config"), &st) == 0 && (st.st_mode & 0777) == 0644);   // mode preserved
    char *kh = slurp(pj(&env, "tfa_cloud_known_hosts"));
    char want[256]; snprintf(want, sizeof want, "tfa-cloud-%s %s\n", UUID, HOSTKEY);
    CHECK(kh && strcmp(kh, want) == 0);
    CHECK(stat(pj(&env, "tfa_cloud"), &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(stat(pj(&env, "tfa_cloud_config"), &st) == 0 && (st.st_mode & 0777) == 0600);
    char pub[128];
    CHECK(cloud_ssh_ensure_key(&env, pub, sizeof pub, err, sizeof err) == 0 &&
          cloud_ssh_valid_ed25519(pub, strlen(pub)));
    char *key1 = slurp(pj(&env, "tfa_cloud"));

    // Idempotent: nothing rewritten, Include not duplicated, key unchanged.
    struct stat a1, a2, b1, b2;
    stat(pj(&env, "config"), &a1); stat(pj(&env, "tfa_cloud_config"), &b1);
    CHECK(apply(&env, &c, err) == 0);
    stat(pj(&env, "config"), &a2); stat(pj(&env, "tfa_cloud_config"), &b2);
    CHECK(a1.st_ino == a2.st_ino && b1.st_ino == b2.st_ino);
    char *cfg2 = slurp(pj(&env, "config"));
    CHECK(cfg && cfg2 && strcmp(cfg, cfg2) == 0);
    char *key2 = slurp(pj(&env, "tfa_cloud"));
    CHECK(key1 && key2 && strcmp(key1, key2) == 0);
    free(cfg2); free(key2);

    // Endpoint refresh: managed block follows, user config untouched.
    cloud_ssh_cfg_t c3 = base_cfg("10.1.2.3", 2200, "default");
    make_hostkey(c3.host_key, 0x42);
    CHECK(apply(&env, &c3, err) == 0);
    char *mc = slurp(pj(&env, "tfa_cloud_config"));
    CHECK(mc && strstr(mc, "HostName 10.1.2.3\n") && strstr(mc, "Port 2200\n"));
    kh = (free(kh), slurp(pj(&env, "tfa_cloud_known_hosts")));
    CHECK(kh && strstr(kh, c3.host_key) && !strstr(kh, HOSTKEY));
    cfg2 = slurp(pj(&env, "config"));
    CHECK(cfg && cfg2 && strcmp(cfg, cfg2) == 0);
    free(cfg); free(cfg2); free(mc); free(kh); free(key1);

    // Another credential profile must not hijack the managed block.
    cloud_ssh_cfg_t cdev = base_cfg("127.0.0.1", 2222, "dev");
    CHECK(apply(&env, &cdev, err) != 0 && strstr(err, "another bridge profile"));

    // Connect probe runs and fails fast against a closed port → not ready.
    env.skip_connect = 0;
    cloud_ssh_cfg_t cp = base_cfg("127.0.0.1", 1, "default");
    CHECK(apply(&env, &cp, err) != 0 && strstr(err, "ssh probe failed"));
    env.skip_connect = 1;

    // User already owns the alias: refuse, write nothing.
    fresh_env(&env, root, "useralias");
    mkdir(env.dir, 0700);
    spit(pj(&env, "config"), "Host tfa-cloud\n  HostName mine.example\n");
    CHECK(apply(&env, &c, err) != 0 && strstr(err, "already defines"));
    cfg = slurp(pj(&env, "config"));
    CHECK(cfg && strcmp(cfg, "Host tfa-cloud\n  HostName mine.example\n") == 0);
    free(cfg);
    CHECK(access(pj(&env, "tfa_cloud"), F_OK) != 0 && access(pj(&env, "tfa_cloud_config"), F_OK) != 0);

    // Alias defined in a file the user Includes: refuse, write nothing.
    fresh_env(&env, root, "incalias");
    mkdir(env.dir, 0700);
    char incl[2048];
    snprintf(incl, sizeof incl, "Include \"%s/conf.d/*\"\n", env.dir);
    spit(pj(&env, "config"), incl);
    char cd[1024]; snprintf(cd, sizeof cd, "%s/conf.d", env.dir); mkdir(cd, 0700);
    spit(pj(&env, "conf.d/mine"), "Host tfa-cloud\n  HostName mine.example\n");
    CHECK(apply(&env, &c, err) != 0 && strstr(err, "already defines"));
    CHECK(access(pj(&env, "tfa_cloud_config"), F_OK) != 0);
    cfg = slurp(pj(&env, "config")); CHECK(cfg && strcmp(cfg, incl) == 0); free(cfg);

    // Hand-written tfa_cloud_config (no managed header): refuse.
    fresh_env(&env, root, "handwritten");
    mkdir(env.dir, 0700);
    spit(pj(&env, "tfa_cloud_config"), "Host tfa-cloud\n  HostName mine\n");
    CHECK(apply(&env, &c, err) != 0 && strstr(err, "not written by the bridge"));

    // ~/.ssh/config is a symlink (dotfiles): refuse, target untouched.
    fresh_env(&env, root, "symcfg");
    mkdir(env.dir, 0700);
    char target[1024]; snprintf(target, sizeof target, "%s/dotfiles_config", root);
    spit(target, "Host x\n");
    CHECK(symlink(target, pj(&env, "config")) == 0);
    CHECK(apply(&env, &c, err) != 0);
    cfg = slurp(target); CHECK(cfg && strcmp(cfg, "Host x\n") == 0); free(cfg);

    // Symlinked known_hosts can't redirect our write.
    fresh_env(&env, root, "symkh");
    mkdir(env.dir, 0700);
    char victim[1024]; snprintf(victim, sizeof victim, "%s/victim", root);
    spit(victim, "keep\n");
    CHECK(symlink(victim, pj(&env, "tfa_cloud_known_hosts")) == 0);
    CHECK(apply(&env, &c, err) != 0);
    cfg = slurp(victim); CHECK(cfg && strcmp(cfg, "keep\n") == 0); free(cfg);

    // Half a key pair: refuse rather than overwrite.
    fresh_env(&env, root, "halfkey");
    mkdir(env.dir, 0700);
    spit(pj(&env, "tfa_cloud"), "not a key\n"); chmod(pj(&env, "tfa_cloud"), 0600);
    CHECK(apply(&env, &c, err) != 0 && strstr(err, "incomplete"));
    cfg = slurp(pj(&env, "tfa_cloud")); CHECK(cfg && strcmp(cfg, "not a key\n") == 0); free(cfg);

    // World-readable private key: refuse.
    fresh_env(&env, root, "loosekey");
    mkdir(env.dir, 0700);
    CHECK(cloud_ssh_ensure_key(&env, pub, sizeof pub, err, sizeof err) == 0);
    chmod(pj(&env, "tfa_cloud"), 0644);
    CHECK(cloud_ssh_ensure_key(&env, pub, sizeof pub, err, sizeof err) != 0);

    // Group/world-writable .ssh: refuse.
    fresh_env(&env, root, "loosedir");
    mkdir(env.dir, 0777); chmod(env.dir, 0777);
    CHECK(apply(&env, &c, err) != 0);

    // User's own earlier setting wins over ours (Include placed after a
    // `Host *` by hand): `ssh -G` catches it, not ready.
    fresh_env(&env, root, "override");
    mkdir(env.dir, 0700);
    char ov[2048];
    snprintf(ov, sizeof ov, "Host *\n  Port 2200\nInclude \"%s/tfa_cloud_config\"\n", env.dir);
    spit(pj(&env, "config"), ov);
    CHECK(apply(&env, &c, err) != 0 && strstr(err, "ssh -G mismatch"));
    if (!strstr(err, "ssh -G mismatch")) fprintf(stderr, "  override: %s\n", err);
    cfg = slurp(pj(&env, "config")); CHECK(cfg && strcmp(cfg, ov) == 0);
    if (cfg && strcmp(cfg, ov) != 0) fprintf(stderr, "  override config now:\n%s\n", cfg);
    free(cfg);
    (void)st2;
}

// `ssh -F <cfg> -G <host>` output, for before/after comparison.
static char *ssh_G(const char *cfg, const char *host) {
    char cmd[2048];
    snprintf(cmd, sizeof cmd, "ssh -F '%s' -G '%s' 2>&1", cfg, host);
    FILE *p = popen(cmd, "r");
    if (!p) return NULL;
    char *b = calloc(1, 1 << 16);
    size_t n = fread(b, 1, (1 << 16) - 1, p);
    b[n] = '\0';
    pclose(p);
    return b;
}

// Global options the user had at the top level must keep applying to every
// other host after our Include is prepended (no Host-context leak).
static void test_no_leak(const char *root) {
    cloud_ssh_env_t env; char err[512];
    cloud_ssh_cfg_t c = base_cfg("127.0.0.1", 2222, "default");
    fresh_env(&env, root, "noleak");
    mkdir(env.dir, 0700);
    const char *user_cfg =
        "User globaluser\n"
        "Port 2022\n"
        "ServerAliveInterval 17\n"
        "Host foo\n  HostName foo.example\n"
        "Host bar\n  User baruser\n";
    spit(pj(&env, "config"), user_cfg);
    const char *hosts[] = { "foo", "bar", "github.com", "tfa-cloud-x" };
    char *before[4];
    for (int i = 0; i < 4; i++) before[i] = ssh_G(pj(&env, "config"), hosts[i]);
    // The Include goes first, so first-match-wins keeps our Port/User for
    // tfa-cloud while the user's globals still govern everything else.
    CHECK(apply(&env, &c, err) == 0);
    if (err[0]) fprintf(stderr, "  noleak: %s\n", err);
    for (int i = 0; i < 4; i++) {
        char *after = ssh_G(pj(&env, "config"), hosts[i]);
        CHECK(before[i] && after && strcmp(before[i], after) == 0);
        if (before[i] && after && strcmp(before[i], after) != 0)
            fprintf(stderr, "  ssh -G %s changed after Include\n", hosts[i]);
        free(before[i]); free(after);
    }
    char *g = ssh_G(pj(&env, "config"), "foo");
    CHECK(g && strstr(g, "\nuser globaluser\n") && strstr(g, "\nport 2022\n") && strstr(g, "\nserveraliveinterval 17\n"));
    free(g);

    // Global options that don't touch our settings coexist: ready, and other
    // hosts still resolve exactly as before.
    fresh_env(&env, root, "noleak2");
    mkdir(env.dir, 0700);
    user_cfg = "ServerAliveInterval 17\nHost foo\n  User fooer\n";
    spit(pj(&env, "config"), user_cfg);
    for (int i = 0; i < 4; i++) before[i] = ssh_G(pj(&env, "config"), hosts[i]);
    CHECK(apply(&env, &c, err) == 0);
    if (err[0]) fprintf(stderr, "  noleak2: %s\n", err);
    for (int i = 0; i < 4; i++) {
        char *after = ssh_G(pj(&env, "config"), hosts[i]);
        CHECK(before[i] && after && strcmp(before[i], after) == 0);
        free(before[i]); free(after);
    }

    // A global IdentityFile would also be offered to tfa-cloud → refuse.
    fresh_env(&env, root, "extraid");
    mkdir(env.dir, 0700);
    spit(pj(&env, "config"), "IdentityFile ~/.ssh/other_key\n");
    CHECK(apply(&env, &c, err) != 0 && strstr(err, "another IdentityFile"));
    // …and the rejected block is not left live.
    char *mb = slurp(pj(&env, "tfa_cloud_config"));
    CHECK(mb && !strstr(mb, "Host tfa-cloud") && strstr(mb, "# profile=default"));
    free(mb);
    // Include line is recognised exactly (no duplicate on retry).
    CHECK(apply(&env, &c, err) != 0);
    char *cc = slurp(pj(&env, "config"));
    { int cnt = 0; for (char *q = cc; q && (q = strstr(q, "tfa_cloud_config\"")); q++) cnt++; CHECK(cnt == 1); }
    free(cc);
    fresh_env(&env, root, "extraid2");
    mkdir(env.dir, 0700);
    spit(pj(&env, "config"), "Host *\n  IdentityFile ~/.ssh/other_key\n");
    CHECK(apply(&env, &c, err) != 0 && strstr(err, "another IdentityFile"));
}

static int capture(void *ctx, const char *d, size_t n) { (void)ctx; (void)d; (void)n; return 0; }

int main(void) {
    char root[] = "/tmp/tfa-cloud-ssh-test.XXXXXX";
    assert(mkdtemp(root));
    setenv("HOME", root, 1);   // belt and braces: nothing may reach the real ~/.ssh
    make_hostkey(HOSTKEY, 0x11);

    test_validators();
    test_parse();
    test_alias_detection();
    test_render();
    // A malformed config payload never reaches the filesystem.
    CHECK(cloud_ssh_config_job("{\"host\":\"x y\"}", 14, capture, NULL) != 0);
    if (cloud_ssh_supported()) { test_apply(root); test_no_leak(root); }
    else fprintf(stderr, "ssh/ssh-keygen not on PATH — skipping filesystem tests\n");

    char cmd[128]; snprintf(cmd, sizeof cmd, "chmod -R u+w %s; rm -rf %s", root, root);
    if (system(cmd) != 0) fprintf(stderr, "cleanup of %s failed\n", root);
    if (g_fail) { fprintf(stderr, "%d check(s) failed\n", g_fail); return 1; }
    printf("test-cloud-ssh: all checks passed\n");
    return 0;
}

// See cloud_ssh.h for the protocol and the files we own.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cloud_ssh.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

#ifdef _MSC_VER            // MSVC CRT spells it with an underscore
#  define strncasecmp _strnicmp
#endif

#define ED25519_PREFIX     "ssh-ed25519 "
#define ED25519_B64_LEN    68   // 51-byte blob, no padding
#define MANAGED_HEADER     "# Managed by TODOforAI bridge (ssh " CLOUD_SSH_ALIAS "). Regenerated automatically; do not edit.\n"
#define INCLUDE_MARKER     "# Added by TODOforAI bridge: `ssh " CLOUD_SSH_ALIAS "` (see tfa_cloud_config)\n"

// ── Validation (portable) ───────────────────────────────────────────────────

int cloud_ssh_valid_uuid(const char *s, size_t n) {
    if (n != 36) return 0;
    for (size_t i = 0; i < 36; i++) {
        int dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (dash ? s[i] != '-' : !isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

// DNS name, IPv4 or bare IPv6. Nothing ssh_config could read as a token
// (%h), quote, comment, whitespace or option (-oProxyCommand=…).
int cloud_ssh_valid_host(const char *s, size_t n) {
    if (n == 0 || n > 253 || !isalnum((unsigned char)s[0])) return 0;
    int colon = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == ':') colon = 1;
        else if (!isalnum(c) && c != '.' && c != '-') return 0;
        if (c == '.' && (i + 1 == n || s[i + 1] == '.' || s[i + 1] == '-')) return 0;
    }
    if (colon)   // IPv6 literal: hex digits and colons only
        for (size_t i = 0; i < n; i++)
            if (!isxdigit((unsigned char)s[i]) && s[i] != ':') return 0;
    return 1;
}

// Exactly "ssh-ed25519 " + 68 base64 chars decoding to the canonical 51-byte
// blob: string "ssh-ed25519" || string(32-byte key). No comment, no padding.
int cloud_ssh_valid_ed25519(const char *s, size_t n) {
    static const uint8_t head[19] = { 0,0,0,11, 's','s','h','-','e','d','2','5','5','1','9', 0,0,0,32 };
    const size_t pl = sizeof ED25519_PREFIX - 1;
    if (n != pl + ED25519_B64_LEN || memcmp(s, ED25519_PREFIX, pl) != 0) return 0;
    for (size_t i = pl; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '+' && s[i] != '/') return 0;
    uint8_t blob[64];
    return b64_decode(s + pl, ED25519_B64_LEN, blob, sizeof blob) == 51 &&
           memcmp(blob, head, sizeof head) == 0;
}

static int valid_profile(const char *s, size_t n) {
    if (n == 0 || n >= sizeof ((cloud_ssh_cfg_t *)0)->profile) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '_' && s[i] != '-') return 0;
    return 1;
}

// Raw span of a top-level key (escapes intact) + its type.
static int field(const char *msg, size_t len, const char *key,
                 const char **v, size_t *vl, json_type_t *t) {
    size_t pos = 0; const char *k; size_t kl;
    while (json_obj_iter(msg, len, &pos, &k, &kl, v, vl, t))
        if (kl == strlen(key) && memcmp(k, key, kl) == 0) return 1;
    return 0;
}

// Strings are copied raw: every valid value is escape-free, so any backslash
// is rejected by the validator's charset before it could mean anything.
static int str_field(const char *msg, size_t len, const char *key, char *dst, size_t cap,
                     int (*ok)(const char *, size_t)) {
    const char *v; size_t vl; json_type_t t;
    if (!field(msg, len, key, &v, &vl, &t) || t != JT_STR || vl >= cap || !ok(v, vl)) return 0;
    memcpy(dst, v, vl); dst[vl] = '\0';
    return 1;
}

static int is_workspace(const char *s, size_t n) { return n == 9 && memcmp(s, "workspace", 9) == 0; }

int cloud_ssh_parse_config(const char *msg, size_t len, cloud_ssh_cfg_t *c, const char **err) {
    memset(c, 0, sizeof *c);
    char user[16];
    const char *v; size_t vl; json_type_t t;
    *err = NULL;
    if (!json_validate_doc(msg, len))                                                 *err = "malformed JSON";
    else if (!str_field(msg, len, "cloudDeviceId", c->device_id, sizeof c->device_id, cloud_ssh_valid_uuid)) *err = "invalid cloudDeviceId";
    else if (!str_field(msg, len, "host", c->host, sizeof c->host, cloud_ssh_valid_host))       *err = "invalid host";
    else if (!str_field(msg, len, "user", user, sizeof user, is_workspace))                     *err = "user must be \"workspace\"";
    else if (!str_field(msg, len, "hostKey", c->host_key, sizeof c->host_key, cloud_ssh_valid_ed25519)) *err = "invalid hostKey";
    else if (!field(msg, len, "port", &v, &vl, &t) || t != JT_NUM || vl == 0 || vl > 5)         *err = "invalid port";
    else {
        c->port = 0;
        for (size_t i = 0; i < vl; i++) {
            if (!isdigit((unsigned char)v[i])) { *err = "invalid port"; return -1; }
            c->port = c->port * 10 + (v[i] - '0');
        }
        if (c->port < 1 || c->port > 65535 || v[0] == '0') { *err = "invalid port"; return -1; }
        // Optional (job payloads only): the credential profile that asks.
        if (field(msg, len, "profile", &v, &vl, &t) &&
            !str_field(msg, len, "profile", c->profile, sizeof c->profile, valid_profile))
            *err = "invalid profile";
    }
    return *err ? -1 : 0;
}

int cloud_ssh_build_payload(const cloud_ssh_cfg_t *c, char *out, size_t cap) {
    int n = snprintf(out, cap,
        "{\"cloudDeviceId\":\"%s\",\"host\":\"%s\",\"port\":%ld,\"user\":\"workspace\","
        "\"hostKey\":\"%s\",\"profile\":\"%s\"}",
        c->device_id, c->host, c->port, c->host_key, c->profile);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

int cloud_ssh_ready_json(const char *device_id, int ready, char *out, size_t cap) {
    int n = snprintf(out, cap, "{\"type\":\"cloud_ssh_ready\",\"cloudDeviceId\":\"%s\",\"ready\":%s}",
                     device_id, ready ? "true" : "false");
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

// ── ssh_config text ─────────────────────────────────────────────────────────

// Next line of text: [*ls, *le) with leading/trailing blanks stripped.
static int next_line(const char *text, size_t n, size_t *pos, const char **ls, const char **le) {
    if (*pos >= n) return 0;
    const char *p = text + *pos, *end = text + n;
    const char *nl = memchr(p, '\n', (size_t)(end - p));
    const char *e = nl ? nl : end;
    *pos = (size_t)(e - text) + (nl ? 1 : 0);
    while (p < e && isspace((unsigned char)*p)) p++;
    while (e > p && isspace((unsigned char)e[-1])) e--;
    *ls = p; *le = e;
    return 1;
}

// Line starts with `kw` (case-insensitive) followed by blank or '='; returns
// the rest, else NULL.
static const char *keyword(const char *ls, const char *le, const char *kw) {
    size_t k = strlen(kw);
    if ((size_t)(le - ls) <= k || strncasecmp(ls, kw, k) != 0) return NULL;
    if (!isspace((unsigned char)ls[k]) && ls[k] != '=') return NULL;
    return ls + k;
}

int cloud_ssh_user_defines_alias(const char *text, size_t n) {
    const size_t al = sizeof CLOUD_SSH_ALIAS - 1;
    size_t pos = 0; const char *ls, *le;
    while (next_line(text, n, &pos, &ls, &le)) {
        const char *p = keyword(ls, le, "Host");
        int match = 0;
        if (!p && (p = keyword(ls, le, "Match"))) match = 1;
        if (!p) continue;
        // Any token equal to the alias (quotes/negation stripped), or — for
        // Match — any mention at all, counts as the user's own definition.
        while (p < le) {
            while (p < le && (isspace((unsigned char)*p) || *p == '=' || *p == ',' || *p == '"' || *p == '!')) p++;
            const char *ts = p;
            while (p < le && !isspace((unsigned char)*p) && *p != ',' && *p != '"') p++;
            size_t tl = (size_t)(p - ts);
            if (tl == al && strncasecmp(ts, CLOUD_SSH_ALIAS, al) == 0) return 1;
            if (match) for (const char *q = ts; q + al <= p; q++)
                if (strncasecmp(q, CLOUD_SSH_ALIAS, al) == 0 && (q + al == p || q[al] != '-')) return 1;
        }
    }
    return 0;
}

int cloud_ssh_render_config(const char *dir, const cloud_ssh_cfg_t *c, char *out, size_t cap) {
    int n = snprintf(out, cap,
        MANAGED_HEADER
        "# profile=%s cloudDeviceId=%s\n"
        "Host " CLOUD_SSH_ALIAS "\n"
        "  HostName %s\n"
        "  Port %ld\n"
        "  User workspace\n"
        "  IdentityFile \"%s/tfa_cloud\"\n"
        "  IdentitiesOnly yes\n"
        "  IdentityAgent none\n"
        "  PubkeyAuthentication yes\n"
        "  PasswordAuthentication no\n"
        "  KbdInteractiveAuthentication no\n"
        "  UserKnownHostsFile \"%s/tfa_cloud_known_hosts\"\n"
        "  GlobalKnownHostsFile /dev/null\n"
        "  HostKeyAlias tfa-cloud-%s\n"
        "  StrictHostKeyChecking yes\n"
        "  UpdateHostKeys no\n"
        "  CheckHostIP no\n"
        "  ForwardAgent no\n"
        "  ForwardX11 no\n"
        "  ProxyCommand none\n"
        "  ProxyJump none\n"
        "  ControlMaster no\n"
        "  ControlPath none\n"
        "  ControlPersist no\n"
        "  PermitLocalCommand no\n"
        // Close our block: whatever follows the Include in ~/.ssh/config must
        // stay global, never become conditional on tfa-cloud.
        "Host *\n",
        c->profile[0] ? c->profile : "default", c->device_id, c->host, c->port, dir, dir, c->device_id);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

// ── POSIX implementation ────────────────────────────────────────────────────
#ifndef _WIN32

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CONFIG_MAX (1024 * 1024)

#define seterr(err, cap, ...) do { if ((err) && (cap)) snprintf((err), (cap), __VA_ARGS__); } while (0)

static int on_path(const char *name) {
    const char *path = getenv("PATH");
    if (!path) return 0;
    char buf[1024];
    for (const char *p = path; ; ) {
        const char *e = strchr(p, ':');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l && snprintf(buf, sizeof buf, "%.*s/%s", (int)l, p, name) < (int)sizeof buf &&
            access(buf, X_OK) == 0) return 1;
        if (!e) return 0;
        p = e + 1;
    }
}

int cloud_ssh_supported(void) { return on_path("ssh") && on_path("ssh-keygen"); }

// A path we can embed quoted in ssh_config without any expansion: ssh
// treats %, ${, ~ and globs specially, and a quote/newline would break out.
static int safe_path(const char *p) {
    if (p[0] != '/') return 0;
    for (; *p; p++)
        if ((unsigned char)*p < 0x20 || strchr("\"\\%$*?[]#`'", *p)) return 0;
    return 1;
}

int cloud_ssh_default_env(cloud_ssh_env_t *env) {
    memset(env, 0, sizeof *env);
    // ssh reads ~/.ssh from the passwd entry, not $HOME: follow it.
    struct passwd *pw = getpwuid(getuid());
    if (!pw || !pw->pw_dir) return -1;
    int n = snprintf(env->dir, sizeof env->dir, "%s/.ssh", pw->pw_dir);
    return (n < 0 || (size_t)n >= sizeof env->dir || !safe_path(env->dir)) ? -1 : 0;
}

static int path_in(const cloud_ssh_env_t *env, const char *name, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/%s", env->dir, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

// Directory must be ours and not writable by anyone else (ssh demands the
// same). A symlinked ~/.ssh (dotfiles) is fine as long as its target is.
static int check_dir(const cloud_ssh_env_t *env, char *err, size_t ecap) {
    struct stat st;
    if (stat(env->dir, &st) != 0) {
        if (errno != ENOENT || mkdir(env->dir, 0700) != 0 || stat(env->dir, &st) != 0) {
            seterr(err, ecap, "cannot create %s", env->dir); return -1;
        }
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 022)) {
        seterr(err, ecap, "%s must be a directory owned by you, not group/world-writable", env->dir);
        return -1;
    }
    return 0;
}

// Read a regular file we own, never through a symlink. 1 = read, 0 = absent,
// -1 = unusable (symlink, foreign owner, too big).
static int read_own(const char *path, char **buf, size_t *len, struct stat *out_st) {
    *buf = NULL; *len = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_size > CONFIG_MAX) {
        close(fd); return -1;
    }
    char *b = malloc((size_t)st.st_size + 1);
    size_t got = 0;
    while (b && got < (size_t)st.st_size) {
        ssize_t r = read(fd, b + got, (size_t)st.st_size - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (!b || got != (size_t)st.st_size) { free(b); return -1; }
    b[got] = '\0';
    *buf = b; *len = got;
    if (out_st) *out_st = st;
    return 1;
}

// Write-temp-then-rename in the same directory. Unchanged content = no write.
// `expect` (optional) is the stat the caller based `data` on: if the file
// changed since, the write is abandoned instead of losing a concurrent edit.
static int write_atomic(const char *path, const char *data, size_t len, mode_t mode,
                        const struct stat *expect) {
    char *cur; size_t cur_len; struct stat st;
    int r = read_own(path, &cur, &cur_len, &st);
    if (r < 0) return -1;
    if (r == 1) {
        int same = cur_len == len && memcmp(cur, data, len) == 0;
        free(cur);
        if (same) return 0;
        if (expect && (st.st_ino != expect->st_ino || st.st_size != expect->st_size ||
                       st.st_mtime != expect->st_mtime)) return -1;
    } else if (expect) return -1;   // vanished under us
    char tmp[1024];
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    if (snprintf(tmp, sizeof tmp, "%s.tmp.%ld.%ld", path, (long)getpid(), (long)ts.tv_nsec) >= (int)sizeof tmp)
        return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) break;
        off += (size_t)w;
    }
    if (off != len || fchmod(fd, mode) != 0 || fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    close(fd);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

// Serialises bridges (multiple profiles, a --kill handover) touching our files.
static int take_lock(const cloud_ssh_env_t *env) {
    char p[1024];
    if (path_in(env, ".tfa_cloud.lock", p, sizeof p) < 0) return -1;
    int fd = open(p, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    while (flock(fd, LOCK_EX) != 0) if (errno != EINTR) { close(fd); return -1; }
    return fd;
}

// Run argv with stdin=/dev/null, stdout+stderr captured, killed at timeout.
// Returns exit status (0..255), or -1 on spawn failure / timeout / signal.
static int run_cmd(char *const argv[], char *out, size_t cap, int timeout_ms) {
    snprintf(out, cap, "cannot run %s", argv[0]);
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        int dn = open("/dev/null", O_RDONLY);
        if (dn < 0 || dup2(dn, 0) < 0 || dup2(pfd[1], 1) < 0 || dup2(pfd[1], 2) < 0) _exit(127);
        close(pfd[0]);
        // Stays in the job worker's process group, so cancelling the job
        // kills us too. Nothing can prompt: stdin is /dev/null, BatchMode.
        unsetenv("SSH_ASKPASS"); unsetenv("SSH_AUTH_SOCK");
        setenv("SSH_ASKPASS_REQUIRE", "never", 1);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[1]);
    size_t used = 0;
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
        long left = timeout_ms - ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000);
        if (left <= 0) { kill(pid, SIGKILL); break; }
        struct pollfd p = { .fd = pfd[0], .events = POLLIN };
        int pr = poll(&p, 1, (int)left);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) continue;
        char tmp[4096];
        ssize_t r = read(pfd[0], tmp, sizeof tmp);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        size_t take = (size_t)r < cap - 1 - used ? (size_t)r : cap - 1 - used;
        memcpy(out + used, tmp, take); used += take;
    }
    out[used] = '\0';
    close(pfd[0]);
    // Output closed ≠ exited: keep the deadline until the child is reaped.
    int st;
    for (;;) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) break;
        if (w < 0 && errno != EINTR) return -1;
        struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
        if ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000 >= timeout_ms) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
            return -1;
        }
        struct timespec nap = { 0, 20 * 1000000L };
        nanosleep(&nap, NULL);
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void first_line(char *s) { s[strcspn(s, "\r\n")] = '\0'; }

// Local refusals shared by both jobs: an alias the user defined themselves,
// a managed block owned by another credential profile, or a ~/.ssh/config we
// won't rewrite (symlink / foreign owner). Must be called under the lock.
static int check_conflicts(const cloud_ssh_env_t *env, const char *profile, char *err, size_t ecap) {
    char p[1024]; char *buf; size_t len;
    if (path_in(env, "config", p, sizeof p) < 0) return -1;
    int r = read_own(p, &buf, &len, NULL);
    if (r < 0) { seterr(err, ecap, "%s is a symlink, not yours, or too large; not touching it", p); return -1; }
    if (r == 1) {
        int clash = cloud_ssh_user_defines_alias(buf, len);
        free(buf);
        if (clash) { seterr(err, ecap, "%s already defines Host " CLOUD_SSH_ALIAS "; leaving it alone", p); return -1; }
    }
    if (path_in(env, "tfa_cloud_config", p, sizeof p) < 0) return -1;
    r = read_own(p, &buf, &len, NULL);
    if (r < 0) { seterr(err, ecap, "%s is not a regular file of yours", p); return -1; }
    if (r == 1) {
        char want[160];
        snprintf(want, sizeof want, "# profile=%s ", profile[0] ? profile : "default");
        int ours = len > strlen(MANAGED_HEADER) && memcmp(buf, MANAGED_HEADER, strlen(MANAGED_HEADER)) == 0;
        int mine = ours && strstr(buf, want) != NULL;
        free(buf);
        if (!ours) { seterr(err, ecap, "%s was not written by the bridge; leaving it alone", p); return -1; }
        if (!mine) { seterr(err, ecap, "%s belongs to another bridge profile", p); return -1; }
    }
    return 0;
}

int cloud_ssh_ensure_key(const cloud_ssh_env_t *env, char *pub, size_t cap, char *err, size_t ecap) {
    char key[1024], pubp[1024];
    if (path_in(env, "tfa_cloud", key, sizeof key) < 0 || path_in(env, "tfa_cloud.pub", pubp, sizeof pubp) < 0)
        return -1;
    struct stat ks, ps;
    int have_k = lstat(key, &ks) == 0, have_p = lstat(pubp, &ps) == 0;
    if (!have_k && !have_p) {
        char out[512];
        char *argv[] = { "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "todoforai-cloud", "-f", key, NULL };
        if (run_cmd(argv, out, sizeof out, 20000) != 0) { first_line(out); seterr(err, ecap, "ssh-keygen failed: %s", out); return -1; }
        if (lstat(key, &ks) != 0) { seterr(err, ecap, "ssh-keygen produced no %s", key); return -1; }
    } else if (!have_k || !have_p) {
        seterr(err, ecap, "%s: key pair is incomplete; remove it to regenerate", key); return -1;
    }
    if (!S_ISREG(ks.st_mode) || ks.st_uid != geteuid() || (ks.st_mode & 077)) {
        seterr(err, ecap, "%s must be a private regular file (0600) owned by you", key); return -1;
    }
    char *buf; size_t len;
    if (read_own(pubp, &buf, &len, NULL) != 1) { seterr(err, ecap, "cannot read %s", pubp); return -1; }
    // "ssh-ed25519 <b64> [comment]": keep type + key only.
    const char *sp = len > 12 ? memchr(buf + 12, ' ', len - 12) : NULL;
    size_t kl = sp ? (size_t)(sp - buf) : len;
    while (kl && (buf[kl - 1] == '\n' || buf[kl - 1] == '\r')) kl--;
    int ok = cloud_ssh_valid_ed25519(buf, kl) && kl < cap;
    if (ok) { memcpy(pub, buf, kl); pub[kl] = '\0'; }
    free(buf);
    if (!ok) seterr(err, ecap, "%s is not an ed25519 public key", pubp);
    return ok ? 0 : -1;
}

// Prepend the Include line to ~/.ssh/config unless already there.
static int ensure_include(const cloud_ssh_env_t *env, char *err, size_t ecap) {
    char cfg[1024], inc[1200];
    if (path_in(env, "config", cfg, sizeof cfg) < 0) return -1;
    snprintf(inc, sizeof inc, "Include \"%s/tfa_cloud_config\"\n", env->dir);
    char *buf; size_t len; struct stat st;
    int r = read_own(cfg, &buf, &len, &st);
    if (r < 0) { seterr(err, ecap, "cannot safely read %s", cfg); return -1; }
    if (r == 1) {
        size_t pos = 0; const char *ls, *le;
        size_t want = strlen(inc) - 1;   // without the newline
        while (next_line(buf, len, &pos, &ls, &le)) {
            // Exact line anywhere: a hand-placed Include is respected (never
            // duplicated); if its placement breaks things, ssh -G says so.
            if ((size_t)(le - ls) == want && memcmp(ls, inc, want) == 0) { free(buf); return 0; }
        }
    }
    size_t il = strlen(INCLUDE_MARKER) + strlen(inc);
    char *nb = malloc(il + len + 2);
    if (!nb) { free(buf); return -1; }
    // Top of file: ssh_config is first-match-wins, and an Include placed after
    // a `Host` line would only apply inside that block.
    size_t u = (size_t)snprintf(nb, il + 1, "%s%s", INCLUDE_MARKER, inc);
    if (len) { nb[u++] = '\n'; memcpy(nb + u, buf, len); u += len; }
    int rc = write_atomic(cfg, nb, u, r == 1 ? (st.st_mode & 0777) : 0600, r == 1 ? &st : NULL);
    free(nb); free(buf);
    if (rc != 0) seterr(err, ecap, "failed to update %s (changed concurrently?)", cfg);
    return rc;
}

// `ssh -G` must resolve to exactly our settings (first-match-wins could let
// an earlier user line override them).
static int verify_effective(const cloud_ssh_env_t *env, const cloud_ssh_cfg_t *c, char *err, size_t ecap) {
    char cfg[1024]; path_in(env, "config", cfg, sizeof cfg);
    char *argv[6]; int a = 0;
    argv[a++] = "ssh"; argv[a++] = "-G";
    if (env->use_F) { argv[a++] = "-F"; argv[a++] = cfg; }
    argv[a++] = CLOUD_SSH_ALIAS; argv[a] = NULL;
    char *out = malloc(64 * 1024);
    if (!out) return -1;
    if (run_cmd(argv, out, 64 * 1024, 10000) != 0) {
        first_line(out); seterr(err, ecap, "ssh -G failed: %s", out); free(out); return -1;
    }
    char want[12][1100]; int n = 0;
    snprintf(want[n++], sizeof want[0], "hostname %s", c->host);
    snprintf(want[n++], sizeof want[0], "port %ld", c->port);
    snprintf(want[n++], sizeof want[0], "user workspace");
    snprintf(want[n++], sizeof want[0], "identityfile %s/tfa_cloud", env->dir);
    snprintf(want[n++], sizeof want[0], "identitiesonly yes");
    snprintf(want[n++], sizeof want[0], "identityagent none");
    snprintf(want[n++], sizeof want[0], "userknownhostsfile %s/tfa_cloud_known_hosts", env->dir);
    snprintf(want[n++], sizeof want[0], "hostkeyalias tfa-cloud-%s", c->device_id);
    snprintf(want[n++], sizeof want[0], "stricthostkeychecking true");
    snprintf(want[n++], sizeof want[0], "forwardagent no");
    snprintf(want[n++], sizeof want[0], "controlmaster false");
    int seen[12] = {0}, id_extra = 0, rc = 0;
    size_t pos = 0, len = strlen(out); const char *ls, *le;
    while (rc == 0 && next_line(out, len, &pos, &ls, &le)) {
        size_t l = (size_t)(le - ls);
        if ((l > 13 && strncmp(ls, "proxycommand ", 13) == 0 && strncmp(ls + 13, "none", 4) != 0) ||
            (l > 10 && strncmp(ls, "proxyjump ", 10) == 0 && strncmp(ls + 10, "none", 4) != 0)) rc = -1;
        for (int i = 0; i < n; i++) {
            size_t k = strcspn(want[i], " ") + 1;
            if (l < k || strncmp(ls, want[i], k) != 0) continue;
            int eq = l == strlen(want[i]) && memcmp(ls, want[i], l) == 0;
            // ssh offers every IdentityFile: ours must be the only one.
            if (i == 3 && !eq) { id_extra = 1; continue; }
            if (eq) seen[i] = 1;
        }
    }
    if (rc == 0 && id_extra) {
        seterr(err, ecap, "ssh -G: another IdentityFile applies to " CLOUD_SSH_ALIAS " (e.g. under Host *); only the dedicated key is allowed");
        rc = -1;
    }
    for (int i = 0; i < n && rc == 0; i++)
        if (!seen[i]) { seterr(err, ecap, "ssh -G mismatch: expected '%s'", want[i]); rc = -1; }
    if (rc != 0 && err && !err[0]) seterr(err, ecap, "ssh -G: a proxy is configured for " CLOUD_SSH_ALIAS);
    free(out);
    return rc;
}

// 1 if `ssh -G tfa-cloud` resolves to something other than the bare alias
// (the user defined it, possibly in an Included file).
static int alias_claimed(const cloud_ssh_env_t *env, char *err, size_t ecap) {
    char cfg[1024], out[16384];
    path_in(env, "config", cfg, sizeof cfg);
    char *argv[6]; int a = 0;
    argv[a++] = "ssh"; argv[a++] = "-G";
    if (env->use_F) { argv[a++] = "-F"; argv[a++] = cfg; }
    argv[a++] = CLOUD_SSH_ALIAS; argv[a] = NULL;
    if (run_cmd(argv, out, sizeof out, 10000) != 0) {
        first_line(out); seterr(err, ecap, "ssh -G failed: %s", out); return 1;
    }
    if (strstr(out, "\nhostname " CLOUD_SSH_ALIAS "\n") || strncmp(out, "hostname " CLOUD_SSH_ALIAS "\n", 18) == 0)
        return 0;
    seterr(err, ecap, "your ssh config (or a file it Includes) already defines " CLOUD_SSH_ALIAS "; leaving it alone");
    return 1;
}

int cloud_ssh_apply(const cloud_ssh_env_t *env, const cloud_ssh_cfg_t *c, char *err, size_t ecap) {
    if (err && ecap) err[0] = '\0';
    if (check_dir(env, err, ecap) != 0) return -1;
    int lk = take_lock(env);
    if (lk < 0) { seterr(err, ecap, "cannot lock %s", env->dir); return -1; }
    int rc = -1;
    char pub[128], p[1024], body[4096];
    if (check_conflicts(env, c->profile, err, ecap) != 0 ||
        cloud_ssh_ensure_key(env, pub, sizeof pub, err, ecap) != 0) goto out;

    int n = snprintf(body, sizeof body, "tfa-cloud-%s %s\n", c->device_id, c->host_key);
    if (path_in(env, "tfa_cloud_known_hosts", p, sizeof p) < 0 || n < 0 || (size_t)n >= sizeof body ||
        write_atomic(p, body, (size_t)n, 0600, NULL) != 0) { seterr(err, ecap, "cannot write %s", p); goto out; }
    if (path_in(env, "tfa_cloud_config", p, sizeof p) < 0) goto out;
    // First install: the alias must be unclaimed anywhere ssh looks
    // (including files the user Includes), i.e. still resolve to itself.
    if (access(p, F_OK) != 0 && alias_claimed(env, err, ecap)) goto out;
    n = cloud_ssh_render_config(env->dir, c, body, sizeof body);
    if (n < 0 || write_atomic(p, body, (size_t)n, 0600, NULL) != 0) { seterr(err, ecap, "cannot write %s", p); goto out; }
    if (ensure_include(env, err, ecap) != 0 || verify_effective(env, c, err, ecap) != 0) {
        // Don't leave a rejected block live: keep only the ownership header.
        n = snprintf(body, sizeof body, MANAGED_HEADER "# profile=%s disabled: setup failed\n",
                     c->profile[0] ? c->profile : "default");
        (void)write_atomic(p, body, (size_t)n, 0600, NULL);
        goto out;
    }
    rc = 0;
out:
    close(lk);   // drop the lock before the (up to ~20s) connect probe
    if (rc != 0 || env->skip_connect) return rc;
    char cfg[1024], out_buf[512];
    path_in(env, "config", cfg, sizeof cfg);
    char *argv[10]; int a = 0;
    argv[a++] = "ssh"; argv[a++] = "-o"; argv[a++] = "BatchMode=yes";
    argv[a++] = "-o"; argv[a++] = "ConnectTimeout=5";
    if (env->use_F) { argv[a++] = "-F"; argv[a++] = cfg; }
    argv[a++] = CLOUD_SSH_ALIAS; argv[a++] = "true"; argv[a] = NULL;
    if (run_cmd(argv, out_buf, sizeof out_buf, 20000) != 0) {
        first_line(out_buf); seterr(err, ecap, "ssh probe failed: %s", out_buf); return -1;
    }
    return 0;
}

static int payload_profile(const char *pl, size_t len, char *out, size_t cap) {
    out[0] = '\0';
    if (json_get_type(pl, len, "profile") == JT_NONE) return 0;
    return str_field(pl, len, "profile", out, cap, valid_profile) ? 0 : -1;
}

int cloud_ssh_key_job(const char *payload, size_t len, bridge_job_emit_fn emit, void *ctx) {
    cloud_ssh_env_t env; char profile[128], err[512] = "", pub[128];
    if (payload_profile(payload, len, profile, sizeof profile) != 0 || cloud_ssh_default_env(&env) != 0) {
        fprintf(stderr, "cloud-ssh: unusable ~/.ssh path or profile\n"); return -1;
    }
    if (check_dir(&env, err, sizeof err) != 0) { fprintf(stderr, "cloud-ssh: %s\n", err); return -1; }
    int lk = take_lock(&env);
    if (lk < 0) { fprintf(stderr, "cloud-ssh: cannot lock %s\n", env.dir); return -1; }
    int rc = check_conflicts(&env, profile, err, sizeof err) == 0 &&
             cloud_ssh_ensure_key(&env, pub, sizeof pub, err, sizeof err) == 0 ? 0 : -1;
    close(lk);
    if (rc != 0) { fprintf(stderr, "cloud-ssh: %s\n", err); return -1; }
    char msg[256];
    int n = snprintf(msg, sizeof msg, "{\"type\":\"cloud_ssh_key\",\"publicKey\":\"%s\"}", pub);
    return emit(ctx, msg, (size_t)n);
}

int cloud_ssh_config_job(const char *payload, size_t len, bridge_job_emit_fn emit, void *ctx) {
    cloud_ssh_cfg_t c; cloud_ssh_env_t env; const char *perr; char err[512] = "", msg[160];
    if (cloud_ssh_parse_config(payload, len, &c, &perr) != 0) { fprintf(stderr, "cloud-ssh: %s\n", perr); return -1; }
    int ok = cloud_ssh_default_env(&env) == 0 && cloud_ssh_apply(&env, &c, err, sizeof err) == 0;
    if (ok) fprintf(stderr, "✓ cloud-ssh: `ssh " CLOUD_SSH_ALIAS "` ready (%s:%ld)\n", c.host, c.port);
    else    fprintf(stderr, "cloud-ssh: not ready: %s\n", err[0] ? err : "unusable ~/.ssh path");
    int n = cloud_ssh_ready_json(c.device_id, ok, msg, sizeof msg);
    return n > 0 ? emit(ctx, msg, (size_t)n) : -1;
}

#else  // _WIN32: v1 is POSIX-only; never advertised, every entry fails closed.

int cloud_ssh_supported(void) { return 0; }
int cloud_ssh_default_env(cloud_ssh_env_t *env) { memset(env, 0, sizeof *env); return -1; }
int cloud_ssh_ensure_key(const cloud_ssh_env_t *env, char *pub, size_t cap, char *err, size_t ecap) {
    (void)env; (void)pub; (void)cap; if (err && ecap) snprintf(err, ecap, "unsupported on Windows"); return -1;
}
int cloud_ssh_apply(const cloud_ssh_env_t *env, const cloud_ssh_cfg_t *c, char *err, size_t ecap) {
    (void)env; (void)c; if (err && ecap) snprintf(err, ecap, "unsupported on Windows"); return -1;
}
int cloud_ssh_key_job(const char *p, size_t l, bridge_job_emit_fn emit, void *ctx) {
    (void)p; (void)l; (void)emit; (void)ctx; return -1;
}
int cloud_ssh_config_job(const char *p, size_t l, bridge_job_emit_fn emit, void *ctx) {
    cloud_ssh_cfg_t c; const char *perr; char msg[160];
    if (cloud_ssh_parse_config(p, l, &c, &perr) != 0) return -1;
    int n = cloud_ssh_ready_json(c.device_id, 0, msg, sizeof msg);
    return n > 0 ? emit(ctx, msg, (size_t)n) : -1;
}

#endif

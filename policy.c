// Local device policy. See policy.h.
#define _GNU_SOURCE
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <direct.h>
#  include <io.h>
#else
#  include <unistd.h>
#  include <pwd.h>
#endif
#ifdef __linux__
#  include <linux/landlock.h>
#  include <linux/openat2.h>
#  include <sys/syscall.h>
#  include <sys/prctl.h>
// Newer ABI bits than the build host's headers may know. Values are ABI-fixed.
#  ifndef LANDLOCK_ACCESS_FS_REFER
#    define LANDLOCK_ACCESS_FS_REFER      (1ULL << 13)
#  endif
#  ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#    define LANDLOCK_ACCESS_FS_TRUNCATE   (1ULL << 14)
#  endif
#  ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#    define LANDLOCK_ACCESS_FS_IOCTL_DEV  (1ULL << 15)
#  endif
#  ifndef SYS_landlock_create_ruleset
#    define SYS_landlock_create_ruleset 444
#    define SYS_landlock_add_rule       445
#    define SYS_landlock_restrict_self  446
#  endif
#  ifndef SYS_openat2
#    define SYS_openat2 437
#  endif
#endif

#include "json.h"

bridge_policy_t g_policy;
static char g_home[1024];      // cached at load; nothing post-fork touches getenv/getpwuid
static char g_cfgdir[1024];    // canonical credentials + policy dir: never inside a workspace

static void usage(FILE *out, const char *u) { fprintf(out, "Usage: todoforai-bridge %s\n", u); }

static void set_broken(const char *why) {
    g_policy.broken = 1;
    if (!g_policy.err[0]) snprintf(g_policy.err, sizeof g_policy.err, "%s", why);
}

// ── paths ──────────────────────────────────────────────────────────────────

static const char *home_dir(void) {
    if (g_home[0]) return g_home;
#ifdef _WIN32
    const char *h = getenv("USERPROFILE");
#else
    const char *h = getenv("HOME");
    if (!h || !*h) { struct passwd *pw = getpwuid(getuid()); h = pw ? pw->pw_dir : NULL; }
#endif
    if (!h || !*h || snprintf(g_home, sizeof g_home, "%s", h) >= (int)sizeof g_home) { g_home[0] = '\0'; return NULL; }
    return g_home;
}

// Per-user config dir (same one login.h uses for credentials.json).
static int config_dir(char *buf, size_t cap) {
    const char *home = home_dir();
    if (!home) return -1;
    int w;
#ifdef _WIN32
    w = snprintf(buf, cap, "%s\\AppData\\Roaming\\todoforai", home);
#elif defined(__APPLE__)
    w = snprintf(buf, cap, "%s/Library/Application Support/todoforai", home);
#else
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0]) w = snprintf(buf, cap, "%s/todoforai", xdg);
    else               w = snprintf(buf, cap, "%s/.config/todoforai", home);
#endif
    return (w < 0 || (size_t)w >= cap) ? -1 : 0;
}

#ifdef _WIN32
#  define IS_SEP(c) ((c) == '/' || (c) == '\\')
#else
#  define IS_SEP(c) ((c) == '/')
#endif

// Canonical absolute form: ~ expanded, symlinks resolved on the longest
// existing prefix (a not-yet-created workspace still canonicalises). The
// unresolved tail must be plain: no `.`/`..` components.
static int canon(const char *in, char *out, size_t cap) {
    char tmp[1024];
    if (in[0] == '~' && (in[1] == '\0' || IS_SEP(in[1]))) {
        const char *h = home_dir();
        if (!h) return -1;
        if (snprintf(tmp, sizeof tmp, "%s%s", h, in + 1) >= (int)sizeof tmp) return -1;
        in = tmp;
    }
#ifdef _WIN32
    // _fullpath normalises text only (no junction/symlink resolution) — the
    // Windows policy is a prefix check, documented as such in policy.h.
    return _fullpath(out, in, cap) ? 0 : -1;
#else
    char work[1024], res[PATH_MAX], abs_[1024];
    if (in[0] != '/') {
        char cwd[1024];
        if (!getcwd(cwd, sizeof cwd)) return -1;
        if (snprintf(abs_, sizeof abs_, "%s/%s", cwd, in) >= (int)sizeof abs_) return -1;
        in = abs_;
    }
    size_t n = strlen(in);
    if (n >= sizeof work) return -1;
    memcpy(work, in, n + 1);
    size_t cut = n;
    while (!realpath(work, res)) {
        if (errno != ENOENT) return -1;          // EACCES/ELOOP/ENOTDIR: not ours to guess
        char *slash = strrchr(work, '/');
        if (!slash || slash == work) return -1;
        *slash = '\0';
        cut = (size_t)(slash - work);
    }
    const char *tail = in + cut;
    for (const char *t = tail; *t; ) {           // reject "." / ".." in the unresolved tail
        while (*t == '/') t++;
        const char *seg = t;
        while (*t && *t != '/') t++;
        size_t sl = (size_t)(t - seg);
        if ((sl == 1 && seg[0] == '.') || (sl == 2 && seg[0] == '.' && seg[1] == '.')) return -1;
    }
    if (strcmp(res, "/") == 0) res[0] = '\0';
    if (snprintf(out, cap, "%s%s", res, *tail ? tail : (res[0] ? "" : "/")) >= (int)cap) return -1;
    return 0;
#endif
}

static int under(const char *path, const char *root) {
    size_t rl = strlen(root);
#ifdef _WIN32
    if (_strnicmp(path, root, rl) != 0) return 0;
#else
    if (strncmp(path, root, rl) != 0) return 0;
#endif
    if (rl && IS_SEP(root[rl - 1])) return 1;    // root is "/" or "C:\": any descendant
    return path[rl] == '\0' || IS_SEP(path[rl]);
}

// Which workspace (index) contains canonical `c`, or -1.
static int ws_index(const char *c) {
    for (int i = 0; i < g_policy.n; i++) if (under(c, g_policy.ws[i])) return i;
    return -1;
}

// Either direction: a grant inside the config dir exposes credentials just
// as surely as one containing it.
static int overlaps_cfg(const char *grant) {
    return under(g_cfgdir, grant) || under(grant, g_cfgdir);
}

int bridge_policy_path_allowed(const char *path) {
    if (!g_policy.active) return 1;
    if (g_policy.broken) return 0;
    if (!path || !*path) return 0;
    if (path[0] != '~' && path[0] != '/'
#ifdef _WIN32
        && !(path[1] == ':' || IS_SEP(path[0]))
#endif
        ) return 0;                              // relative: nothing to anchor to
    char c[1024];
    if (canon(path, c, sizeof c) != 0) return 0;
    return ws_index(c) >= 0;
}

const char *bridge_policy_default_cwd(void) {
    if (!g_policy.active || g_policy.broken || g_policy.n == 0) return NULL;
    return g_policy.ws[0];
}

int bridge_policy_open(const char *path, int flags, int mode) {
#ifdef _WIN32
    if (g_policy.active && !bridge_policy_path_allowed(path)) { errno = EACCES; return -1; }
    return _open(path, flags, mode);
#else
    if (!g_policy.active) return open(path, flags | O_CLOEXEC, mode);
    if (g_policy.broken) { errno = EACCES; return -1; }
    char c[1024];
    if (canon(path, c, sizeof c) != 0) { errno = EACCES; return -1; }
    int wi = ws_index(c);
    if (wi < 0) { errno = EACCES; return -1; }
#  ifndef O_PATH
#    define O_PATH O_RDONLY               // macOS: a directory fd is just an O_RDONLY open
#  endif
    int root = open(g_policy.ws[wi], O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) return -1;
    const char *rel = c + strlen(g_policy.ws[wi]);
    while (*rel == '/') rel++;
    if (!*rel) rel = ".";
#  ifdef __linux__
    // Resolve the remainder beneath the workspace root: a symlink swapped in
    // after canon() can't lead outside it. No fallback: a kernel without
    // openat2 (<5.6) can't honour the policy.
    struct open_how how = { .flags = (unsigned long long)(flags | O_CLOEXEC), .mode = (unsigned long long)mode,
                            .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS };
    int fd = (int)syscall(SYS_openat2, root, rel, &how, sizeof how);
#  else
    // macOS: no beneath-resolution primitive — O_NOFOLLOW on the final
    // component only. An intermediate symlink swapped between check and open
    // is a documented gap (macOS gets the path check, not the jail).
    int fd = openat(root, rel, flags | O_CLOEXEC | O_NOFOLLOW, mode);
#  endif
    int saved = errno;
    close(root);
    errno = saved == EXDEV ? EACCES : saved;   // EXDEV = RESOLVE_BENEATH's escape signal
    return fd;
#endif
}

const char *bridge_policy_deny_msg(const char *path, char *buf, size_t cap) {
    if (g_policy.broken)
        snprintf(buf, cap, "device policy is unusable (%s) — fix %s on that machine", g_policy.err, g_policy.path);
    else
        snprintf(buf, cap, "device policy denies access to %s — allow it on that machine with:"
                           " todoforai-bridge policy add \"%s\"", path, path);
    return buf;
}

// ── load / save ────────────────────────────────────────────────────────────

#define POLICY_FILE_MAX 65536

// -2 absent; -1 present but unreadable/oversized; else byte count (0 = an
// empty file, which is present and therefore broken, not "no policy").
static int read_file(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? -2 : -1;
    size_t n = fread(buf, 1, cap, f);
    int err = ferror(f);
    fclose(f);
    if (err || n >= cap) return -1;
    buf[n] = '\0';
    return (int)n;
}

// Whole document must be one well-formed object with only known keys of the
// right type; anything odd ⇒ broken (deny all). Duplicate keys are rejected
// so "jail":true,"jail":false can't mean different things to two readers.
static void parse(const char *json, size_t len) {
    g_policy.jail = 1;
    if (!json_validate_doc(json, len)) { set_broken("not a single well-formed JSON document"); return; }
    size_t pos = 0; const char *k, *v; size_t kl, vl; json_type_t t;
    int seen_jail = 0, seen_ws = 0;
    while (json_obj_iter(json, len, &pos, &k, &kl, &v, &vl, &t)) {
        if (kl == 4 && memcmp(k, "jail", 4) == 0) {
            if (seen_jail++ || (t != JT_BOOL_T && t != JT_BOOL_F)) { set_broken("\"jail\" must appear once, true/false"); return; }
            g_policy.jail = (t == JT_BOOL_T);
        } else if (kl == 10 && memcmp(k, "workspaces", 10) == 0) {
            if (seen_ws++ || t != JT_ARR) { set_broken("\"workspaces\" must appear once, an array"); return; }
        } else { set_broken("unknown key in policy"); return; }
    }
    const char *arr; size_t alen;
    if (!json_get_arr(json, len, "workspaces", &arr, &alen)) { set_broken("\"workspaces\" array missing"); return; }
    pos = 0; int rc;
    while ((rc = json_arr_iter(arr, alen, &pos, &v, &vl, &t)) == 1) {
        if (t != JT_STR) { set_broken("\"workspaces\" entries must be strings"); return; }
        if (g_policy.n >= POLICY_MAX_WS) { set_broken("too many workspaces"); return; }
        char raw[1024];
        long dl = json_unescape_span(v, vl, raw, sizeof raw);
        if (dl <= 0 || (size_t)dl != strlen(raw)) { set_broken("bad workspace string"); return; }
        if (canon(raw, g_policy.ws[g_policy.n], sizeof g_policy.ws[0]) != 0) { set_broken("workspace path cannot be resolved"); return; }
        if (overlaps_cfg(g_policy.ws[g_policy.n])) { set_broken("a workspace overlaps the todoforai config dir"); return; }
        g_policy.n++;
    }
    if (rc < 0) set_broken("malformed \"workspaces\" array");
}

#ifdef __linux__
static int landlock_abi(void);
#endif

void bridge_policy_load(void) {
    memset(&g_policy, 0, sizeof g_policy);
    g_home[0] = '\0';
    char raw_cfg[1024];
    if (!home_dir() || config_dir(raw_cfg, sizeof raw_cfg) != 0) return;   // no HOME: no per-user policy
    // Canonical, like the workspaces, so a symlinked ~/.config or a relative
    // XDG_CONFIG_HOME can't slip past the overlap checks.
    if (canon(raw_cfg, g_cfgdir, sizeof g_cfgdir) != 0) snprintf(g_cfgdir, sizeof g_cfgdir, "%s", raw_cfg);
    static char buf[POLICY_FILE_MAX + 1];
    char user[1024];
    const char *candidates[2] = { NULL, NULL };
#ifndef _WIN32
    candidates[0] = "/etc/todoforai/policy.json";
#endif
    if (snprintf(user, sizeof user, "%s/policy.json", g_cfgdir) < (int)sizeof user) candidates[1] = user;
    for (int i = 0; i < 2; i++) {
        if (!candidates[i]) continue;
        int n = read_file(candidates[i], buf, sizeof buf);
        if (n == -2) continue;
        snprintf(g_policy.path, sizeof g_policy.path, "%s", candidates[i]);
        g_policy.active = 1;
        if (n < 0) { set_broken("cannot read policy file (or > 64 KiB)"); return; }
        parse(buf, (size_t)n);
#ifdef __linux__
        // ABI 3 (Linux 6.2) is the floor: below it truncate(2) is unmediated,
        // so "read-only" would be a lie. Older kernels: set "jail": false.
        if (!g_policy.broken && g_policy.jail && landlock_abi() < 3)
            set_broken("Landlock ABI 3+ (Linux 6.2) required for \"jail\": true");
#endif
        return;
    }
}

static int mkdir_p(const char *dir) {
    char tmp[1024];
    if (snprintf(tmp, sizeof tmp, "%s", dir) >= (int)sizeof tmp) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (IS_SEP(*p)) { char c = *p; *p = '\0';
#ifdef _WIN32
            _mkdir(tmp);
#else
            mkdir(tmp, 0700);
#endif
            *p = c; }
    }
#ifdef _WIN32
    return _mkdir(tmp) == 0 || errno == EEXIST ? 0 : -1;
#else
    return mkdir(tmp, 0700) == 0 || errno == EEXIST ? 0 : -1;
#endif
}

static int save(void) {
    char path[1024], tmp[1040];
    if (snprintf(path, sizeof path, "%s/policy.json", g_cfgdir) >= (int)sizeof path) return -1;
    if (mkdir_p(g_cfgdir) != 0) return -1;
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
#ifdef _WIN32
    FILE *f = fopen(tmp, "wb");
#else
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
#endif
    if (!f) return -1;
    fprintf(f, "{\n  \"jail\": %s,\n  \"workspaces\": [", g_policy.jail ? "true" : "false");
    for (int i = 0; i < g_policy.n; i++) {
        char esc[6200]; size_t u = 0;       // 1023 bytes × 6 (\u00XX) + quotes
        if (json_emit_str(esc, sizeof esc, &u, g_policy.ws[i], -1) < 0) { fclose(f); return -1; }
        fprintf(f, "%s\n    %.*s", i ? "," : "", (int)u, esc);
    }
    fputs(g_policy.n ? "\n  ]\n}\n" : "]\n}\n", f);
    if (fclose(f) != 0) return -1;
#ifdef _WIN32
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) return -1;
#else
    if (rename(tmp, path) != 0) return -1;
#endif
    snprintf(g_policy.path, sizeof g_policy.path, "%s", path);
    return 0;
}

static int add_ws(const char *p) {
    char c[1024];
    if (canon(p, c, sizeof c) != 0) { fprintf(stderr, "error: cannot resolve %s\n", p); return -1; }
    if (overlaps_cfg(c)) { fprintf(stderr, "error: %s overlaps the todoforai config dir (credentials, this policy)\n", c); return -1; }
    for (int i = 0; i < g_policy.n; i++) if (strcmp(g_policy.ws[i], c) == 0) return 0;
    if (g_policy.n >= POLICY_MAX_WS) { fprintf(stderr, "error: policy holds at most %d workspaces\n", POLICY_MAX_WS); return -1; }
    snprintf(g_policy.ws[g_policy.n++], sizeof g_policy.ws[0], "%s", c);
    return 0;
}

// ── jail (Linux only) ──────────────────────────────────────────────────────
// Landlock, applied in the child right before exec and inherited by the
// whole tree. Grant model: the system is readable except $HOME; inside
// $HOME only workspaces, toolchain/cache dirs (RW — installs need them) and
// shell rc files (RO). Writes: workspaces, /tmp, /dev. The config dir is
// never granted: parse() refuses any workspace overlapping it, and it isn't
// under any of the fixed grants.
//
// Runs post-fork in a multithreaded parent, so: no malloc/getenv/locale —
// snprintf on plain %s and open/fstat/syscall only.

#ifdef __linux__
static const char *RO_ROOTS[] = { "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc", "/opt",
                                  "/nix", "/snap", "/var/lib", "/proc", "/sys", "/run", NULL };
static const char *RW_ROOTS[] = { "/tmp", "/var/tmp", "/dev", NULL };
static const char *RW_HOME[]  = { ".cache", ".local", ".npm", ".bun", ".cargo", ".rustup", ".nvm", ".deno", "go",
                                  ".todoforai/bin", ".todoforai/tools", ".gitconfig", ".npmrc", NULL };
static const char *RO_HOME[]  = { ".bashrc", ".zshrc", ".profile", ".bash_profile", ".zshenv", NULL };

#define LL_RO_FILE (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE)
#define LL_RW_FILE (LL_RO_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE)
#define LL_RO      (LL_RO_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
#define LL_RW      (LL_RO | LL_RW_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
                    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | \
                    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
                    LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_IOCTL_DEV)

static int landlock_abi(void) {
    return (int)syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}

// 0 ok (absent path = nothing to grant), -1 real failure. Regular files get
// the file subset — Landlock rejects directory-only rights on a file rule.
static int ll_add(int rs, const char *path, __u64 access, __u64 handled) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT || errno == ENOTDIR ? 0 : -1;
    struct stat st;
    if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode)) access &= LL_RW_FILE;
    struct landlock_path_beneath_attr a = { .allowed_access = access & handled, .parent_fd = fd };
    int rc = (int)syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &a, 0);
    close(fd);
    return rc;
}

static int ll_add_home(int rs, const char *rel, __u64 access, __u64 handled) {
    char p[1200];
    if (snprintf(p, sizeof p, "%s/%s", g_home, rel) >= (int)sizeof p) return -1;
    return ll_add(rs, p, access, handled);
}

int bridge_policy_jail_child(void) {
    if (!g_policy.active) return 0;
    if (g_policy.broken) return -1;
    if (!g_policy.jail) return 0;
    int abi = landlock_abi();
    if (abi < 3) return -1;
    __u64 handled = LL_RW & ~(abi >= 5 ? 0 : LANDLOCK_ACCESS_FS_IOCTL_DEV);
    struct landlock_ruleset_attr ra = { .handled_access_fs = handled };
    int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) return -1;
    int rc = 0;
    for (int i = 0; RO_ROOTS[i] && rc == 0; i++) rc = ll_add(rs, RO_ROOTS[i], LL_RO, handled);
    for (int i = 0; RW_ROOTS[i] && rc == 0; i++) rc = ll_add(rs, RW_ROOTS[i], LL_RW, handled);
    for (int i = 0; RW_HOME[i] && rc == 0; i++)  rc = ll_add_home(rs, RW_HOME[i], LL_RW, handled);
    for (int i = 0; RO_HOME[i] && rc == 0; i++)  rc = ll_add_home(rs, RO_HOME[i], LL_RO, handled);
    for (int i = 0; i < g_policy.n && rc == 0; i++) rc = ll_add(rs, g_policy.ws[i], LL_RW, handled);
    if (rc == 0 && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) rc = -1;
    if (rc == 0) rc = (int)syscall(SYS_landlock_restrict_self, rs, 0);
    close(rs);
    return rc == 0 ? 0 : -1;
}
#else
// macOS/Windows: path checks only, the shell is not confined (policy.h).
int bridge_policy_jail_child(void) { return (g_policy.active && g_policy.broken) ? -1 : 0; }
#endif

// ── CLI ────────────────────────────────────────────────────────────────────

int cmd_policy(int argc, char **argv) {
    static const char *USAGE = "policy init [PATH...] | add PATH... | list";
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout, USAGE);
        printf("\nA device policy confines the backend to the listed workspaces on this\n"
               "machine: the bridge refuses other paths and (Linux 6.2+/macOS) jails every\n"
               "shell it spawns so nothing under $HOME outside them is reachable.\n"
               "Without a policy file the backend has the full access of this user.\n"
               "Windows: path checks only; the shell itself is not confined.\n\n"
               "  init [PATH...]   create the policy (default: current directory)\n"
               "  add PATH...      allow more workspaces\n"
               "  list             show the active policy\n");
        return 0;
    }
    bridge_policy_load();
    if (g_policy.active && g_policy.broken) {
        fprintf(stderr, "error: %s is unusable: %s\n", g_policy.path, g_policy.err);
        if (strcmp(argv[1], "list") != 0) return 1;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "list") == 0) {
        if (!g_policy.active) { printf("no device policy — backend has full user access\n"); return 0; }
        if (g_policy.broken) return 1;
        printf("%s (jail: %s)\n", g_policy.path, g_policy.jail ? "on" : "off");
        for (int i = 0; i < g_policy.n; i++) printf("  %s\n", g_policy.ws[i]);
        return 0;
    }
    if (strcmp(sub, "init") == 0) {
        if (g_policy.active && argc == 2) {
            fprintf(stderr, "policy already exists at %s (use `policy add`)\n", g_policy.path); return 1;
        }
        if (!g_policy.active) { g_policy.active = 1; g_policy.jail = 1; }
        if (argc == 2) { if (add_ws(".") != 0) return 1; }
        for (int i = 2; i < argc; i++) if (add_ws(argv[i]) != 0) return 1;
    } else if (strcmp(sub, "add") == 0) {
        if (argc < 3) { usage(stderr, USAGE); return 2; }
        if (!g_policy.active) { fprintf(stderr, "no policy yet — run `todoforai-bridge policy init` first\n"); return 1; }
        for (int i = 2; i < argc; i++) if (add_ws(argv[i]) != 0) return 1;
    } else {
        usage(stderr, USAGE); return 2;
    }
    if (save() != 0) { fprintf(stderr, "error: cannot write policy: %s\n", strerror(errno)); return 1; }
    printf("policy: %s\n", g_policy.path);
    for (int i = 0; i < g_policy.n; i++) printf("  %s\n", g_policy.ws[i]);
    printf("restart the bridge to apply\n");
    return 0;
}

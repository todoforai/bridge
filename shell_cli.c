// Shell helpers the bridge ships into every RUN: `__live` (tail shim) and
// `tfa-cat`. Both talk to the daemon's loopback shell relay (shell_relay.h),
// which forwards on the Noise channel — no curl, no per-call TLS, same code on
// Linux, macOS and Windows.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "subcmd.h"
#include "shell_relay.h"
#include "json.h"
#include "webfetch.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifdef _WIN32
#  include <io.h>
#  include <direct.h>   // _getcwd
#  include <sys/stat.h>
#  include <windows.h>
#  define sh_read(fd, b, n)  _read(fd, b, (unsigned)(n))
#  define sh_write(fd, b, n) _write(fd, b, (unsigned)(n))
#  define sh_open(p)         _open(p, _O_RDONLY | _O_BINARY)
#  define sh_close(fd)       _close(fd)
typedef int sh_ssize;
#else
#  include <signal.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  define sh_read(fd, b, n)  read(fd, b, n)
#  define sh_write(fd, b, n) write(fd, b, n)
#  define sh_open(p)         open(p, O_RDONLY | O_CLOEXEC)
#  define sh_close(fd)       close(fd)
typedef ssize_t sh_ssize;
#endif

static void stdio_binary(void) {
#ifdef _WIN32
    _setmode(0, _O_BINARY);
    _setmode(1, _O_BINARY);
#else
    signal(SIGPIPE, SIG_IGN);  // EPIPE instead: stop like cat would, but say so via rc
#endif
}

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        sh_ssize w = sh_write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

// Is stdout the agent's terminal? (Windows: _isatty is also true for NUL, so
// ask the console instead — the RUN's ConPTY is a console.)
static int stdout_is_tty(void) {
#ifdef _WIN32
    DWORD mode;
    return GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) != 0;
#else
    return isatty(1);
#endif
}

// ── `<bridge> __live` — tee stdin to stdout, lines also to the chat block ──
// The tail() shim runs `cmd | <bridge> __live | command tail …` so a `| tail -N`
// that would sit silent until EOF still shows lines in the chat block.
// Display-only (never stored; the tool result is still tail's). A plain tee:
// the daemon batches and rate-limits. Never breaks the pipe: without a relay it
// is a plain `cat`, and EOF never waits on the network.
int cmd_live(int argc, char **argv) {
    (void)argc; (void)argv;
    stdio_binary();
    char err[256];
    ws_fd_t s = getenv("TODOFORAI_MESSAGE_ID") ? shell_client_open("live", NULL, NULL, -1, NULL, 0, err, sizeof err) : WS_INVALID_FD;
    static char in[16 * 1024];
    int out_ok = 1;
    for (;;) {
        sh_ssize r = sh_read(0, in, sizeof in);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        if (write_all(1, in, (size_t)r) < 0) { out_ok = 0; break; }  // reader gone
        if (s != WS_INVALID_FD && shell_client_send_lossy(s, in, (size_t)r) != 0) { shell_client_close(s); s = WS_INVALID_FD; }
    }
    if (s != WS_INVALID_FD) shell_client_close(s);   // daemon flushes the last lines
    return out_ok ? 0 : 141;  // 128+SIGPIPE, what cat reports under pipefail
}

// ── `tfa-cat` — cat, except media printed to the agent's terminal reaches the model ──
// POSIX: the bridge symlinks ~/.todoforai/tools/bin/tfa-cat to itself and
// dispatches on argv[0]; Windows: a tfa-cat() shell function → `<bridge> __cat`.
// stdout = the RUN's terminal → images/PDFs (sniffed by magic bytes) go through
// the relay to the running bash block; the backend hands them to the agent
// with this bash call's result. Text, and redirected/piped stdout, is plain cat.

#define CAT_MAX_BYTES (20L * 1024 * 1024)   // backend per-command cap
#define CAT_MAX_IMAGE 3500000L              // agent MAX_MEDIA_IMAGE_BYTES (LLM API limit)

static const char *cat_sniff(const unsigned char *b, size_t n, const char **ext) {
    if (n >= 8 && !memcmp(b, "\x89PNG\r\n\x1a\n", 8)) { *ext = "png"; return "image/png"; }
    if (n >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff) { *ext = "jpg"; return "image/jpeg"; }
    if (n >= 6 && (!memcmp(b, "GIF87a", 6) || !memcmp(b, "GIF89a", 6))) { *ext = "gif"; return "image/gif"; }
    if (n >= 12 && !memcmp(b, "RIFF", 4) && !memcmp(b + 8, "WEBP", 4)) { *ext = "webp"; return "image/webp"; }
    if (n >= 5 && !memcmp(b, "%PDF-", 5)) { *ext = "pdf"; return "application/pdf"; }
    return NULL;
}

// Could b[0..n) still grow into a supported magic? (Stop sniffing as soon as not,
// so a short line on an open pipe prints at once, like cat.)
static int cat_may_match(const unsigned char *b, size_t n) {
    static const char *const pre[] = { "\x89PNG\r\n\x1a\n", "\xff\xd8\xff", "GIF8", "RIFF", "%PDF-" };
    for (size_t i = 0; i < sizeof pre / sizeof *pre; i++) {
        size_t m = strlen(pre[i]);
        if (!memcmp(b, pre[i], n < m ? n : m) && (n < m || i == 2 || i == 3)) return 1;
    }
    return 0;
}

// Read up to 16 bytes, but only while a magic is still possible.
static sh_ssize cat_head(int fd, unsigned char *p, size_t cap) {
    size_t got = 0;
    while (got < cap) {
        sh_ssize r = sh_read(fd, p + got, cap - got);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) break;
        got += (size_t)r;
        if (!cat_may_match(p, got)) break;
        const char *ext; if (cat_sniff(p, got, &ext) && got >= 12) break;
    }
    return (sh_ssize)got;
}

static int file_exists(const char *p);

// Office/rich documents anydoc (catalog tool) turns into text: the binary hint names it.
static int cat_is_office(const char *name) {
    static const char *const ext[] = { ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".epub" };
    size_t n = strlen(name);
    for (size_t i = 0; i < sizeof ext / sizeof *ext; i++) {
        size_t m = strlen(ext[i]), j = 0;
        if (n < m) continue;
        while (j < m && (name[n - m + j] | 0x20) == ext[i][j]) j++;
        if (j == m) return 1;
    }
    return 0;
}


// `FILE:FROM[:TO]` → lines FROM..TO (1-based, inclusive; no TO = to EOF), as
// the agent's `read` tool takes them. Lines are filtered on the way out, so a
// range of a huge file or ref costs only what it prints.
typedef struct { long from, to, line, bytes; char last; } cat_range_t;   // from 0 = whole input; bytes/last: what was read

// Split a trailing `:N[:M]` off `arg` into `path` (an existing file named so
// wins). Refs under todoforai:todos/ take a range only after an attachment id
// (a UUID), so names like `…/bash:1` stay names — the agent's ReadTool rule.
static int cat_split_range(const char *arg, char *path, size_t cap, cat_range_t *r) {
    *r = (cat_range_t){ .line = 1, .last = '\n' };
    size_t n = strlen(arg);
    if (n >= cap) return -1;
    memcpy(path, arg, n + 1);
    if (file_exists(arg)) return 0;
    long num[2]; int k = 0;
    char *end = path + n;
    while (k < 2) {
        char *p = end;
        while (p > path && p[-1] >= '0' && p[-1] <= '9') p--;
        if (p == end || p <= path + 1 || p[-1] != ':') break;
        if (end - p > 9) { k = 0; break; }   // no line number is that long: a name
        num[k++] = strtol(p, NULL, 10);
        end = p - 1;
    }
    if (!k) return 0;
    *end = '\0';
    if (!strncmp(path, "todoforai:todos/", sizeof "todoforai:todos/" - 1)) {
        const char *id = strrchr(path, '/') + 1;
        int ok = strlen(id) == 36;
        for (const char *c = id; ok && *c; c++)
            ok = (*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f') || (*c >= 'A' && *c <= 'F') || *c == '-';
        if (!ok) { memcpy(path, arg, n + 1); return 0; }
    }
    r->from = num[k - 1] < 1 ? 1 : num[k - 1];
    r->to = k == 2 ? (num[0] < r->from ? r->from : num[0]) : 0;
    return 1;
}

// Write the part of buf[0..n) inside the range. 0 go on, 1 past the range, -1 write error.
static int cat_write(int out, const char *buf, size_t n, cat_range_t *r) {
    if (!r->from) {
        if (n) { r->bytes += (long)n; r->last = buf[n - 1]; }
        for (const char *p = buf; (p = memchr(p, '\n', n - (size_t)(p - buf))); p++) r->line++;
        return write_all(out, buf, n) < 0 ? -1 : 0;
    }
    size_t i = 0;
    while (i < n) {
        if (r->to && r->line > r->to) return 1;
        const char *nl = memchr(buf + i, '\n', n - i);
        size_t e = nl ? (size_t)(nl - buf) + 1 : n;
        if (r->line >= r->from && write_all(out, buf + i, e - i) < 0) return -1;
        if (nl) r->line++;
        i = e;
    }
    return r->to && r->line > r->to;
}

// Over this, the bash tool's default output cap (first+last 10k chars) cuts the
// middle — say how big the file is so the agent can read the rest by range.
#define CAT_BIG_TEXT 20000L
static void cat_big_note(const char *name, const cat_range_t *r) {
    if (r->from || r->bytes <= CAT_BIG_TEXT) return;
    fprintf(stderr, "\ntfa-cat: %s: %ld lines, %ld bytes — if the output above was cut, print a part: tfa-cat '%s:FROM:TO'\n",
            name, r->line - (r->last == '\n'), r->bytes, name);
}

// Rest of `fd` after `head` → out. 0 ok, -1 read error, -2 write error,
// -3 binary (`check_bin` and a NUL in the first block; nothing written).
static int cat_copy(int fd, int out, const unsigned char *head, size_t hn, int check_bin, cat_range_t *rng) {
    if (check_bin && hn && memchr(head, 0, hn)) return -3;
    static char buf[64 * 1024];
    for (int first = 1;; first = 0) {
        sh_ssize r = sh_read(fd, buf, sizeof buf);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (first) {
            if (check_bin && r > 0 && memchr(buf, 0, (size_t)r)) return -3;
            if (hn) {
                int w = cat_write(out, (const char *)head, hn, rng);
                if (w < 0) return -2;
                if (w > 0) return 0;
            }
        }
        if (r == 0) return 0;
        int w = cat_write(out, buf, (size_t)r, rng);
        if (w < 0) return -2;
        if (w > 0) return 0;
    }
}

// head + rest of fd → one attach stream (or, with `ref`, a put: the bytes
// replace that `todoforai:` resource). NULL on success, else the reason.
// Read whole first (≤ the cap): the stream declares its exact size, so a
// killed or failing tfa-cat can never leave a truncated file behind.
static const char *cat_upload(int fd, const unsigned char *head, size_t hn, const char *name,
                              const char *mime, const char *ref, char *err, size_t errcap) {
    char *buf = malloc(CAT_MAX_BYTES + 1);
    if (!buf) return "out of memory";
    if (hn) memcpy(buf, head, hn);
    size_t total = hn;
    const char *fail = NULL;
    for (;;) {
        sh_ssize r = sh_read(fd, buf + total, CAT_MAX_BYTES + 1 - total);
        if (r < 0) { if (errno == EINTR) continue; fail = "read error"; break; }
        if (r == 0) break;
        total += (size_t)r;
        if (total > CAT_MAX_BYTES) {
            snprintf(err, errcap, "over %ld bytes — compress/downscale it first", CAT_MAX_BYTES);
            fail = err; break;
        }
    }
    if (!fail && mime && !strncmp(mime, "image/", 6) && (long)total > CAT_MAX_IMAGE) {
        snprintf(err, errcap, "image over %ld bytes — downscale it first (e.g. `convert in.png -resize 1568x1568\\> out.png`)", CAT_MAX_IMAGE);
        fail = err;
    }
    if (!fail) {
        ws_fd_t s = shell_client_open(ref ? "put" : "attach", name, mime, (long)total, ref, 0, err, errcap);
        if (s == WS_INVALID_FD) fail = err;
        else if (shell_client_send(s, buf, total)) { shell_client_close(s); fail = "bridge daemon hung up"; }
        else fail = shell_client_finish(s, SHELL_REPLY_MS + 5000, err, errcap);
    }
    free(buf);
    return fail;
}

// ── refs: `skill:<name>[/file]` (this machine), `todoforai:…` (the backend) ──

// A regular file (stat, not open: a FIFO must not block the lookup).
static int file_exists(const char *p) {
#ifdef _WIN32
    struct _stat st;
    return _stat(p, &st) == 0 && (st.st_mode & _S_IFREG);
#else
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

// ── skills on this machine: ONE walk for `--scan`, `list` and `<name>` ──
// Per root: {.agents,.claude}/skills, then {.agents,.claude}/plugins/*/ (sorted)
// skills + commands. In each skills dir, `find -L -maxdepth 6 -name '.*' -prune`
// order: every SKILL.md, then each *.md lying directly in it (loose). The walk
// reads each file's head exactly as the shell walk's awk did and visits only what
// that walk emitted. `--scan` replaces that shell walk in the agent
// (_bridge_get_skills) and the apps (shared-fer buildSkillWalkScript), which keep
// it only as the fallback for a bridge without `--scan`.

static int is_dir(const char *p) {
#ifdef _WIN32
    struct _stat st;
    return _stat(p, &st) == 0 && (st.st_mode & _S_IFDIR);
#else
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

typedef struct { char *v; size_t n, cap; int fail; } sk_buf_t;

static void sk_put(sk_buf_t *b, const char *s, size_t n) {
    if (b->fail) return;
    if (b->n + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 16384;
        while (c < b->n + n + 1) c *= 2;
        char *v = realloc(b->v, c);
        if (!v) { b->fail = 1; return; }
        b->v = v; b->cap = c;
    }
    memcpy(b->v + b->n, s, n);
    b->n += n;
    b->v[b->n] = '\0';
}

// A file read line by line, whole lines (awk getline), up to 4 MB.
typedef struct { int fd, eof; sk_buf_t b; size_t at; } sk_file_t;

// Next line (without its \n) → *ln, its length; -1 at the end.
static long sk_line(sk_file_t *f, const char **ln) {
    for (;;) {
        char *nl = f->at < f->b.n ? memchr(f->b.v + f->at, '\n', f->b.n - f->at) : NULL;
        if (nl || f->eof) {
            if (f->at >= f->b.n) return -1;
            size_t l = nl ? (size_t)(nl - (f->b.v + f->at)) : f->b.n - f->at;
            *ln = f->b.v + f->at;
            f->at += l + (nl ? 1 : 0);
            return (long)l;
        }
        char chunk[16384];
        sh_ssize r = f->b.n < 4u << 20 ? sh_read(f->fd, chunk, sizeof chunk) : 0;
        if (r <= 0) f->eof = 1;
        else { sk_put(&f->b, chunk, (size_t)r); if (f->b.fail) return -1; }
    }
}

static int sk_is_fence(const char *l, long n) { if (n && l[n - 1] == '\r') n--; return n == 3 && !strncmp(l, "---", 3); }

// The head the shell walk's awk emitted: a closed `---` frontmatter (cut past 8K:
// none), plus ≤ 2K of body for a loose .md, whose frontmatter is optional. 1 = it has one.
static int sk_head(const char *path, int loose, sk_buf_t *out) {
    sk_file_t f = { sh_open(path), 0, { 0 }, 0 };
    if (f.fd < 0) return 0;
    const char *l;
    long ll = sk_line(&f, &l);
    int ok = 0;
#define SK_ADD(p, len) do { sk_put(out, p, (size_t)(len)); sk_put(out, "\n", 1); } while (0)
    if (ll >= 0) {
        int bom = ll >= 3 && !memcmp(l, "\357\273\277", 3);
        size_t c = (size_t)ll + 1;
        if (sk_is_fence(l + 3 * bom, ll - 3 * bom)) {
            SK_ADD(l, ll);
            while ((ll = sk_line(&f, &l)) >= 0) {
                if ((c += (size_t)ll + 1) > 8192) break;
                SK_ADD(l, ll);
                if (sk_is_fence(l, ll)) { ok = 1; break; }
            }
            for (size_t m = 0; ok && loose && m < 2048 && (ll = sk_line(&f, &l)) >= 0; m += (size_t)ll + 1) SK_ADD(l, ll);
        } else if (loose) {
            SK_ADD(l, ll);
            ok = 1;
            while (c < 2048 && (ll = sk_line(&f, &l)) >= 0) { c += (size_t)ll + 1; SK_ADD(l, ll); }
        }
    }
#undef SK_ADD
    sh_close(f.fd);
    free(f.b.v);
    if (f.b.fail) out->fail = 1;
    if (!ok) out->n = 0;
    return ok;
}

// A walk visits each record the shell walk emitted: (kind skill|loose|command, plugin,
// path, head); nonzero from `fn` stops it. `fail`: out of memory, the walk is incomplete.
typedef struct sk_walk sk_walk_t;
struct sk_walk {
    int (*fn)(sk_walk_t *w, const char *kind, const char *plugin, const char *path, const char *head, size_t hn);
    const char *scope; void *ctx; int fail;
};

static int sk_visit(sk_walk_t *w, const char *kind, const char *plugin, const char *path) {
    if (strpbrk(path, "\036\037") || strpbrk(plugin, "\036\037")) return 0;
    sk_buf_t h = { 0 };
    int ok = sk_head(path, !strcmp(kind, "loose"), &h);
    int stop = 0;
    if (h.fail) w->fail = 1;
    else if ((ok || !strcmp(kind, "command")) && !(h.n && memchr(h.v, '\036', h.n))) stop = w->fn(w, kind, plugin, path, h.n ? h.v : "", h.n);
    free(h.v);
    return stop;
}

static int sk_is_md(const char *n) { size_t l = strlen(n); return l >= 3 && !strcmp(n + l - 3, ".md"); }

// A directory's identity, so a symlink back into its own ancestry is skipped (find -L).
typedef struct sk_anc { unsigned long long dev, ino; const struct sk_anc *up; } sk_anc_t;
static int sk_id(const char *p, sk_anc_t *a) {
#ifdef _WIN32
    (void)p; (void)a; return 0;   // no inode numbers: the depth cap bounds a loop
#else
    struct stat st;
    if (stat(p, &st)) return 0;
    a->dev = (unsigned long long)st.st_dev; a->ino = (unsigned long long)st.st_ino;
    return 1;
#endif
}

// find -L <dir> -maxdepth 6 -name '.*' -prune -o -type f -name <pat> (NULL: *.md), readdir order.
static int sk_find(sk_walk_t *w, const char *dir, int level, const sk_anc_t *up, const char *kind, const char *plugin, const char *pat) {
    sk_anc_t me = { 0, 0, up };
    if (sk_id(dir, &me)) for (const sk_anc_t *a = up; a; a = a->up) if (a->dev == me.dev && a->ino == me.ino) return 0;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    char p[4096];
    int stop = 0;
    while (!stop && (e = readdir(d))) {
        if (e->d_name[0] == '.' || snprintf(p, sizeof p, "%s/%s", dir, e->d_name) >= (int)sizeof p) continue;
        if (is_dir(p)) { if (level < 6) stop = sk_find(w, p, level + 1, &me, kind, plugin, pat); }
        else if ((pat ? !strcmp(e->d_name, pat) : sk_is_md(e->d_name)) && file_exists(p)) stop = sk_visit(w, kind, plugin, p);
    }
    closedir(d);
    return stop;
}

// A skills dir: its SKILL.md tree, then every *.md lying directly in it (as loose).
static int sk_skills(sk_walk_t *w, const char *dir, const char *plugin) {
    if (!is_dir(dir)) return 0;
    if (sk_find(w, dir, 1, NULL, "skill", plugin, "SKILL.md")) return 1;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    char p[4096];
    int stop = 0;
    while (!stop && (e = readdir(d))) {
        if (e->d_name[0] == '.' || !sk_is_md(e->d_name)) continue;
        if (snprintf(p, sizeof p, "%s/%s", dir, e->d_name) < (int)sizeof p && file_exists(p)) stop = sk_visit(w, "loose", plugin, p);
    }
    closedir(d);
    return stop;
}

static int skill_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int sk_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'; }

// A plugin's name as the shell walk's sed read .claude-plugin/plugin.json: on the first
// line holding `"name"<sp>:<sp>"<value>"`, its last such value; empty/none: the folder.
static void sk_plugin_name(const char *pdir, const char *dflt, char *out, size_t cap) {
    snprintf(out, cap, "%s", dflt);
    char f[4200];
    if (snprintf(f, sizeof f, "%s/.claude-plugin/plugin.json", pdir) >= (int)sizeof f || !file_exists(f)) return;
    sk_file_t r = { sh_open(f), 0, { 0 }, 0 };
    if (r.fd < 0) return;
    const char *l;
    long ll;
    while ((ll = sk_line(&r, &l)) >= 0) {
        const char *best = NULL;
        size_t bl = 0;
        for (const char *p = l; (p = memchr(p, '"', (size_t)(l + ll - p))); p++) {
            if ((size_t)(l + ll - p) < 6 || strncmp(p, "\"name\"", 6)) continue;
            const char *v = p + 6, *end = l + ll;
            while (v < end && sk_space(*v)) v++;
            if (v >= end || *v++ != ':') continue;
            while (v < end && sk_space(*v)) v++;
            if (v >= end || *v++ != '"') continue;
            const char *q = memchr(v, '"', (size_t)(end - v));
            if (q) { best = v; bl = (size_t)(q - v); }
        }
        if (best) { if (bl && bl < cap) { memcpy(out, best, bl); out[bl] = '\0'; } break; }
    }
    sh_close(r.fd);
    free(r.b.v);
}

// <root>/{.agents,.claude}/{skills, plugins/*/{skills,commands}}. `strip`: trailing
// slashes off first, as the callers do to a workspace root (never to $HOME).
static int sk_root(sk_walk_t *w, const char *root, int strip) {
    static const char *const dirs[] = { ".agents", ".claude" };
    char r[4096], base[4200], pdir[4400], sub[4500], pn[1024];
    snprintf(r, sizeof r, "%s", root);
    for (size_t l = strlen(r); strip && l && r[l - 1] == '/'; ) r[--l] = '\0';
    for (int i = 0; i < 2; i++) {
        if (snprintf(base, sizeof base, "%s/%s/skills", r, dirs[i]) < (int)sizeof base && sk_skills(w, base, "")) return 1;
        if (snprintf(base, sizeof base, "%s/%s/plugins", r, dirs[i]) >= (int)sizeof base) continue;
        DIR *d = opendir(base);
        if (!d) continue;
        struct dirent *e;
        char **pl = NULL;
        size_t np = 0, cap = 0;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            if (np == cap) { char **v = realloc(pl, (cap = cap ? cap * 2 : 16) * sizeof *pl); if (!v) { w->fail = 1; break; } pl = v; }
            if (!(pl[np] = strdup(e->d_name))) { w->fail = 1; break; }
            np++;
        }
        closedir(d);
        if (np) qsort(pl, np, sizeof *pl, skill_cmp);   // `plugins/*/` glob order
        int stop = 0;
        for (size_t j = 0; j < np; j++) {
            if (!stop && snprintf(pdir, sizeof pdir, "%s/%s", base, pl[j]) < (int)sizeof pdir && is_dir(pdir)) {
                sk_plugin_name(pdir, pl[j], pn, sizeof pn);
                stop = (snprintf(sub, sizeof sub, "%s/skills", pdir) < (int)sizeof sub && sk_skills(w, sub, pn))
                    || (snprintf(sub, sizeof sub, "%s/commands", pdir) < (int)sizeof sub && is_dir(sub) && sk_find(w, sub, 1, NULL, "command", pn, NULL));
            }
            free(pl[j]);
        }
        free(pl);
        if (stop) return 1;
    }
    return 0;
}

static void sk_home(char *home, size_t cap) {
    const char *h = getenv("HOME");
#ifdef _WIN32
    if (!h || !*h) h = getenv("USERPROFILE");
#endif
    snprintf(home, cap, "%s", h ? h : "");
#ifdef _WIN32
    for (char *c = home; *c; c++) if (*c == '\\') *c = '/';
#endif
}

// What a skill name means in this shell: the cwd, its parents, then $HOME, as the agent lists.
static int sk_local(sk_walk_t *w) {
    char dir[4096], home[4096];
    sk_home(home, sizeof home);
#ifdef _WIN32
    if (!_getcwd(dir, sizeof dir)) dir[0] = '\0';
    for (char *c = dir; *c; c++) if (*c == '\\') *c = '/';
#else
    if (!getcwd(dir, sizeof dir)) dir[0] = '\0';
#endif
    while (dir[0]) {
        if (strcmp(dir, home) && sk_root(w, dir, 1)) return 1;
        char *cut = strrchr(dir, '/');
        if (!cut || cut[1] == '\0') break;   // was "/" or "C:/" — done
        cut[cut == dir || (cut == dir + 2 && dir[1] == ':') ? 1 : 0] = '\0';   // keep the root's slash
    }
    return *home && sk_root(w, home, 0);
}

// Append `src[0..n)` to `out` with whitespace runs collapsed to one space.
static void ws_append(char *out, size_t cap, const char *src, size_t n) {
    size_t o = strlen(out);
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        int sp = src[i] == ' ' || src[i] == '\t' || src[i] == '\r' || src[i] == '\n';
        if (sp) { if (o && out[o - 1] != ' ') out[o++] = ' '; }
        else out[o++] = src[i];
    }
    out[o] = '\0';
}

// A skill file's name + description as the agent's _skill_meta reads them (top-level
// `name:`/`description:`, block scalars folded; a loose .md: stem + first paragraph).
// 0 = not listed (no closed frontmatter, disabled).
// A record's name + description as the agent's _skill_meta reads its head (top-level
// `name:`/`description:`, block scalars folded; a loose .md: stem + first paragraph;
// name whitespace collapsed, at most 64 characters). 0 = not listed.
static int skill_meta_of(const char *head, int loose, const char *dflt, char *name, size_t ncap, char *desc, size_t dcap) {
    const char *buf = head;
    snprintf(name, ncap, "%s", dflt);
    desc[0] = '\0';
    const char *p = buf;
    if (!strncmp(p, "\xef\xbb\xbf", 3)) p += 3;
    const char *body = p;
    if (!strncmp(p, "---", 3) && (p[3] == '\n' || p[3] == '\r')) {
        int closed = 0, in_desc = 0;
        for (p = strchr(p, '\n'); p && *++p; p = strchr(p, '\n')) {
            size_t l = strcspn(p, "\r\n");
            while (l && (p[l - 1] == ' ' || p[l - 1] == '\t')) l--;
            if (l == 3 && !strncmp(p, "---", 3)) { closed = 1; body = p + l; break; }
            if (in_desc && (p[0] == ' ' || p[0] == '\t' || !l)) { ws_append(desc, dcap, " ", 1); ws_append(desc, dcap, p, l); continue; }
            in_desc = 0;
            size_t k = 0;
            while (k < l && (p[k] == '_' || p[k] == '-' || (unsigned)((p[k] | 0x20) - 'a') < 26u || (unsigned)(p[k] - '0') < 10u)) k++;
            size_t c = k;
            while (c < l && (p[c] == ' ' || p[c] == '\t')) c++;
            if (!k || c >= l || p[c] != ':') continue;
            const char *v = p + c + 1;
            size_t vl = l - (size_t)(v - p);
            while (vl && (*v == ' ' || *v == '\t')) { v++; vl--; }
            for (size_t i = 1; i < vl; i++) if (v[i] == '#' && (v[i - 1] == ' ' || v[i - 1] == '\t')) { vl = i; break; }
            while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
            if (vl >= 2 && (*v == '"' || *v == '\'') && v[vl - 1] == *v) { v++; vl -= 2; }
            if (k == 24 && !strncmp(p, "disable-model-invocation", 24) && vl == 4 && !strncmp(v, "true", 4)) return 0;
            if (k == 4 && !strncmp(p, "name", 4) && vl) { if (vl >= ncap) return 0; memcpy(name, v, vl); name[vl] = '\0'; }
            if (k == 11 && !strncmp(p, "description", 11)) {
                desc[0] = '\0';
                if (vl && (*v == '>' || *v == '|')) in_desc = 1;   // block scalar: the indented lines below
                else ws_append(desc, dcap, v, vl);
            }
        }
        if (!closed) return 0;
    } else if (!loose) return 0;
    if (loose && !desc[0]) {   // first prose paragraph of the body
        for (p = body; *p; ) {
            size_t l = strcspn(p, "\r\n");
            const char *t = p;
            while (l && (*t == ' ' || *t == '\t')) { t++; l--; }
            int skip = !l || *t == '#' || *t == '|' || !strncmp(t, "```", 3) || !strncmp(t, "---", 3);
            if (skip && desc[0]) break;
            if (!skip) { if (desc[0]) ws_append(desc, dcap, " ", 1); ws_append(desc, dcap, t, l); }
            p += strcspn(p, "\r\n");
            if (*p == '\r') p++;
            if (*p == '\n') p++;
        }
    }
    size_t o = strlen(desc);
    while (o && desc[o - 1] == ' ') desc[--o] = '\0';
    return 1;
}


// A skill's name when its frontmatter has none: SKILL.md → its folder, a loose/command .md → its stem.
static void sk_dflt_name(const char *path, const char *kind, char *out, size_t cap) {
    const char *end = path + strlen(path), *b;
    if (!strcmp(kind, "skill")) { end = strrchr(path, '/'); if (!end) end = path; }
    for (b = end; b > path && b[-1] != '/'; b--) ;
    size_t l = (size_t)(end - b);
    if (strcmp(kind, "skill") && l > 3) l -= 3;   // .md
    if (l >= cap) l = cap - 1;
    memcpy(out, b, l); out[l] = '\0';
}


// A record the agent lists (not a command, not a loose SKILL.md/README.md) → its name + description.
static int sk_listable(const char *kind, const char *path, const char *head, char *name, size_t ncap, char *desc, size_t dcap) {
    if (!strcmp(kind, "command")) return 0;
    int loose = !strcmp(kind, "loose");
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (loose && (!strcmp(b, "SKILL.md") || !strcasecmp(b, "README.md"))) return 0;
    char dflt[256], raw[1024];
    sk_dflt_name(path, kind, dflt, sizeof dflt);
    if (!skill_meta_of(head, loose, dflt, raw, sizeof raw, desc, dcap)) return 0;
    name[0] = '\0';
    ws_append(name, ncap, raw, strlen(raw));
    size_t o = strlen(name), cps = 0;
    while (o && name[o - 1] == ' ') name[--o] = '\0';
    for (const char *c = name; *c; c++) cps += ((unsigned char)*c & 0xC0) != 0x80;
    return *name && cps <= 64;
}

// <name>[/<file>] → the skill's SKILL.md (or <file> in its folder) on this machine:
// the first record listed under that name (first wins, as in the agent's list).
// 0 found, -1 no such skill here (bad name too), -2 a loose <name>.md: no files beside it.
typedef struct { const char *want; char *out; size_t cap; } sk_find_t;
static int sk_named(sk_walk_t *w, const char *kind, const char *plugin, const char *path, const char *head, size_t hn) {
    (void)plugin; (void)hn;
    sk_find_t *f = w->ctx;
    char name[1024], desc[64];
    if (!sk_listable(kind, path, head, name, sizeof name, desc, sizeof desc) || strcmp(name, f->want)) return 0;
    snprintf(f->out, f->cap, "%s", path);
    return 1;
}

static int skill_path(const char *spec, char *out, size_t cap) {
    if (!*spec || strstr(spec, "..") || strchr(spec, '\\') || spec[0] == '/') return -1;
    char name[256], skill[4096] = "";
    size_t nl = strcspn(spec, "/");
    if (nl >= sizeof name) return -1;
    memcpy(name, spec, nl); name[nl] = '\0';
    const char *file = spec[nl] ? spec + nl + 1 : NULL;
    sk_find_t f = { name, skill, sizeof skill };
    sk_walk_t w = { sk_named, "", &f, 0 };
    if (!sk_local(&w) || skill[0] == '\0') return -1;
    if (!file) return snprintf(out, cap, "%s", skill) < (int)cap ? 0 : -1;
    char *slash = strrchr(skill, '/');
    if (!slash || strcmp(slash, "/SKILL.md")) { snprintf(out, cap, "%s", skill); return -2; }
    *slash = '\0';
    return snprintf(out, cap, "%s/%s", skill, file) < (int)cap ? 0 : -1;
}

// A backend resource, as the agent's `read` sees it. On the agent's terminal
// an image/PDF is attached by the backend directly (no bytes come here);
// anything else — and everything when piped — is printed like a file.
// The command name in messages: `tfa-skill` reuses cat_one through a skill: ref.
static const char *cat_prog = "tfa-cat";
// The file the last skill: ref resolved to on this machine ("" = none / the backend's).
static char cat_skill_file[4096];

static int cat_ref(const char *ref, int attach, int tty, cat_range_t *rng) {
    // tfa-skill names its skill, not the `skill:` ref it fetches.
    const char *shown = strcmp(cat_prog, "tfa-skill") == 0 && strncmp(ref, "skill:", 6) == 0 ? ref + 6 : ref;
    if (!attach) { fprintf(stderr, "%s: %s: refs need an agent shell (TODOFORAI_BLOCK_ID unset)\n", cat_prog, shown); return 1; }
    char err[512], mime[128];
    ws_fd_t s = shell_client_open("fetch", NULL, NULL, -1, ref, tty, err, sizeof err);
    if (s == WS_INVALID_FD) { fprintf(stderr, "%s: %s: %s\n", cat_prog, shown, err); return 1; }
    long size = 0;
    int r = shell_client_fetch_head(s, &size, mime, sizeof mime, err, sizeof err);
    if (r <= 0) {
        shell_client_close(s);
        if (r < 0) { fprintf(stderr, "%s: %s: %s\n", cat_prog, shown, err); return 1; }
        return 0;   // attached
    }
    static char buf[64 * 1024];
    long got = 0;
    int rc = 0, done = 0;
    while (got < size) {
        long n = shell_client_recv(s, buf, sizeof buf);
        if (n <= 0) break;
        // Binary (a NUL early on: docx/xlsx/zip/…) on the agent's terminal is
        // noise: say how to get it instead. Piped/redirected → bytes, like cat.
        if (tty && got == 0 && memchr(buf, 0, (size_t)n)) {
            const char *b = ref;
            for (const char *c = ref; *c; c++) if (*c == '/' || *c == ':') b = c + 1;
            if (!*b) b = "file";
            fprintf(stderr, "tfa-cat: %s: binary (%s, %ld bytes), not printed. Save it: tfa-cat '%s' > '%s'%s%s%s\n",
                    ref, mime, size, ref, b, cat_is_office(b) ? " && anydoc '" : "", cat_is_office(b) ? b : "", cat_is_office(b) ? "' (as text)" : "");
            shell_client_close(s);
            return 1;
        }
        got += n;
        int w = cat_write(1, buf, (size_t)n, rng);
        if (w < 0) { rc = 141; break; }
        if (w > 0) { done = 1; break; }   // range done: closing cancels the rest
    }
    shell_client_close(s);
    if (!rc && !done && got != size) { fprintf(stderr, "tfa-cat: %s: transfer broke (%ld of %ld bytes)\n", ref, got, size); rc = 1; }
    if (!rc && tty) cat_big_note(ref, rng);
    return rc;
}


// One input. 0 ok, 1 error (already reported), 141 stdout gone.
static int cat_one(const char *arg, int attach, int tty, int *stdin_seq) {
    int is_stdin = strcmp(arg, "-") == 0;
    char skill[4096], spec[4096];
    cat_range_t rng = { .line = 1, .last = '\n' };
    if (!is_stdin) {
        if (cat_split_range(arg, spec, sizeof spec, &rng) < 0) { fprintf(stderr, "tfa-cat: %s: name too long\n", arg); return 1; }
        if (rng.from && spec[strspn(spec, "0123456789")] == '\0' && !file_exists(spec)) {
            fprintf(stderr, "tfa-cat: %s: no file before the range — use FILE:FROM:TO (e.g. src/main.c:%s)\n", arg, arg);
            return 1;
        }
        arg = spec;
    }
    if (!is_stdin && strncmp(arg, "skill:", 6) == 0) {
        cat_skill_file[0] = '\0';
        // Not on this machine: the backend has the project's and the built-in ones.
        int sp = skill_path(arg + 6, skill, sizeof skill);
        // A skill found here keeps its own files: never a same-named one's from the backend.
        if (sp == -2) { fprintf(stderr, "%s: %s: %s is a single file, nothing beside it\n", cat_prog, arg + 6, skill); return 1; }
        if (sp != 0) return cat_ref(arg, attach, tty, &rng);
        snprintf(cat_skill_file, sizeof cat_skill_file, "%s", skill);
        arg = skill;
    } else if (!is_stdin && strncmp(arg, "todoforai:", 10) == 0 && !file_exists(arg)) {
        return cat_ref(arg, attach, tty, &rng);
    }
    int fd = is_stdin ? 0 : sh_open(arg);
    if (fd < 0) { fprintf(stderr, "tfa-cat: %s: %s\n", arg, strerror(errno)); return 1; }
    unsigned char head[16];
    // Redirected/piped stdout: plain cat, no sniffing (and no waiting for 16 bytes).
    sh_ssize hn = tty ? cat_head(fd, head, sizeof head) : 0;
    int rc = 0;
    const char *ext = NULL, *mime = hn > 0 ? cat_sniff(head, (size_t)hn, &ext) : NULL;
    if (hn < 0) { fprintf(stderr, "tfa-cat: %s: %s\n", arg, strerror(errno)); rc = 1; }
    else if (mime) {
        // Raw image bytes on a terminal help nobody — attach, or say why not.
        char name[128], err[512];
        if (is_stdin) snprintf(name, sizeof name, "stdin-%d.%s", ++*stdin_seq, ext);
        else {
            const char *b = arg;
            for (const char *c = arg; *c; c++) if (*c == '/' || *c == '\\') b = c + 1;
            snprintf(name, sizeof name, "%.127s", b);
            for (char *p = name; *p; p++) if (*p == '"' || *p == ';' || *p == '\\' || (unsigned char)*p < 32) *p = '_';
        }
        const char *e = !attach
            ? "not in an agent shell (remote/ssh? pipe it: `ssh host cat f | tfa-cat`)"
            : cat_upload(fd, head, (size_t)hn, name, mime, NULL, err, sizeof err);
        if (e) { fprintf(stderr, "tfa-cat: %s: not attached: %s\n", arg, e); rc = 1; }
    } else {
        // Binary on the agent's terminal is noise (see cat_ref); piped → bytes.
        int r = cat_copy(fd, 1, head, hn > 0 ? (size_t)hn : 0, tty, &rng);
        if (r == -1) { fprintf(stderr, "tfa-cat: %s: %s\n", arg, strerror(errno)); rc = 1; }
        else if (r == -2) rc = 141;
        else if (r == -3) {
            if (cat_is_office(arg)) fprintf(stderr, "tfa-cat: %s: binary, not printed. As text: anydoc '%s'\n", arg, arg);
            else fprintf(stderr, "tfa-cat: %s: binary, not printed (use a tool that reads it, or pipe/redirect for the raw bytes)\n", arg);
            rc = 1;
        } else if (tty && !is_stdin)
            cat_big_note(arg, &rng);   // the bash output cap keeps head+tail: say what the middle was
    }
    if (!is_stdin) sh_close(fd);
    return rc;
}

// `tfa-cat -w todoforai:<path> < data`: stdin replaces (or creates) the resource.
static int cat_put(const char *ref) {
    if (strncmp(ref, "todoforai:", 10) != 0) { fprintf(stderr, "tfa-cat: -w %s: only todoforai: refs (local files: write them with the shell)\n", ref); return 1; }
    const char *blk = getenv("TODOFORAI_BLOCK_ID");
    if (!blk || !*blk) { fprintf(stderr, "tfa-cat: -w %s: refs need an agent shell (TODOFORAI_BLOCK_ID unset)\n", ref); return 1; }
    char err[512];
    const char *e = cat_upload(0, NULL, 0, NULL, NULL, ref, err, sizeof err);
    if (e) { fprintf(stderr, "tfa-cat: -w %s: %s\n", ref, e); return 1; }
    return 0;
}

int cmd_cat(int argc, char **argv) {
    if (argc >= 2 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version"))) {
        printf("tfa-cat %s\n", BRIDGE_VERSION); return 0;
    }
    if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        printf("Usage: tfa-cat [FILE|REF][:FROM[:TO]]...   (no FILE or - = stdin)\n"
               "cat, but images/PDFs printed to an agent's terminal are attached to the bash call,\n"
               "so the model sees them. Redirected/piped output is raw bytes, exactly like cat.\n"
               "  FILE:FROM:TO            lines FROM..TO only (FILE:FROM = to the end)\n"
               "  todoforai:<path>        a TODOforAI file, e.g. todoforai:todos/<todoId>/<name>\n"
               "                          (a folder prints its listing)\n"
               "tfa-cat -w todoforai:<path> < data   stdin replaces (or creates) that file\n");
        return 0;
    }
    stdio_binary();
    if (argc >= 2 && !strcmp(argv[1], "-w")) {
        if (argc != 3) { fprintf(stderr, "usage: tfa-cat -w todoforai:<path> < data\n"); return 2; }
        return cat_put(argv[2]);
    }
    const char *blk = getenv("TODOFORAI_BLOCK_ID");
    int attach = blk && *blk, tty = stdout_is_tty(), seq = 0, rc = 0;
    if (argc < 2) return cat_one("-", attach, tty, &seq);
    for (int i = 1; i < argc; i++) {
        int r = cat_one(argv[i], attach, tty, &seq);
        if (r == 141) return 141;
        if (r) rc = 1;
    }
    return rc;
}

// ── `tfa-skill list [word...]`: every skill the agent could list, with its description ──
// This machine's (the agent's walk order: the cwd and its parents, then $HOME; first
// name wins), then the backend's (`skills:` ref: yours in the project, the project's,
// the built-in). The system prompt may carry names only (AgentSettings.toolDetail).

typedef struct { char *name, *desc; } skill_ent_t;
typedef struct { skill_ent_t *v; size_t n, cap; } skill_list_t;

static int skill_list_has(const skill_list_t *l, const char *name) {
    for (size_t i = 0; i < l->n; i++) if (!strcmp(l->v[i].name, name)) return 1;
    return 0;
}

static void skill_list_add(skill_list_t *l, const char *name, const char *desc) {
    if (!*name || skill_list_has(l, name)) return;
    if (l->n == l->cap) {
        size_t c = l->cap ? l->cap * 2 : 32;
        skill_ent_t *v = realloc(l->v, c * sizeof *v);
        if (!v) return;
        l->v = v; l->cap = c;
    }
    char *n = strdup(name), *d = strdup(desc ? desc : "");
    if (!n || !d) { free(n); free(d); return; }
    l->v[l->n++] = (skill_ent_t){ n, d };
}

static int sk_listed(sk_walk_t *w, const char *kind, const char *plugin, const char *path, const char *head, size_t hn) {
    (void)plugin; (void)hn;
    char name[1024], desc[4096];
    if (sk_listable(kind, path, head, name, sizeof name, desc, sizeof desc)) skill_list_add(w->ctx, name, desc);
    return 0;
}

typedef struct { char *pat; int allow; } skill_rule_t;
typedef struct { skill_rule_t *v; size_t n, cap; } skill_rules_t;

static void skill_rules_add(skill_rules_t *rs, int allow, const char *pat) {
    if (!*pat) return;
    if (rs->n == rs->cap) {
        size_t nc = rs->cap ? rs->cap * 2 : 16;
        skill_rule_t *nv = realloc(rs->v, nc * sizeof *nv);
        if (!nv) return;
        rs->v = nv; rs->cap = nc;
    }
    char *p = strdup(pat);
    if (!p) return;
    rs->v[rs->n++] = (skill_rule_t){ p, allow };
}

// Mirrors shared-fbe `skillFilterLines` / Julia `skill_on`: exact beats trailing `*`,
// longer prefix wins, `-` beats `+` on a tie, unmatched = allowed.
static int skill_rule_allows(const skill_rules_t *rs, const char *name) {
    int best = -1, allowed = 1;
    for (size_t i = 0; i < rs->n; i++) {
        const char *pat = rs->v[i].pat;
        size_t len = strlen(pat);
        int wild = len > 0 && pat[len - 1] == '*';
        int matched = wild ? !strncmp(name, pat, len - 1) : !strcmp(name, pat);
        if (!matched) continue;
        int spec = wild ? (int)(len - 1) : INT_MAX;
        if (spec > best || (spec == best && !rs->v[i].allow)) {
            best = spec;
            allowed = rs->v[i].allow;
        }
    }
    return allowed;
}

// The backend's skills (`skills:` ref → optional `\t+pat`/`\t-pat` filter lines, then
// `name: description` lines) into `l` and `rs`, after the local ones.
static int skill_list_remote(skill_list_t *l, skill_rules_t *rs, char *err, size_t ecap) {
    char mime[128];
    ws_fd_t s = shell_client_open("fetch", NULL, NULL, -1, "skills:", 0, err, ecap);
    if (s == WS_INVALID_FD) return -1;
    long size = 0;
    int r = shell_client_fetch_head(s, &size, mime, sizeof mime, err, ecap);
    if (r <= 0 || size < 0 || size > 4 * 1024 * 1024) { shell_client_close(s); if (r > 0) snprintf(err, ecap, "listing too big"); return -1; }
    char *buf = malloc((size_t)size + 1);
    long got = 0;
    while (buf && got < size) {
        long n = shell_client_recv(s, buf + got, (size_t)(size - got));
        if (n <= 0) break;
        got += n;
    }
    shell_client_close(s);
    if (!buf || got != size) { free(buf); snprintf(err, ecap, "transfer broke"); return -1; }
    buf[got] = '\0';
    for (char *line = buf, *nl; *line; line = nl ? nl + 1 : line + strlen(line)) {
        nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (line[0] == '\t' && (line[1] == '+' || line[1] == '-')) {
            skill_rules_add(rs, line[1] == '+', line + 2);
            if (!nl) break;
            continue;
        }
        char *c = strstr(line, ": ");
        if (c) { *c = '\0'; skill_list_add(l, line, c + 2); }
        else skill_list_add(l, line, "");
        if (!nl) break;
    }
    free(buf);
    return 0;
}

static int ent_cmp(const void *a, const void *b) { return strcmp(((const skill_ent_t *)a)->name, ((const skill_ent_t *)b)->name); }

// Case-insensitive substring (ASCII).
static int ci_has(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (; *hay; hay++) if (!strncasecmp(hay, needle, n)) return 1;
    return !n;
}

static int skill_list_cmd(int argc, char **argv) {
    skill_list_t l = { 0 };
    sk_walk_t w = { sk_listed, "", &l, 0 };
    sk_local(&w);
    size_t local = l.n;
    skill_rules_t rs = { 0 };
    const char *blk = getenv("TODOFORAI_BLOCK_ID");
    char err[512] = "";
    int remote = blk && *blk ? skill_list_remote(&l, &rs, err, sizeof err) : -1;
    qsort(l.v, local, sizeof *l.v, ent_cmp);
    qsort(l.v + local, l.n - local, sizeof *l.v, ent_cmp);
    size_t shown = 0;
    for (size_t i = 0; i < l.n; i++) {
        skill_ent_t *e = &l.v[i];
        int on = skill_rule_allows(&rs, e->name);
        int hit = on && argc <= 2;
        for (int a = 2; a < argc && on && !hit; a++) hit = ci_has(e->name, argv[a]) || ci_has(e->desc, argv[a]);
        if (hit) {
            printf("- %s%s%s", e->name, e->desc[0] ? ": " : "", e->desc);
            putchar('\n');
            shown++;
        }
        free(e->name); free(e->desc);
    }
    for (size_t i = 0; i < rs.n; i++) free(rs.v[i].pat);
    free(rs.v);
    free(l.v);
    if (!shown) fprintf(stderr, "tfa-skill: no skills%s\n", argc > 2 ? " match" : "");
    if (remote < 0 && blk && *blk) fprintf(stderr, "tfa-skill: project and built-in skills not listed: %s\n", err[0] ? err : "unavailable");
    if (fflush(stdout) == EOF) return 141;
    return shown ? 0 : 1;
}

// ── `tfa-skill --scan [root...]`: the skill walk's records for the agent and the apps ──
// Same output as the shell walk it replaces (shared-fer buildSkillWalkScript): one
// base64 blob of `RS scope US kind US plugin US path US head` records, scope `repo`
// for each root, then `user` for $HOME. Out of memory: exit 1, nothing printed, so
// the caller's shell walk runs instead.
static int sk_scanned(sk_walk_t *w, const char *kind, const char *plugin, const char *path, const char *head, size_t hn) {
    sk_buf_t *b = w->ctx;
    sk_put(b, "\036", 1); sk_put(b, w->scope, strlen(w->scope));
    sk_put(b, "\037", 1); sk_put(b, kind, strlen(kind));
    sk_put(b, "\037", 1); sk_put(b, plugin, strlen(plugin));
    sk_put(b, "\037", 1); sk_put(b, path, strlen(path));
    sk_put(b, "\037", 1); sk_put(b, head, hn);
    return 0;
}

static int skill_scan_cmd(int argc, char **argv) {
    sk_buf_t b = { 0 };
    sk_walk_t w = { sk_scanned, "repo", &b, 0 };
    for (int i = 2; i < argc; i++) sk_root(&w, argv[i], 1);
    char home[4096];
    sk_home(home, sizeof home);
    w.scope = "user";
    sk_root(&w, home, 0);   // "$HOME/.agents/…", as the shell walk spells it (even unset)
    size_t cap = 4 * ((b.n + 2) / 3) + 1;
    char *enc = w.fail || b.fail ? NULL : malloc(cap);
    if (!enc) { free(b.v); fprintf(stderr, "tfa-skill: --scan: out of memory\n"); return 1; }
    size_t e = b.n ? b64_encode((const uint8_t *)b.v, b.n, enc, cap) : 0;
    int bad = fwrite(enc, 1, e, stdout) != e;
    free(enc); free(b.v);
    return bad || fflush(stdout) == EOF ? 141 : 0;
}

// `tfa-skill <name>[/<file>][:FROM[:TO]]`: a listed skill's SKILL.md (or another
// file of it), wherever the agent found it: this machine's (skill_path, the agent's
// walk), else — one fetch — yours in the project, the project's, the built-in
// (backend fetchShellResource). Its own command so the Skills permission governs
// it (agent CLI_FOR_NATIVE); `tfa-cat skill:…` still resolves for older prompts.
int cmd_skill(int argc, char **argv) {
    if (argc >= 2 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version"))) {
        printf("tfa-skill %s\n", BRIDGE_VERSION); return 0;
    }
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        printf("Usage: tfa-skill <name>[/<file>][:FROM[:TO]]...\n"
               "       tfa-skill list [word...]\n"
               "Print a skill: its SKILL.md, or <file> inside its folder.\n"
               "list: every skill with its description; words (any, case-insensitive) filter by name/description.\n"
               "This machine's first (.agents/ and .claude/ skills and plugins of home, then of\n"
               "the cwd and its parents), else yours in the project, the project's, a built-in.\n");
        return argc < 2 ? 2 : 0;
    }
    stdio_binary();
    if (!strcmp(argv[1], "list")) return skill_list_cmd(argc, argv);
    if (!strcmp(argv[1], "--scan")) return skill_scan_cmd(argc, argv);   // for the agent and the apps
    cat_prog = "tfa-skill";
    const char *blk = getenv("TODOFORAI_BLOCK_ID");
    int attach = blk && *blk, tty = stdout_is_tty(), seq = 0, rc = 0;
    for (int i = 1; i < argc; i++) {
        char ref[4096];
        if (snprintf(ref, sizeof ref, "skill:%s", argv[i]) >= (int)sizeof ref) { fprintf(stderr, "tfa-skill: %s: name too long\n", argv[i]); rc = 1; continue; }
        int r = cat_one(ref, attach, tty, &seq);
        if (r == 141) return 141;
        if (r) rc = 1;
        // Where it lives, for its scripts/ and references/ (the listing has no paths).
        else if (tty && cat_skill_file[0]) fprintf(stderr, "\ntfa-skill: %s is %s\n", argv[i], cat_skill_file);
    }
    return rc;
}

// ── `tfa-search`, `tfa-question`, `tfa-show` — commands that run in the backend ──
// Each is a REST call or two, so nothing of them lives here: argv goes up the
// relay (kind `cli`), the backend runs the command (packages/shared-fbe
// shellCli.ts — the code the npm packages of the same names run) and answers
// exit code + stdout + stderr. A command that reads stdin or a file answers
// `need` first and is asked again with those bytes, so stdin is only consumed
// when the command wants it. New flags, help and output need no bridge release.
// POSIX: argv[0] dispatch via ~/.todoforai/tools/bin symlinks; Windows: shell
// functions → `<bridge> __cli <name>`.

const char *const BRIDGE_CLI_NAMES[] = { "tfa-search", "tfa-question", "tfa-show", "tfa-settings", "tfa-memory", "tfa-files", "tfa-surface",
    "tfa-imagegen", "tfa-videogen", "tfa-music", "tfa-stt", "tfa-tts", "tfa-speech", "tfa-treg", "tfa-device",
    "tfa-summary", "tfa-explore", "tfa-review", "tfa-handoff", "tfa-webfetch", NULL };

int bridge_cli_builtin(const char *name) {
    for (int i = 0; BRIDGE_CLI_NAMES[i]; i++) if (strcmp(name, BRIDGE_CLI_NAMES[i]) == 0) return 1;
    return 0;
}

#define CLI_MAX_INPUTS 8   // = the backend's (tfa-imagegen edit: up to 7 references + stdin)
#define CLI_MAX_HEAD   (48 * 1024)   // request line (argv, cwd); the backend allows 64 KB

typedef struct { const char *kind; char path[4096]; char *data; size_t size; int flag; } cli_input_t;

static int stdin_is_tty(void) {
#ifdef _WIN32
    DWORD mode;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
#else
    return isatty(0);
#endif
}

// Whole fd → malloc'd buffer (≤ CAT_MAX_BYTES). NULL + err on failure.
static char *cli_slurp(int fd, size_t *len, char *err, size_t errcap) {
    size_t cap = 64 * 1024, n = 0;
    char *buf = malloc(cap);
    while (buf) {
        if (n == cap) {
            cap *= 2;
            char *b = realloc(buf, cap);
            if (!b) { free(buf); buf = NULL; break; }
            buf = b;
        }
        sh_ssize r = sh_read(fd, buf + n, cap - n);
        if (r < 0) { if (errno == EINTR) continue; free(buf); snprintf(err, errcap, "read error"); return NULL; }
        if (r == 0) { *len = n; return buf; }
        n += (size_t)r;
        if (n > (size_t)CAT_MAX_BYTES) { free(buf); snprintf(err, errcap, "over %ld bytes", CAT_MAX_BYTES); return NULL; }
    }
    snprintf(err, errcap, "out of memory");
    return NULL;
}

// An explicit empty pipe means an empty selection, not the whole working tree.
static int review_default_input(void) {
#ifdef _WIN32
    return GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR;
#else
    struct stat st;
    return fstat(0, &st) == 0 && S_ISCHR(st.st_mode);
#endif
}

// The reviewer runs remotely; capture the current checkout locally. No user input
// goes into this fixed command. A supplied patch takes precedence over git.
static int review_diff(cli_input_t *in, char *err, size_t errcap) {
#ifdef _WIN32
    FILE *f = _popen("git diff --no-ext-diff --no-textconv HEAD --", "rb");
#else
    FILE *f = popen("git diff --no-ext-diff --no-textconv HEAD --", "r");
#endif
    if (!f) { snprintf(err, errcap, "cannot start git diff"); return -1; }
    free(in->data);
    in->flag = 0;
#ifdef _WIN32
    in->data = cli_slurp(_fileno(f), &in->size, err, errcap);
    int status = _pclose(f);
#else
    in->data = cli_slurp(fileno(f), &in->size, err, errcap);
    int status = pclose(f);
#endif
    if (!in->data) return -1;
    if (!status) return 0;
    free(in->data); in->data = NULL;
    snprintf(err, errcap, "git diff HEAD failed; run in a repository or pipe a diff");
    return -1;
}

// The input the backend asked for. 0, or -1 with err.
static int cli_read_input(cli_input_t *in, const char *need, const char *path, char *err, size_t errcap) {
    memset(in, 0, sizeof *in);
    if (strcmp(need, "stdin") == 0) {
        in->kind = "stdin";
        if (stdin_is_tty()) { in->flag = 1; return 0; }
        return (in->data = cli_slurp(0, &in->size, err, errcap)) ? 0 : -1;
    }
    if (strcmp(need, "file") != 0 || !*path) { snprintf(err, errcap, "the server asked for an input this bridge does not know (%s): update the bridge", need); return -1; }
    in->kind = "file";
    snprintf(in->path, sizeof in->path, "%s", path);
    int fd = file_exists(path) ? sh_open(path) : -1;
    if (fd < 0) { in->flag = 1; return 0; }
    in->data = cli_slurp(fd, &in->size, err, errcap);
    sh_close(fd);
    if (!in->data) { char why[128]; snprintf(why, sizeof why, "%.127s", err); snprintf(err, errcap, "%.300s: %s", path, why); return -1; }
    return 0;
}

// {"argv":[…],"cwd":…,"projectId":…,"frontendId":…,"agentSettingsId":…,"stdoutTty":…,"inputs":[…]}\n → line. -1: too long.
static int cli_request_line(char *line, size_t cap, size_t *u, int argc, char **argv, const cli_input_t *in, int nin) {
    int bad = json_emit_raw(line, cap, u, "{\"argv\":[", 9) < 0;
    for (int i = 0; i < argc && !bad; i++)
        bad = (i && json_emit_raw(line, cap, u, ",", 1) < 0) || json_emit_str(line, cap, u, argv[i], -1) < 0;
    if (!bad) bad = json_emit_raw(line, cap, u, "]", 1) < 0;
    char cwd[4096];
#ifdef _WIN32
    const char *wd = _getcwd(cwd, sizeof cwd);
#else
    const char *wd = getcwd(cwd, sizeof cwd);
#endif
    const char *proj = getenv("TODOFORAI_PROJECT_ID");
    if (!bad && wd) bad = json_emit_raw(line, cap, u, ",\"cwd\":", 7) < 0 || json_emit_str(line, cap, u, wd, -1) < 0;
    const char *fe = getenv("TODOFORAI_FRONTEND_ID");   // tfa-surface's target tab
    if (!bad && proj && *proj) bad = json_emit_raw(line, cap, u, ",\"projectId\":", 13) < 0 || json_emit_str(line, cap, u, proj, -1) < 0;
    if (!bad && fe && *fe) bad = json_emit_raw(line, cap, u, ",\"frontendId\":", 14) < 0 || json_emit_str(line, cap, u, fe, -1) < 0;
    const char *ag = getenv("TODOFORAI_AGENT_SETTINGS_ID");   // this turn's agent: a sub-agent patches its settings
    if (!bad && ag && *ag) bad = json_emit_raw(line, cap, u, ",\"agentSettingsId\":", 19) < 0 || json_emit_str(line, cap, u, ag, -1) < 0;
    const char *mid = getenv("TODOFORAI_MODEL_ID");   // this turn's running model: tfa-review picks another vendor
    if (!bad && mid && *mid) bad = json_emit_raw(line, cap, u, ",\"modelId\":", 11) < 0 || json_emit_str(line, cap, u, mid, -1) < 0;
    if (!bad) bad = stdout_is_tty() ? json_emit_raw(line, cap, u, ",\"stdoutTty\":true", 17) < 0 : json_emit_raw(line, cap, u, ",\"stdoutTty\":false", 18) < 0;
    if (!bad) bad = json_emit_raw(line, cap, u, ",\"inputs\":[", 11) < 0;
    for (int i = 0; i < nin && !bad; i++) {
        char k[96];
        int file = in[i].kind[0] == 'f';
        int kn = snprintf(k, sizeof k, "%s{\"kind\":\"%s\",\"size\":%zu%s", i ? "," : "", in[i].kind, in[i].size,
                          in[i].flag ? (file ? ",\"missing\":true" : ",\"tty\":true") : "");
        bad = json_emit_raw(line, cap, u, k, (size_t)kn) < 0
           || (file && (json_emit_raw(line, cap, u, ",\"path\":", 8) < 0 || json_emit_str(line, cap, u, in[i].path, -1) < 0))
           || json_emit_raw(line, cap, u, "}", 1) < 0;
    }
    return bad || json_emit_raw(line, cap, u, "]}\n", 3) < 0 ? -1 : 0;
}

// `path` ← bytes (created / truncated). 0, or -1 with err.
static int cli_write_file(const char *path, const char *p, size_t n, char *err, size_t errcap) {
#ifdef _WIN32
    int fd = _open(path, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
#endif
    int ok = fd >= 0 && write_all(fd, p, n) == 0, e = errno;
    if (fd >= 0 && sh_close(fd) != 0 && ok) { ok = 0; e = errno; }
    if (!ok) snprintf(err, errcap, "%.300s: %s", path, strerror(e));
    return ok ? 0 : -1;
}

// One round: request up, the whole reply down (malloc'd, *rn bytes). NULL + err on failure.
static char *cli_round(const char *name, const char *line, size_t ln, const cli_input_t *in, int nin, size_t *rn, char *err, size_t errcap) {
    size_t total = 0;
    for (int i = 0; i < nin; i++) total += in[i].size;
    if (total > (size_t)CAT_MAX_BYTES) { snprintf(err, errcap, "inputs over %ld bytes", CAT_MAX_BYTES); return NULL; }
    total += ln;   // the backend allows the request line on top
    ws_fd_t s = shell_client_open("cli", name, NULL, (long)total, NULL, 0, err, errcap);
    if (s == WS_INVALID_FD) return NULL;
    int sent = shell_client_send(s, line, ln) == 0;
    for (int i = 0; i < nin && sent; i++) sent = !in[i].size || shell_client_send(s, in[i].data, in[i].size) == 0;
    // A send that failed may be a refusal: its reason is on the socket.
    long size = 0; char mime[128];
    int h = shell_client_fetch_head(s, &size, mime, sizeof mime, err, errcap);
    if (h == 0) snprintf(err, errcap, "no answer from the server");
    char *buf = h == 1 ? malloc((size_t)size + 1) : NULL;
    if (h == 1 && !buf) snprintf(err, errcap, "out of memory");
    for (long got = 0; buf && got < size; ) {
        long r = shell_client_recv(s, buf + got, (size_t)(size - got));
        if (r <= 0) { free(buf); buf = NULL; snprintf(err, errcap, "the answer broke off"); break; }
        got += r;
    }
    shell_client_close(s);
    if (buf) { buf[size] = '\0'; *rn = (size_t)size; }
    return buf;
}

static int cli_run(const char *name, int argc, char **argv, const char *input, size_t size) {
    stdio_binary();
    static cli_input_t in[CLI_MAX_INPUTS];
    char err[512] = "";
    char *line = malloc(CLI_MAX_HEAD), *res = NULL;
    int nin = 0, rc = 1;
    if (!line) { fprintf(stderr, "%s: out of memory\n", name); return 1; }
    for (;;) {
        size_t ln = 0, rn = 0;
        if (cli_request_line(line, CLI_MAX_HEAD, &ln, argc - 1, argv + 1, in, nin) < 0) { snprintf(err, sizeof err, "arguments too long (pass long text on stdin or as a file)"); break; }
        free(res);
        if (!(res = cli_round(name, line, ln, in, nin, &rn, err, sizeof err))) break;
        const char *nl = memchr(res, '\n', rn);
        size_t hl = nl ? (size_t)(nl - res) : rn;
        char need[32], path[4096]; size_t l = 0;
        if (json_get_str_decoded(res, hl, "need", need, sizeof need, &l)) {
            if (!json_get_str_decoded(res, hl, "path", path, sizeof path, &l)) path[0] = '\0';
            if (nin == CLI_MAX_INPUTS) { snprintf(err, sizeof err, "the command reads too many inputs"); break; }
            if (input) {
                if (strcmp(need, "stdin") || nin) { snprintf(err, sizeof err, "unexpected input request"); break; }
                in[nin] = (cli_input_t){ .kind = "stdin", .data = (char *)input, .size = size };
            } else if (cli_read_input(&in[nin], need, path, err, sizeof err) < 0) break;
            if (!strcmp(name, "tfa-review") && !strcmp(need, "stdin") && !in[nin].size && review_default_input()
                && review_diff(&in[nin], err, sizeof err) < 0) break;
            nin++;
            continue;
        }
        long code = 1, out = -1, er = -1, fs = 0;
        int has_file = json_get_str_decoded(res, hl, "file", path, sizeof path, &l) && *path;
        if (!nl || !json_get_long(res, hl, "code", &code) || !json_get_long(res, hl, "out", &out) || !json_get_long(res, hl, "err", &er)
            || (has_file && !json_get_long(res, hl, "fileSize", &fs))
            || out < 0 || er < 0 || fs < 0 || (size_t)out > rn - hl - 1 || (size_t)er > rn - hl - 1 - (size_t)out
            || (size_t)fs != rn - hl - 1 - (size_t)out - (size_t)er) { snprintf(err, sizeof err, "unexpected answer from the server"); break; }
        // The command's one output file (its -o, else a fixed default like out.png), as typed
        // from here: before its "Saved …" goes out. The path is the server's word, the same
        // trust as the output it prints. A file we can't write fails the run, nothing else printed.
        if (has_file && cli_write_file(path, nl + 1 + out + er, (size_t)fs, err, sizeof err) < 0) break;
        // stdout gone (`| head`): 141 like any filter, the command itself already ran.
        rc = write_all(1, nl + 1, (size_t)out) < 0 ? 141 : (int)(code & 0xff);
        (void)write_all(2, nl + 1 + out, (size_t)er);
        err[0] = '\0';
        break;
    }
    if (err[0]) fprintf(stderr, "%s: %s\n", name, err);
    if (!input) for (int i = 0; i < nin; i++) free(in[i].data);
    free(res); free(line);
    return rc;
}

int cmd_cli(const char *name, int argc, char **argv) {
    if (argc >= 2 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version"))) { printf("%s %s\n", name, BRIDGE_VERSION); return 0; }
    if (!strcmp(name, "tfa-webfetch")) { stdio_binary(); return cmd_webfetch(argc, argv, cli_run); }
    return cli_run(name, argc, argv, NULL, 0);
}

#ifndef _WIN32
void bridge_link_tool(const char *self, const char *name, int replace_foreign) {
    char real[1024];
    if (!self || !*self) return;
    if (strcmp(self, "/proc/self/exe") == 0) {
        ssize_t rn = readlink(self, real, sizeof real - 1);
        if (rn <= 0) return;
        real[rn] = '\0';
        size_t dl = strlen(" (deleted)");
        if ((size_t)rn > dl && strcmp(real + rn - dl, " (deleted)") == 0) real[rn - dl] = '\0';
        self = real;
    }
    char abs[4096];
    if (self[0] != '/') {   // macOS/BSD argv0 fallback may be relative
        if (!realpath(self, abs)) return;
        self = abs;
    }
    const char *home = getenv("HOME");
    if (!home || !*home) return;
    char dir[1024], link[1100], tmp[1120], cur[1024];
    if (snprintf(dir, sizeof dir, "%s/.todoforai/tools/bin", home) >= (int)sizeof dir) return;
    snprintf(link, sizeof link, "%s/%s", dir, name);
    ssize_t cn = readlink(link, cur, sizeof cur - 1);
    if (cn > 0) { cur[cn] = '\0'; if (strcmp(cur, self) == 0) return; }
    // Replace only our own link (a bridge binary) or nothing — never a real
    // tool someone put here (e.g. platform-tools' adb).
    if (!replace_foreign && (cn > 0 ? !strstr(cur, "bridge") : access(link, F_OK) == 0)) return;
    char p1[1024]; snprintf(p1, sizeof p1, "%s/.todoforai", home); mkdir(p1, 0755);
    snprintf(p1, sizeof p1, "%s/.todoforai/tools", home); mkdir(p1, 0755);
    mkdir(dir, 0755);
    // Replace atomically (an old link or a stale npm shim alike).
    snprintf(tmp, sizeof tmp, "%s/.%s.%ld", dir, name, (long)getpid());
    unlink(tmp);
    if (symlink(self, tmp) == 0 && rename(tmp, link) != 0) unlink(tmp);
}
#endif

// Shell helpers the bridge ships into every RUN: `__live` (tail shim) and
// `tfa-cat`. Both talk to the daemon's loopback shell relay (shell_relay.h),
// which forwards on the Noise channel — no curl, no per-call TLS, same code on
// Linux, macOS and Windows.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "subcmd.h"
#include "shell_relay.h"

#include <errno.h>
#include <stdio.h>
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

// skill:<name>[/<file>] → <root>/{.agents,.claude}/skills/<name>/<file|SKILL.md>,
// roots = cwd and its parents, then $HOME — the agent's discovery order
// (repo first). 0 found, -1 not found / bad name.
static int skill_path(const char *spec, char *out, size_t cap) {
    if (!*spec || strstr(spec, "..") || spec[0] == '/' || spec[0] == '\\') return -1;
    char rel[512];
    const char *slash = strchr(spec, '/');
    if (snprintf(rel, sizeof rel, slash ? "%s" : "%s/SKILL.md", spec) >= (int)sizeof rel) return -1;
    static const char *const dirs[] = { ".agents", ".claude" };
    char dir[4096];
    const char *home = getenv("HOME");
#ifdef _WIN32
    if (!_getcwd(dir, sizeof dir)) dir[0] = '\0';
    if (!home || !*home) home = getenv("USERPROFILE");
#else
    if (!getcwd(dir, sizeof dir)) dir[0] = '\0';
#endif
    while (dir[0]) {   // cwd, its parents, then the root itself ("" + "/…")
        for (int i = 0; i < 2; i++)
            if (snprintf(out, cap, "%s/%s/skills/%s", dir, dirs[i], rel) < (int)cap && file_exists(out)) return 0;
        char *cut = NULL;
        for (char *c = dir; *c; c++) if (*c == '/' || *c == '\\') cut = c;
        if (!cut) break;
        if (cut[1] == '\0') break;   // was "/" or "C:\" — done
        cut[cut == dir || (cut == dir + 2 && dir[1] == ':') ? 1 : 0] = '\0';   // keep the root's slash
    }
    for (int i = 0; i < 2 && home && *home; i++)
        if (snprintf(out, cap, "%s/%s/skills/%s", home, dirs[i], rel) < (int)cap && file_exists(out)) return 0;
    return -1;
}

// A backend resource, as the agent's `read` sees it. On the agent's terminal
// an image/PDF is attached by the backend directly (no bytes come here);
// anything else — and everything when piped — is printed like a file.
static int cat_ref(const char *ref, int attach, int tty, cat_range_t *rng) {
    if (!attach) { fprintf(stderr, "tfa-cat: %s: refs need an agent shell (TODOFORAI_BLOCK_ID unset)\n", ref); return 1; }
    char err[512], mime[128];
    ws_fd_t s = shell_client_open("fetch", NULL, NULL, -1, ref, tty, err, sizeof err);
    if (s == WS_INVALID_FD) { fprintf(stderr, "tfa-cat: %s: %s\n", ref, err); return 1; }
    long size = 0;
    int r = shell_client_fetch_head(s, &size, mime, sizeof mime, err, sizeof err);
    if (r <= 0) {
        shell_client_close(s);
        if (r < 0) { fprintf(stderr, "tfa-cat: %s: %s\n", ref, err); return 1; }
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
            fprintf(stderr, "tfa-cat: %s: binary (%s, %ld bytes), not printed. Save it: tfa-cat '%s' > '%s'\n",
                    ref, mime, size, ref, *b ? b : "file");
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
        if (skill_path(arg + 6, skill, sizeof skill) != 0) {
            fprintf(stderr, "tfa-cat: %s: no such skill on this machine (looked in .agents/skills and .claude/skills of the cwd, its parents and home)\n", arg);
            return 1;
        }
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
            fprintf(stderr, "tfa-cat: %s: binary, not printed (use a tool that reads it, or pipe/redirect for the raw bytes)\n", arg);
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
               "  skill:<name>[/<file>]   a skill on this machine (SKILL.md by default)\n"
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

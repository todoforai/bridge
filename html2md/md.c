/* md.c — HTML events → Markdown for LLM reading (not round-trip fidelity).
 * Lazy output: newlines, list markers and inline markers are only written before the next visible
 * text, so empty blocks/links/emphasis vanish and whitespace never piles up.
 * MD_CLEAN adds boilerplate cuts: nav/footer, header/aside outside main/article, role=navigation|banner|contentinfo|search|dialog,
 * hidden/aria-hidden, display:none, form controls, and (via md_gate) <main>/role=main only. */
#include "md.h"
#include "alloc.h"
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

typedef struct { char *p; size_t n, cap, limit; int cut; } buf_t;
static void bput(buf_t *b, const char *s, size_t n) {
    if (b->cut) return;
    if (b->limit && n > b->limit - b->n) {
        n = b->limit - b->n;
        while (n && ((unsigned char)s[n] & 0xc0) == 0x80) n--;
        b->cut = 1;
    }
    if (b->cut && n == 0) return;
    if (b->n + n + 1 > b->cap) { b->cap = (b->n + n + 1) * 2; b->p = md_alloc(realloc(b->p, b->cap)); }
    memcpy(b->p + b->n, s, n); b->n += n; b->p[b->n] = 0;
}
static void bstr(buf_t *b, const char *s) { bput(b, s, strlen(s)); }

enum { K_OTHER, K_SKIP, K_CLEANSKIP, K_BLOCK, K_H, K_P, K_BR, K_HR, K_PRE, K_CODE, K_STRONG, K_EM, K_DEL,
       K_A, K_IMG, K_UL, K_OL, K_LI, K_BQ, K_TABLE, K_TR, K_TD, K_DT, K_DD, K_HEADER, K_MAIN, K_ARTICLE, K_ASIDE };
static const struct { const char *t; int k; } TAGS[] = {
    {"script",K_SKIP},{"style",K_SKIP},{"noscript",K_SKIP},{"template",K_SKIP},{"svg",K_SKIP},{"head",K_SKIP},
    {"iframe",K_SKIP},{"canvas",K_SKIP},{"object",K_SKIP},{"math",K_SKIP},{"title",K_SKIP},{"dialog",K_SKIP},
    {"nav",K_CLEANSKIP},{"footer",K_CLEANSKIP},{"aside",K_ASIDE},{"button",K_CLEANSKIP},{"select",K_CLEANSKIP},
    {"textarea",K_CLEANSKIP},{"input",K_CLEANSKIP},{"label",K_OTHER},
    {"div",K_BLOCK},{"section",K_BLOCK},{"form",K_BLOCK},{"fieldset",K_BLOCK},{"figure",K_BLOCK},
    {"figcaption",K_BLOCK},{"details",K_BLOCK},{"summary",K_BLOCK},{"address",K_BLOCK},{"center",K_BLOCK},
    {"body",K_BLOCK},{"html",K_BLOCK},{"dl",K_BLOCK},{"caption",K_BLOCK},{"legend",K_BLOCK},
    {"header",K_HEADER},{"main",K_MAIN},{"article",K_ARTICLE},
    {"h1",K_H},{"h2",K_H},{"h3",K_H},{"h4",K_H},{"h5",K_H},{"h6",K_H},{"p",K_P},{"br",K_BR},{"hr",K_HR},
    {"pre",K_PRE},{"code",K_CODE},{"kbd",K_CODE},{"samp",K_CODE},{"tt",K_CODE},
    {"strong",K_STRONG},{"b",K_STRONG},{"em",K_EM},{"i",K_EM},{"del",K_DEL},{"s",K_DEL},{"strike",K_DEL},
    {"a",K_A},{"img",K_IMG},{"ul",K_UL},{"menu",K_UL},{"ol",K_OL},{"li",K_LI},{"blockquote",K_BQ},
    {"table",K_TABLE},{"tr",K_TR},{"td",K_TD},{"th",K_TD},{"dt",K_DT},{"dd",K_DD},
};
static int kind(const char *t, size_t n) {
    for (size_t i = 0; i < sizeof TAGS / sizeof *TAGS; i++)
        if (strlen(TAGS[i].t) == n && !strncasecmp(TAGS[i].t, t, n)) return TAGS[i].k;
    return K_OTHER;
}

typedef struct { int k, aux; size_t out_at, pend_at, pfx_at; char *href; } frame_t;
typedef struct { int ordered, n; } list_t;

struct md {
    buf_t out, pend, pfx;          /* output, lazily written markers, line prefix ("> ", list indent) */
    frame_t *st; int sp_n, st_cap; /* open elements */
    list_t lists[64]; int nlist;
    int flags, skip, pre, code, sp, nl, first_skip, cell, heading, gate, gated_in, saw_gate, in_article;
    int tbl_layout[64], ntbl, row_cells, rows;
    char base[8193];
};

md_t *md_new(const char *base, int flags) {
    md_t *m = md_alloc(calloc(1, sizeof *m));
    m->out.limit = HTML2MD_MAX_BYTES;
    m->flags = flags;
    snprintf(m->base, sizeof m->base, "%s", base ? base : "");
    bstr(&m->out, ""); bstr(&m->pend, ""); bstr(&m->pfx, "");
    return m;
}

/* ---- URL resolution (enough for links: scheme, //host, /path, ?q, rel with ../) ---- */
static char *resolve(const char *base, const char *h, size_t n) {
    while (n && isspace((unsigned char)*h)) h++, n--;
    while (n && isspace((unsigned char)h[n - 1])) n--;
    buf_t r = {0}; bstr(&r, "");
    size_t i = 0; while (i < n && (isalnum((unsigned char)h[i]) || h[i] == '+' || h[i] == '-' || h[i] == '.')) i++;
    const char *sch = strstr(base, "://");
    if (i < n && h[i] == ':' && i > 0) bput(&r, h, n);                               /* absolute */
    else if (!sch) bput(&r, h, n);
    else {
        size_t origin = (size_t)(sch - base) + 3;
        while (base[origin] && base[origin] != '/' && base[origin] != '?' && base[origin] != '#') origin++;
        if (n >= 2 && h[0] == '/' && h[1] == '/') { bput(&r, base, (size_t)(sch - base) + 1); bput(&r, h, n); }
        else if (n && h[0] == '/') { bput(&r, base, origin); bput(&r, h, n); }
        else {
            size_t e = strcspn(base, "?#");
            if (n && h[0] == '?') { bput(&r, base, e); bput(&r, h, n); }
            else {
                size_t dir = e; while (dir > origin && base[dir - 1] != '/') dir--;
                if (dir <= origin) { bput(&r, base, origin); bput(&r, "/", 1); } else bput(&r, base, dir);
                while (n >= 3 && !strncmp(h, "../", 3)) {              /* pop one segment per ../ */
                    h += 3; n -= 3;
                    if (r.n > origin + 1) { r.n--; while (r.n > origin + 1 && r.p[r.n - 1] != '/') r.n--; r.p[r.n] = 0; }
                }
                while (n >= 2 && !strncmp(h, "./", 2)) h += 2, n -= 2;
                bput(&r, h, n);
            }
        }
    }
    buf_t o = {0}; bstr(&o, "");                       /* markdown-safe: no raw spaces or parens */
    for (size_t j = 0; j < r.n; j++)
        if (r.p[j] == ' ') bstr(&o, "%20"); else if (r.p[j] == ')') bstr(&o, "%29"); else if (r.p[j] == '(') bstr(&o, "%28");
        else bput(&o, r.p + j, 1);
    free(r.p);
    return o.p;
}

/* ---- lazy writer ---- */
static int at_line_start(md_t *m) { return m->out.n == 0 || m->out.p[m->out.n - 1] == '\n'; }
static void want_nl(md_t *m, int n) { if (m->nl < n) m->nl = n; }
static void rtrim(md_t *m) { while (m->out.n && m->out.p[m->out.n - 1] == ' ') m->out.n--; m->out.p[m->out.n] = 0; }

static void flush(md_t *m) {
    if (m->nl && m->out.n) {
        if (m->cell || m->heading) { if (!at_line_start(m)) bput(&m->out, " ", 1); }
        else {
            rtrim(m);
            for (int i = 0; i < m->nl; i++) {
                bput(&m->out, "\n", 1);
                if (i < m->nl - 1) continue;                                     /* blank line: no prefix */
                bput(&m->out, m->pfx.p, m->pfx.n > (size_t)m->first_skip ? m->pfx.n - (size_t)m->first_skip : 0);
            }
            m->first_skip = 0;
        }
        m->sp = 0;
    } else if (m->sp && m->out.n && !at_line_start(m)) bput(&m->out, " ", 1);
    m->nl = 0; m->sp = 0;
    if (m->pend.n) { bput(&m->out, m->pend.p, m->pend.n); m->pend.n = 0; m->pend.p[0] = 0; }
}

/* write pending newlines now (block start that must not be flattened by a heading/cell context) */
static void flush_nl(md_t *m) {
    if (!m->nl || !m->out.n || m->cell) return;
    int h = m->heading; m->heading = 0;
    buf_t keep = m->pend; m->pend = (buf_t){0}; bstr(&m->pend, "");
    flush(m); free(m->pend.p); m->pend = keep; m->heading = h;
}

static int visible(md_t *m) { return !m->skip && (!m->gate || m->gated_in); }

void md_text(md_t *m, const char *s, size_t n) {
    if (!visible(m)) return;
    if (m->pre) {
        for (size_t i = 0; i < n && !md_full(m); i++) {
            if (s[i] == '\r') continue;
            if (m->nl || m->pend.n) flush(m);
            bput(&m->out, s + i, 1);
            if (s[i] == '\n') bput(&m->out, m->pfx.p, m->pfx.n);
        }
        return;
    }
    for (size_t i = 0; i < n && !md_full(m); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f') { m->sp = 1; continue; }
        if (c == 0xC2 && i + 1 < n && (unsigned char)s[i + 1] == 0xA0) { m->sp = 1; i++; continue; }  /* nbsp */
        size_t j = i;   /* run of non-space bytes */
        while (j < n && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' && s[j] != '\f' &&   /* not strchr: it matches NUL → endless loop */ !((unsigned char)s[j] == 0xC2 && j + 1 < n && (unsigned char)s[j + 1] == 0xA0)) j++;
        flush(m);
        if (m->cell == 1) { for (size_t k = i; k < j; k++) if (s[k] == '|') bstr(&m->out, "\\|"); else bput(&m->out, s + k, 1); }
        else bput(&m->out, s + i, j - i);
        i = j - 1;
    }
}

static int attr_is(md_attr_fn a, void *c, const char *name, const char *val) {
    size_t l; const char *v = a ? a(c, name, &l) : NULL;
    return v && strlen(val) == l && !strncasecmp(v, val, l);
}
static int attr_has(md_attr_fn a, void *c, const char *name) { size_t l; return a && a(c, name, &l) != NULL; }

static int cleanskip_attr(md_attr_fn a, void *c) {
    static const char *ROLES[] = {"navigation","banner","contentinfo","search","dialog","menu","menubar","alertdialog"};
    for (size_t i = 0; i < sizeof ROLES / sizeof *ROLES; i++) if (attr_is(a, c, "role", ROLES[i])) return 1;
    if (attr_has(a, c, "hidden") || attr_is(a, c, "aria-hidden", "true")) return 1;
    size_t l; const char *st = a ? a(c, "style", &l) : NULL;
    if (st) { char t[256]; size_t k = 0;
        for (size_t i = 0; i < l && k < sizeof t - 1; i++) if (st[i] != ' ') t[k++] = (char)tolower((unsigned char)st[i]);
        t[k] = 0; if (strstr(t, "display:none")) return 1; }   /* not visibility:hidden: SSR pages hide the whole body until hydration */
    return 0;
}

static frame_t *push(md_t *m, int k) {
    if (m->sp_n == m->st_cap) { m->st_cap = m->st_cap ? m->st_cap * 2 : 64; m->st = md_alloc(realloc(m->st, sizeof *m->st * (size_t)m->st_cap)); }
    frame_t *f = &m->st[m->sp_n++];
    memset(f, 0, sizeof *f); f->k = k; f->out_at = m->out.n; f->pend_at = m->pend.n; f->pfx_at = m->pfx.n;
    return f;
}

void md_open(md_t *m, const char *tag, size_t tn, md_attr_fn a, void *c) {
    int k = kind(tag, tn);
    int clean = m->flags & MD_CLEAN;
    if (m->skip) { m->skip++; push(m, K_SKIP); return; }
    if (k == K_SKIP || (clean && (k == K_CLEANSKIP || cleanskip_attr(a, c)))
        || (clean && (k == K_HEADER || k == K_ASIDE) && !m->in_article && !m->gated_in)) {   /* inside main/article: content */ m->skip = 1; push(m, K_SKIP); return; }
    int is_main = k == K_MAIN || attr_is(a, c, "role", "main");
    frame_t *f = push(m, k);
    if (is_main) { m->saw_gate = 1; if (m->gate && !m->gated_in) { m->gated_in = 1; f->aux = 1; } }
    if (k == K_ARTICLE || is_main) { m->in_article++; f->aux |= 2; }
    if (!visible(m)) return;
    switch (k) {
    case K_BLOCK: case K_HEADER: case K_ASIDE: case K_MAIN: case K_ARTICLE: case K_DT: case K_DD: want_nl(m, 1); break;
    case K_P: want_nl(m, 2); break;
    case K_BR: if (m->nl < 2) m->nl++; break;
    case K_HR: want_nl(m, 2); flush(m); bstr(&m->out, "---"); want_nl(m, 2); break;
    case K_H: { want_nl(m, 2); if (!m->heading) flush_nl(m);
        int lv = tag[1] - '0'; for (int i = 0; i < lv; i++) bput(&m->pend, "#", 1); bput(&m->pend, " ", 1); m->heading++; break; }
    case K_STRONG: if (!m->pre && !m->code) bstr(&m->pend, "**"); break;
    case K_EM: if (!m->pre && !m->code) bstr(&m->pend, "_"); break;
    case K_DEL: if (!m->pre && !m->code) bstr(&m->pend, "~~"); break;
    case K_CODE: if (!m->pre) { if (!m->code) bstr(&m->pend, "`"); m->code++; } break;
    case K_PRE: {
        want_nl(m, 2); flush(m);
        size_t l; const char *cl = a ? a(c, "class", &l) : NULL; char lang[32] = "";
        for (size_t i = 0; cl && i + 9 <= l; i++) if (!memcmp(cl + i, "language-", 9) || !memcmp(cl + i, "lang-", 5)) {
            const char *p = cl + i + (cl[i + 4] == '-' ? 5 : 9); size_t q = 0;
            while (q < 31 && p + q < cl + l && (isalnum((unsigned char)p[q]) || p[q] == '-' || p[q] == '+')) q++;
            memcpy(lang, p, q); lang[q] = 0; break; }
        bstr(&m->out, "```"); bstr(&m->out, lang); bput(&m->out, "\n", 1); bput(&m->out, m->pfx.p, m->pfx.n);
        m->pre++; break; }
    case K_A: {
        size_t l; const char *h = a ? a(c, "href", &l) : NULL;
        if (h && l && l <= 8192 && h[0] != '#' && (l < 11 || strncasecmp(h, "javascript:", 11)) && !m->pre) { f->href = resolve(m->base, h, l); bstr(&m->pend, "["); }
        break; }
    case K_IMG: {
        size_t sl, al; const char *src = a ? a(c, "src", &sl) : NULL, *alt = a ? a(c, "alt", &al) : NULL;
        if (!src || sl > 8192 || !alt || !al || (sl >= 5 && !strncmp(src, "data:", 5))) break;
        char *u = resolve(m->base, src, sl);
        flush(m); bstr(&m->out, "!["); for (size_t i = 0; i < al; i++) bput(&m->out, alt[i] == '\n' ? " " : alt + i, 1);
        bstr(&m->out, "]("); bstr(&m->out, u); bstr(&m->out, ")"); free(u);
        break; }
    case K_UL: case K_OL:
        want_nl(m, m->nlist ? 1 : 2);
        if (m->nlist < 64) { size_t l; const char *s = a ? a(c, "start", &l) : NULL;
            m->lists[m->nlist].ordered = k == K_OL; int v = 0; for (size_t i = 0; s && i < l && i < 6 && isdigit((unsigned char)s[i]); i++) v = v * 10 + s[i] - '0';   /* bounded: attrs are not NUL-terminated */
            m->lists[m->nlist].n = v ? v - 1 : 0; }
        m->nlist++; f->aux |= 16; break;
    case K_LI: {
        want_nl(m, 1);
        char mk[16] = "- ";
        if (m->nlist && m->nlist <= 64 && m->lists[m->nlist - 1].ordered) snprintf(mk, sizeof mk, "%d. ", ++m->lists[m->nlist - 1].n);
        if (m->cell) break;
        bstr(&m->pend, mk);
        size_t w = strlen(mk); if (m->pfx.n < 64) for (size_t i = 0; i < w; i++) bput(&m->pfx, " ", 1);   /* cap: depth × lines amplification */
        m->first_skip = (int)w; break; }
    case K_BQ: want_nl(m, 2); if (m->pfx.n < 64) bstr(&m->pfx, "> "); break;
    case K_TABLE: {
        int layout = attr_has(a, c, ":layout") || m->cell;
        want_nl(m, 2);
        if (m->ntbl < 64) m->tbl_layout[m->ntbl] = layout;
        m->ntbl++; f->aux |= layout ? 4 : 0;
        if (!layout) { m->rows = 0; }
        break; }
    case K_TR:
        if (m->ntbl && m->ntbl <= 64 && !m->tbl_layout[m->ntbl - 1] && !m->cell) { want_nl(m, 1); flush(m); bstr(&m->out, "|"); m->row_cells = 0; f->aux |= 8; }
        else want_nl(m, 1);
        break;
    case K_TD:
        if (m->ntbl && m->ntbl <= 64 && !m->tbl_layout[m->ntbl - 1] && !m->cell) { m->cell = 1; m->sp = 1; f->aux |= 8; m->row_cells++; }
        else m->sp = 1;
        break;
    default: break;
    }
    if (k == K_DT) bstr(&m->pend, "**");
    if (k == K_DD) bstr(&m->pend, ": ");
}

void md_close(md_t *m, const char *tag, size_t tn) {
    (void)tag; (void)tn;
    if (!m->sp_n) return;
    frame_t f = m->st[--m->sp_n];
    if (f.k == K_SKIP) { if (m->skip) m->skip--; return; }
    int was_visible = visible(m);
    if (f.aux & 2) m->in_article--;
    if (f.aux & 1) m->gated_in = 0;
    if (!was_visible) { free(f.href); return; }
    int empty = m->out.n == f.out_at && m->pend.n >= f.pend_at;
    switch (f.k) {
    case K_STRONG: case K_EM: case K_DEL: case K_DT:
        if (m->pre || m->code) break;
        if (empty) { m->pend.n = f.pend_at; m->pend.p[m->pend.n] = 0; break; }
        bstr(&m->out, f.k == K_STRONG || f.k == K_DT ? "**" : f.k == K_EM ? "_" : "~~");
        if (f.k == K_DT) want_nl(m, 1);
        break;
    case K_CODE:
        if (m->pre) break;
        if (--m->code) break;
        if (empty) { m->pend.n = f.pend_at; m->pend.p[m->pend.n] = 0; } else bstr(&m->out, "`");
        break;
    case K_A:
        if (!f.href) break;
        if (empty) { m->pend.n = f.pend_at; m->pend.p[m->pend.n] = 0; }
        else { bstr(&m->out, "]("); bstr(&m->out, f.href); bstr(&m->out, ")"); }
        free(f.href); break;
    case K_H: m->heading--; if (empty) { m->pend.n = f.pend_at; m->pend.p[m->pend.n] = 0; } want_nl(m, 2); break;
    case K_P: case K_BQ: want_nl(m, 2); break;
    case K_BLOCK: case K_HEADER: case K_ASIDE: case K_MAIN: case K_ARTICLE: case K_DD: want_nl(m, 1); break;
    case K_PRE:
        m->pre--; rtrim(m);
        if (!at_line_start(m)) bput(&m->out, "\n", 1);
        bput(&m->out, m->pfx.p, f.pfx_at); bstr(&m->out, "```"); want_nl(m, 2); break;
    case K_UL: case K_OL: if (f.aux & 16) m->nlist--;   /* only lists that were counted */ want_nl(m, m->nlist ? 1 : 2); break;
    case K_LI: if (empty) { m->pend.n = f.pend_at; m->pend.p[m->pend.n] = 0; m->first_skip = 0; } want_nl(m, 1); break;
    case K_TD:
        if (f.aux & 8) { m->cell = 0; m->nl = 0; m->sp = 0; m->pend.n = 0; m->pend.p[0] = 0; rtrim(m); bstr(&m->out, " |"); }
        break;
    case K_TR:
        if (f.aux & 8) {
            if (m->row_cells == 0) { m->out.n = f.out_at; m->out.p[m->out.n] = 0; break; }   /* empty row */
            if (m->rows++ == 0) { bput(&m->out, "\n", 1); bput(&m->out, m->pfx.p, m->pfx.n); bstr(&m->out, "|");
                for (int i = 0; i < m->row_cells; i++) bstr(&m->out, " --- |"); }
            want_nl(m, 1);
        } else want_nl(m, 1);
        break;
    case K_TABLE: m->ntbl--; want_nl(m, 2); break;
    default: break;
    }
    m->pfx.n = f.pfx_at; m->pfx.p[m->pfx.n] = 0;
    if ((size_t)m->first_skip > m->pfx.n) m->first_skip = 0;
}

void md_gate(md_t *m, int on) { m->gate = on; }
int md_saw_main(md_t *m) { return m->saw_gate; }

int md_full(const md_t *m) { return m->out.cut || m->out.n >= HTML2MD_MAX_BYTES; }

char *md_finish(md_t *m, size_t *len) {
    rtrim(m);
    /* drop trailing spaces per line and collapse 3+ newlines */
    buf_t o = {0}; bstr(&o, "");
    size_t i = 0; while (i < m->out.n && (m->out.p[i] == '\n' || m->out.p[i] == ' ')) i++;
    int nls = 0;
    for (; i < m->out.n; i++) {
        char ch = m->out.p[i];
        if (ch == '\n') { while (o.n && o.p[o.n - 1] == ' ') o.n--; if (++nls > 2) continue; }
        else nls = 0;
        bput(&o, &ch, 1);
    }
    /* Some emitters append byte by byte; do not return a partial UTF-8 character. */
    if (o.n) {
        size_t j = o.n - 1;
        while (j && ((unsigned char)o.p[j] & 0xc0) == 0x80) j--;
        unsigned c = (unsigned char)o.p[j];
        size_t width = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc0 ? 2 : 1;
        if (o.n - j < width) o.p[o.n = j] = 0;
    }
    for (int j = 0; j < m->sp_n; j++) free(m->st[j].href);
    free(m->st); free(m->out.p); free(m->pend.p); free(m->pfx.p); free(m);
    *len = o.n; return o.p;
}

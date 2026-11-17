/* fe_tok.c — dependency-free tokenizer front-end ("own small C heuristic"): no spec tree building,
 * just a tag stack with the common implied closes (p, li, td/th, tr, dt/dd), void elements,
 * raw-text script/style/textarea, comments, numeric + common named entities. */
#include "md.h"
#include "alloc.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

/* bounded substring search: libc strstr may strlen the whole rest of the document per call (O(n²)) */
static const char *find(const char *p, const char *e, const char *needle) {
    size_t n = strlen(needle);
    for (; (size_t)(e - p) >= n; p++) { p = memchr(p, needle[0], (size_t)(e - p)); if (!p || (size_t)(e - p) < n) return NULL; if (!memcmp(p, needle, n)) return p; }
    return NULL;
}

typedef struct { char *p; size_t n, cap; } sb_t;
static void sput(sb_t *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) { b->cap = (b->n + n + 1) * 2; b->p = md_alloc(realloc(b->p, b->cap)); }
    memcpy(b->p + b->n, s, n); b->n += n; b->p[b->n] = 0;
}
static void utf8(sb_t *b, unsigned c) {
    char t[4]; size_t n;
    if (c < 0x80) { t[0] = (char)c; n = 1; }
    else if (c < 0x800) { t[0] = (char)(0xC0 | c >> 6); t[1] = (char)(0x80 | (c & 63)); n = 2; }
    else if (c < 0x10000) { t[0] = (char)(0xE0 | c >> 12); t[1] = (char)(0x80 | (c >> 6 & 63)); t[2] = (char)(0x80 | (c & 63)); n = 3; }
    else { t[0] = (char)(0xF0 | c >> 18); t[1] = (char)(0x80 | (c >> 12 & 63)); t[2] = (char)(0x80 | (c >> 6 & 63)); t[3] = (char)(0x80 | (c & 63)); n = 4; }
    sput(b, t, n);
}
static const struct { const char *n; unsigned c; } ENT[] = {
    {"amp",38},{"lt",60},{"gt",62},{"quot",34},{"apos",39},{"nbsp",160},{"copy",169},{"reg",174},{"trade",8482},
    {"mdash",8212},{"ndash",8211},{"hellip",8230},{"laquo",171},{"raquo",187},{"lsquo",8216},{"rsquo",8217},
    {"ldquo",8220},{"rdquo",8221},{"bdquo",8222},{"bull",8226},{"middot",183},{"times",215},{"euro",8364},{"deg",176},
    {"shy",173},{"zwj",8205},{"zwnj",8204},{"thinsp",8201},{"ensp",8194},{"emsp",8195},{"rarr",8594},{"larr",8592},
    {"aacute",225},{"Aacute",193},{"eacute",233},{"Eacute",201},{"iacute",237},{"Iacute",205},{"oacute",243},
    {"Oacute",211},{"ouml",246},{"Ouml",214},{"odblac",337},{"Odblac",336},{"uacute",250},{"Uacute",218},
    {"uuml",252},{"Uuml",220},{"udblac",369},{"Udblac",368},{"auml",228},{"Auml",196},{"szlig",223},{"pound",163},
    {"yen",165},{"cent",162},{"sect",167},{"para",182},{"plusmn",177},{"frac12",189},{"hearts",9829},{"check",10003},
};
/* decode entities in s[0..n) into b */
static void decode(sb_t *b, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (s[i] != '&') { size_t j = i; while (j < n && s[j] != '&') j++; sput(b, s + i, j - i); i = j - 1; continue; }
        size_t j = i + 1; unsigned c = 0; int ok = 0;
        if (j < n && s[j] == '#') {
            j++; int hex = j < n && (s[j] == 'x' || s[j] == 'X'); if (hex) j++;
            size_t d0 = j; while (j < n && (hex ? isxdigit((unsigned char)s[j]) : isdigit((unsigned char)s[j])) && j - d0 < 8) { c = c * (hex ? 16 : 10) + (unsigned)(isdigit((unsigned char)s[j]) ? s[j] - '0' : (tolower((unsigned char)s[j]) - 'a' + 10)); j++; }
            ok = j > d0; if (c == 0 || c > 0x10FFFF || (c >= 0xD800 && c < 0xE000)) c = 0xFFFD;
        } else {
            size_t d0 = j; while (j < n && isalnum((unsigned char)s[j]) && j - d0 < 10) j++;
            for (size_t k = 0; k < sizeof ENT / sizeof *ENT; k++)
                if (strlen(ENT[k].n) == j - d0 && !strncmp(ENT[k].n, s + d0, j - d0)) { c = ENT[k].c; ok = 1; break; }
        }
        if (!ok) { sput(b, "&", 1); continue; }
        if (j < n && s[j] == ';') j++;
        utf8(b, c); i = j - 1;
    }
}

typedef struct { const char *ns[48], *vs[48]; size_t nl[48], vl[48]; int n; const char *rest, *end; sb_t vals; } attrs_t;
static const char *get_attr(void *ctx, const char *name, size_t *len) {
    attrs_t *a = ctx;
    if (!strcmp(name, ":layout")) {   /* another <table opens before this table's </table> */
        const char *o = a->rest, *open = NULL, *close = NULL;
        const char *lim = a->end - a->rest > 65536 ? a->rest + 65536 : a->end;   /* bounded: no O(n²) */
        for (; lim - o >= 7; o++) if (*o == '<') {
            if (!open && !strncasecmp(o, "<table", 6)) open = o;
            if (!strncasecmp(o, "</table", 7)) { close = o; break; }
            if (open) break;
        }
        *len = 0; return open && (!close || open < close) ? "" : NULL;
    }
    for (int i = 0; i < a->n; i++)
        if (strlen(name) == a->nl[i] && !strncasecmp(name, a->ns[i], a->nl[i])) { *len = a->vl[i]; return a->vs[i]; }
    return NULL;
}

static int in(const char *t, size_t n, const char *const *set) {
    for (; *set; set++) if (strlen(*set) == n && !strncasecmp(*set, t, n)) return 1;
    return 0;
}
static const char *const VOID_[] = {"br","hr","img","input","meta","link","area","base","col","embed","param","source","track","wbr",0};
static const char *const RAW[] = {"script","style","textarea","title","xmp","noscript",0};
static const char *const BLOCKS[] = {"p","div","ul","ol","table","h1","h2","h3","h4","h5","h6","pre","blockquote","section","article","header","footer","nav","aside","form","hr","dl","figure","main",0};

typedef struct { char t[16]; size_t n; } tag_t;

char *html2md_tok(const char *s, size_t n, const char *base, size_t *out_len, int *cut) {
    const char *e = s + n;
    /* <main> or role=main anywhere → gate like the lexbor front-end */
    int gate = 0;
    for (const char *p = s; e - p > 5 && !gate; p++) if (*p == '<' && (!strncasecmp(p, "<main", 5) && (p[5] == '>' || isspace((unsigned char)p[5])))) gate = 1;
    for (int pass = 0; pass < 2; pass++) {
        md_t *m = md_new(base, MD_CLEAN); md_gate(m, gate);
        tag_t st[512]; int sp = 0;
        sb_t txt = {0}, vals = {0}; sput(&txt, "", 0);
#define CLOSE_TOP() do { md_close(m, st[sp-1].t, st[sp-1].n); sp--; } while (0)
        const char *p = s;
        while (p < e && !md_full(m)) {
            if (*p != '<') {
                const char *q = memchr(p, '<', (size_t)(e - p)); if (!q) q = e;
                txt.n = 0; decode(&txt, p, (size_t)(q - p)); md_text(m, txt.p, txt.n); p = q; continue;
            }
            if (e - p >= 4 && !strncmp(p, "<!--", 4)) { const char *q = find(p + 4, e, "-->"); p = q ? q + 3 : e; continue; }
            if (p + 1 < e && (p[1] == '!' || p[1] == '?')) { const char *q = memchr(p, '>', (size_t)(e - p)); p = q ? q + 1 : e; continue; }
            int closing = p + 1 < e && p[1] == '/';
            const char *t = p + 1 + closing, *te = t;
            while (te < e && (isalnum((unsigned char)*te) || *te == '-' || *te == ':')) te++;
            if (te == t || !isalpha((unsigned char)*t)) { md_text(m, "<", 1); p++; continue; }
            size_t tn = (size_t)(te - t);
            /* attributes */
            attrs_t A = {0}; const char *q = te; int selfclose = 0;
            while (q < e && *q != '>') {
                while (q < e && (isspace((unsigned char)*q) || *q == '/')) { if (*q == '/') selfclose = 1; q++; }
                if (q >= e || *q == '>') break;
                selfclose = 0;
                const char *an = q; while (q < e && !isspace((unsigned char)*q) && *q != '=' && *q != '>' && *q != '/') q++;
                size_t anl = (size_t)(q - an); const char *av = NULL; size_t avl = 0;
                while (q < e && isspace((unsigned char)*q)) q++;
                if (q < e && *q == '=') {
                    q++; while (q < e && isspace((unsigned char)*q)) q++;
                    if (q < e && (*q == '"' || *q == '\'')) { char qc = *q++; av = q; while (q < e && *q != qc) q++; avl = (size_t)(q - av); if (q < e) q++; }
                    else { av = q; while (q < e && !isspace((unsigned char)*q) && *q != '>') q++; avl = (size_t)(q - av); }
                }
                if (A.n < 48 && anl) { A.ns[A.n] = an; A.nl[A.n] = anl; A.vs[A.n] = av ? av : ""; A.vl[A.n] = avl; A.n++; }
            }
            p = q < e ? q + 1 : e;
            if (closing) {
                int i = sp - 1; while (i >= 0 && !(st[i].n == tn && !strncasecmp(st[i].t, t, tn))) i--;
                if (i >= 0) while (sp > i) CLOSE_TOP();
                continue;
            }
            /* implied closes */
            if (in(t, tn, BLOCKS)) { for (int i = sp - 1; i >= 0; i--) { if (st[i].n == 1 && st[i].t[0] == 'p') { while (sp > i) CLOSE_TOP(); break; }
                if (in(st[i].t, st[i].n, (const char *const[]){"div","td","th","li","section","article","body","table","blockquote",0})) break; } }
            const char *const *sib = NULL; const char *const *stop = NULL;
            static const char *const LI[] = {"li",0}, *const LISTOP[] = {"ul","ol","menu",0};
            static const char *const TD[] = {"td","th",0}, *const TDSTOP[] = {"tr","table",0};
            static const char *const TR[] = {"tr",0}, *const TRSTOP[] = {"table","tbody","thead","tfoot",0};
            static const char *const DT[] = {"dt","dd",0}, *const DTSTOP[] = {"dl",0};
            if (in(t, tn, LI)) sib = LI, stop = LISTOP; else if (in(t, tn, TD)) sib = TD, stop = TDSTOP;
            else if (tn == 2 && !strncasecmp(t, "tr", 2)) sib = TR, stop = TRSTOP; else if (in(t, tn, DT)) sib = DT, stop = DTSTOP;
            if (sib) for (int i = sp - 1; i >= 0; i--) { if (in(st[i].t, st[i].n, stop)) break; if (in(st[i].t, st[i].n, sib)) { while (sp > i) CLOSE_TOP(); break; } }
            /* attribute values with entities decoded */
            size_t off[48]; vals.n = 0;           /* one buffer reused across tags (musl malloc churn) */
            for (int i = 0; i < A.n; i++) { off[i] = vals.n; decode(&vals, A.vs[i], A.vl[i]); A.vl[i] = vals.n - off[i]; sput(&vals, "", 1); }
            for (int i = 0; i < A.n; i++) A.vs[i] = vals.p ? vals.p + off[i] : "";
            A.rest = p; A.end = e;
            md_open(m, t, tn, get_attr, &A);
            if (in(t, tn, VOID_) || selfclose) { md_close(m, t, tn); continue; }
            if (sp < 512) { size_t k = tn < 15 ? tn : 15; memcpy(st[sp].t, t, k); st[sp].t[k] = 0; st[sp].n = k; sp++; }
            else { md_close(m, t, tn); }
            if (in(t, tn, RAW)) {       /* raw text until </tag */
                const char *r = p;
                while (r < e && !(e - r >= (ptrdiff_t)tn + 3 && r[0] == '<' && r[1] == '/' && !strncasecmp(r + 2, t, tn)
                                  && strchr(" \t\n\r\f/>", r[2 + tn]) && r[2 + tn])) r++;     /* bounded, whole tag name */
                txt.n = 0; decode(&txt, p, (size_t)(r - p)); md_text(m, txt.p, txt.n);
                p = r;
            }
        }
        *cut = md_full(m);
        while (sp && !md_full(m)) CLOSE_TOP();
        *cut = *cut || md_full(m);
        free(txt.p); free(vals.p);
        char *md = md_finish(m, out_len);
        if (gate && *out_len < 500 && pass == 0) { free(md); gate = 0; continue; }
        return md;
    }
    return NULL;
}

/* html2md regressions: charset, hostile input, caps. make test-html2md (ASan+UBSan). */
#include "../html2md/md.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
static char *conv(const char *html, size_t n, const char *ctype, int *cut) {
    size_t u, o; const char *label; int c = 0;
    char *t = to_utf8((const unsigned char *)html, n, ctype, &u, &label);
    char *m = html2md_tok(t, u, "https://ex.com/a/", &o, &c);
    free(t);
    if (strlen(m) != o) { printf("FAIL embedded NUL in output\n"); fails++; }
    if (cut) *cut = c;
    return m;
}
static void has(const char *name, const char *html, size_t n, const char *ctype, const char *want, int present) {
    char *m = conv(html, n, ctype, NULL);
    if ((strstr(m, want) != NULL) != present) { printf("FAIL %s: %s '%s'\n---\n%s\n---\n", name, present ? "missing" : "unexpected", want, m); fails++; }
    free(m);
}
#define S(x) x, sizeof x - 1

int main(void) {
    has("heading+link", S("<h1>Hi</h1><p><a href=\"/x\">y</a></p>"), "text/html", "# Hi", 1);
    has("relative link", S("<a href=\"b\">y</a>"), "text/html", "(https://ex.com/a/b)", 1);
    has("latin2 header", S("<p>\xf5\xfb</p>"), "text/html; charset=iso-8859-2", "\xc5\x91\xc5\xb1", 1);
    has("latin2 meta", S("<meta charset=iso-8859-2><p>\xf5</p>"), "text/html", "\xc5\x91", 1);
    has("utf16 bom", S("\xff\xfe<\0p\0>\0\x51\x01<\0/\0p\0>\0"), "text/html", "\xc5\x91", 1);
    has("overlong rejected", S("<p>\xc0\xbc</p>"), "text/html", "<", 0);
    has("entity", S("<p>&amp;&eacute;&#x151;</p>"), "text/html", "&\xc3\xa9\xc5\x91", 1);
    has("nul", S("<p>a\0b</p>"), "text/html", "a\xef\xbf\xbd" "b", 1);
    has("script dropped", S("<script>var x='</scr'+'ipt>'</script><p>ok</p>"), "text/html", "ok", 1);
    has("aside in main kept", S("<main><aside>keep</aside></main>"), "text/html", "keep", 1);
    has("aside outside dropped", S("<aside>drop</aside><main>x</main>"), "text/html", "drop", 0);
    /* Table with role=main inside a hidden list must not unbalance the list stack. */
    has("gate/list balance", S("<ul hidden><table role=main><tr><td>x</td></tr></table></ul><ol><li>a</ol><ul><li>b</ul>"), "text/html", "- b", 1);
    has("huge start", S("<ol start=99999999999999999999><li>a</ol>"), "text/html", "a", 1);

    /* Hostile shapes: must finish, stay within the cap, and not crash under ASan. */
    size_t n = 4u << 20; char *big = malloc(n + 1); int cut = 0;
    for (size_t i = 0; i < n; i++) big[i] = "<p>word "[i % 8];
    big[n] = 0; char *m = conv(big, n, "text/html", &cut);
    if (!cut || strlen(m) > 700000) { printf("FAIL cap: cut=%d len=%zu\n", cut, strlen(m)); fails++; }
    free(m);
    for (size_t i = 0; i < n; i++) big[i] = "<div><ul><blockquote>"[i % 21];
    free(conv(big, n, "text/html", NULL));
    for (size_t i = 0; i < n; i++) big[i] = "<a href=\"x"[i % 10];
    free(conv(big, n, "text/html", NULL));
    free(big);

    printf(fails ? "html2md: %d FAIL\n" : "html2md: all ok\n", fails);
    return fails != 0;
}

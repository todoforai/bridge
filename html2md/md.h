/* md.h — streaming HTML-event → Markdown emitter used by the tiny tokenizer.
 * A front-end calls md_open/md_text/md_close in document order; md_finish returns the Markdown (malloc'd). */
#ifndef MD_H
#define MD_H
#include <stddef.h>

/* Attribute lookup for the element being opened: value or NULL, *len set. */
typedef const char *(*md_attr_fn)(void *ctx, const char *name, size_t *len);

typedef struct md md_t;
enum { MD_CLEAN = 1 };
md_t *md_new(const char *base_url, int flags);
void  md_gate(md_t *m, int on);      /* emit only inside <main>/role=main */
int   md_saw_main(md_t *m);
void  md_open(md_t *m, const char *tag, size_t tag_len, md_attr_fn attr, void *ctx);
void  md_close(md_t *m, const char *tag, size_t tag_len);
void  md_text(md_t *m, const char *s, size_t len);   /* UTF-8, entities already decoded */
char *md_finish(md_t *m, size_t *out_len);           /* frees m */

/* charset.c: bytes → UTF-8 by BOM, Content-Type charset, early <meta charset>; undeclared invalid UTF-8 → replacement character.
 * Returns malloc'd NUL-terminated UTF-8; *label = the decoder used. */
char *to_utf8(const unsigned char *b, size_t n, const char *content_type, size_t *out_len, const char **label);

/* Stop at the output budget (UTF-8 boundary); *cut indicates a partial page. */
#define HTML2MD_MAX_BYTES 600000
int md_full(const md_t *m);
char *html2md_tok(const char *utf8, size_t n, const char *base_url, size_t *out_len, int *cut);
#endif

// Shell relay end to end: the daemon half (shell_relay_*) runs on this test's
// poll loop with a fake Noise send that records frames; the client half is the
// REAL bridge binary (`tfa-cat`, `__live`) run as a child — on a PTY where a
// TTY stdout matters. Build+run: make test-shell-relay (needs build/todoforai-bridge).
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "../shell_relay.h"
#include "../json.h"

#include <assert.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static char frames[48 << 20];   // 20MB cap → ~27MB of b64
static size_t frames_len;
static int connected = 1, busy = 0;
static long reply_after_end = -1;  // streamId to auto-CLOSE on END
static const char *reply_err;
static shell_relay_t R;
// Fake backend for `fetch`: answers the next fetch OPEN with this body
// (fetch_attach: CLOSE ok without a body; fetch_err: CLOSE with error).
static long fetch_id = -1;
static const char *fetch_body, *fetch_err;
static size_t fetch_len;
static int fetch_attach;

// cli: answers queued per round (a `need` round, then the result), served as a fetch body on END.
static char cli_replies[4][4096]; static size_t cli_len[4]; static int cli_n, cli_i;
static long cli_stream = -1, cli_refuse_id = -1;
static int cli_refuse, cli_opens;   // refuse the Nth round: CLOSE {error} right at OPEN (a backend without `cli`)

static int fake_send(void *ctx, const char *json, size_t len) {
    (void)ctx;
    if (!connected) return -1;
    assert(frames_len + len + 1 < sizeof frames);
    memcpy(frames + frames_len, json, len); frames_len += len;
    frames[frames_len++] = '\n';
    frames[frames_len] = 0;
    if (strstr(json, "\"shell:open\"") && strstr(json, "\"kind\":\"fetch\"")) {
        const char *p = NULL; size_t pl = 0;
        json_get_obj(json, len, "payload", &p, &pl);
        json_get_long(p, pl, "streamId", &fetch_id);
    }
    if (strstr(json, "\"shell:open\"") && strstr(json, "\"kind\":\"cli\"")) {
        const char *p = NULL; size_t pl = 0;
        json_get_obj(json, len, "payload", &p, &pl);
        json_get_long(p, pl, "streamId", &cli_stream);
        if (++cli_opens == cli_refuse) { cli_refuse_id = cli_stream; cli_stream = -1; }
    }
    if (strstr(json, "\"shell:end\"") && !strstr(json, "\"abort\"")) {
        long id = 0; const char *p = NULL; size_t pl = 0;
        json_get_obj(json, len, "payload", &p, &pl);
        json_get_long(p, pl, "streamId", &id);
        if (id == cli_refuse_id) { /* refused at OPEN: the backend no longer knows it */ }
        else if (id == cli_stream) {
            cli_stream = -1;
            if (!fetch_err && cli_i < cli_n) { fetch_body = cli_replies[cli_i]; fetch_len = cli_len[cli_i]; cli_i++; }
            fetch_id = id;
        }
        else reply_after_end = id;
    }
    return 0;
}
static int fake_busy(void *ctx) { (void)ctx; return busy; }
static int fake_ready(void *ctx) { (void)ctx; return connected; }

static void pump(int ms) {
    struct pollfd pf[1 + SHELL_MAX_STREAMS];
    size_t n = 0;
    shell_relay_fill_pfds(&R, pf, &n, 1 + SHELL_MAX_STREAMS);
    if (poll(pf, n, ms) > 0) shell_relay_service(&R, pf, 0, n);
    if (reply_after_end > 0) {
        char c[256];
        int cn = reply_err
            ? snprintf(c, sizeof c, "{\"streamId\":%ld,\"error\":\"%s\"}", reply_after_end, reply_err)
            : snprintf(c, sizeof c, "{\"streamId\":%ld}", reply_after_end);
        reply_after_end = -1;
        shell_relay_on_close(&R, c, (size_t)cn);
    }
    if (cli_refuse_id > 0) {
        char c[96];
        int cn = snprintf(c, sizeof c, "{\"streamId\":%ld,\"error\":\"bad request\"}", cli_refuse_id);
        cli_refuse_id = -1;
        shell_relay_on_close(&R, c, (size_t)cn);
    }
    if (fetch_id > 0) {
        long id = fetch_id; fetch_id = -1;
        static char c[SHELL_DATA_CHUNK * 2 + 128];
        int cn;
        if (fetch_err) cn = snprintf(c, sizeof c, "{\"streamId\":%ld,\"error\":\"%s\"}", id, fetch_err);
        else if (fetch_attach) cn = snprintf(c, sizeof c, "{\"streamId\":%ld}", id);
        else {
            cn = snprintf(c, sizeof c, "{\"streamId\":%ld,\"size\":%zu,\"mime\":\"text/plain\"}", id, fetch_len);
            shell_relay_on_ready(&R, c, (size_t)cn);
            for (size_t off = 0; off < fetch_len; off += SHELL_DATA_CHUNK) {
                size_t n = fetch_len - off < SHELL_DATA_CHUNK ? fetch_len - off : SHELL_DATA_CHUNK;
                int h = snprintf(c, sizeof c, "{\"streamId\":%ld,\"b64\":\"", id);
                size_t bl = b64_encode((const uint8_t *)fetch_body + off, n, c + h, sizeof c - (size_t)h - 4);
                memcpy(c + h + bl, "\"}", 3);
                shell_relay_on_data(&R, c, (size_t)h + bl + 2);
            }
            cn = snprintf(c, sizeof c, "{\"streamId\":%ld}", id);
        }
        shell_relay_on_close(&R, c, (size_t)cn);
    }
    shell_relay_tick(&R);
}

// Run `cmd` via sh (on a PTY if tty), pumping the relay until it exits.
// Returns exit code; child's output (stdout+stderr when tty) in out.
static int run(const char *cmd, int tty, char *out, size_t cap) {
    int fd = -1; pid_t pid;
    int pp[2] = { -1, -1 };
    if (tty) pid = forkpty(&fd, NULL, NULL, NULL);
    else { assert(pipe(pp) == 0); pid = fork(); }
    if (pid == 0) {
        if (!tty) { dup2(pp[1], 1); dup2(pp[1], 2); close(pp[0]); close(pp[1]); }
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    if (!tty) { close(pp[1]); fd = pp[0]; }
    size_t o = 0; int st = 0, done = 0;
    for (int spins = 0; spins < 2000; spins++) {
        pump(5);
        struct pollfd p = { .fd = fd, .events = POLLIN };
        while (poll(&p, 1, 0) > 0) {
            ssize_t r = read(fd, out + o, cap - 1 - o);
            if (r <= 0) break;
            o += (size_t)r;
        }
        if (!done && waitpid(pid, &st, WNOHANG) == pid) done = 1;
        if (done) { for (int i = 0; i < 40; i++) pump(5); break; }
    }
    // drain remaining
    struct pollfd p = { .fd = fd, .events = POLLIN };
    while (poll(&p, 1, 0) > 0) { ssize_t r = read(fd, out + o, cap - 1 - o); if (r <= 0) break; o += (size_t)r; }
    out[o] = 0;
    close(fd);
    assert(done);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static size_t count(const char *hay, const char *needle) {
    size_t c = 0;
    for (const char *p = hay; (p = strstr(p, needle)); p += strlen(needle)) c++;
    return c;
}

// Concatenate + decode every shell:data b64 in frames → dst.
static size_t decoded(char *dst, size_t cap) {
    size_t o = 0;
    for (const char *p = frames; (p = strstr(p, "\"shell:data\"")); p++) {
        const char *b = strstr(p, "\"b64\":\"") + 7, *e = strchr(b, '"');
        o += b64_decode(b, (size_t)(e - b), dst + o, cap - o);
    }
    return o;
}

static void reset(void) {
    frames_len = 0; frames[0] = 0; reply_err = NULL; connected = 1; busy = 0;
    fetch_body = fetch_err = NULL; fetch_len = 0; fetch_attach = 0;
    cli_n = cli_i = 0; cli_refuse = cli_opens = 0;
}

// Queue one backend answer for a `cli` round: the reply line + `rest`.
static void cli_answer(const char *line, const char *rest) {
    cli_len[cli_n] = (size_t)snprintf(cli_replies[cli_n], sizeof cli_replies[0], "%s\n%s", line, rest);
    cli_n++;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    shell_relay_init(&R, fake_send, fake_busy, fake_ready, NULL);
    assert(R.port);
    char env[512];
    snprintf(env, sizeof env, "env -u TODOFORAI_MESSAGE_ID TODOFORAI_BRIDGE_PORT=%u TODOFORAI_API_TOKEN=dst_x TODOFORAI_TODO_ID=T1 TODOFORAI_BLOCK_ID=B1 ", R.port);
    char cmd[2048];
    static char out[1 << 20], dec[24 << 20];
    assert(system("mkdir -p build/sr && cd build/sr && ln -sf ../todoforai-bridge tfa-cat"
                  " && printf '\\211PNG\\r\\n\\032\\n0123456789' > a.png && printf 'hello\\n' > t.txt"
                  " && head -c 3000000 /dev/urandom > big.bin && (printf '%%PDF-1.4\\n'; cat big.bin) > big.pdf"
                  " && (printf '%%PDF-1.4\\n'; head -c 21000000 /dev/zero) > huge.pdf"
                  " && (printf '\\211PNG\\r\\n\\032\\n'; head -c 3600000 /dev/zero) > big.png"
                  " && mkdir -p repo/sub .claude/skills/demo && printf 'skill body\\n' > .claude/skills/demo/SKILL.md"
                  " && printf 'ref\\n' > .claude/skills/demo/ref.md") == 0);

    // 1. PNG on a TTY → open/data/end, ok, silent, rc 0.
    reset();
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat build/sr/a.png; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "rc=0"));
    assert(!strstr(out, "PNG"));
    assert(count(frames, "\"shell:open\"") == 1 && strstr(frames, "\"kind\":\"attach\"") && strstr(frames, "\"name\":\"a.png\"")
        && strstr(frames, "\"mime\":\"image/png\"") && strstr(frames, "\"token\":\"dst_x\"") && strstr(frames, "\"blockId\":\"B1\""));
    assert(count(frames, "\"shell:end\"") == 1);
    assert(decoded(dec, sizeof dec) == 18 && !memcmp(dec, "\x89PNG", 4));
    printf("ok 1 png attached\n");

    // 2. Backend rejection → message on stderr, rc 1.
    reset(); reply_err = "no running command for this block";
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "not attached: no running command for this block") && strstr(out, "rc=1"));
    printf("ok 2 backend error surfaced\n");

    // 3. Text → plain cat, no frames. Redirected PNG → raw bytes, no frames.
    reset();
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat build/sr/t.txt; %s build/sr/tfa-cat build/sr/a.png > build/sr/copy.png && cmp build/sr/a.png build/sr/copy.png && echo same", env, env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "hello") && strstr(out, "same") && frames_len == 0);
    printf("ok 3 text/redirect plain cat\n");

    // 4. 3MB PDF via stdin, chunked ≤ SHELL_DATA_CHUNK, bytes intact.
    reset();
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat < build/sr/big.pdf; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "rc=0"));
    assert(strstr(frames, "\"name\":\"stdin-1.pdf\""));
    size_t dn = decoded(dec, sizeof dec);
    FILE *f = fopen("build/sr/big.pdf", "rb"); static char want[4 << 20]; size_t wn = fread(want, 1, sizeof want, f); fclose(f);
    assert(dn == wn && !memcmp(dec, want, wn));
    assert(count(frames, "\"shell:data\"") >= wn / SHELL_DATA_CHUNK);
    printf("ok 4 3MB pdf chunked intact (%zu frames)\n", count(frames, "\"shell:data\""));

    // 5. >20MB → refused before anything is sent.
    reset();
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat build/sr/huge.pdf; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "compress/downscale") && strstr(out, "rc=1"));
    assert(frames_len == 0);
    printf("ok 5 over cap refused\n");

    // 5b. Client dies mid-stream (declared 100, sent 3, EOF) → abort, never END-ok.
    reset();
    snprintf(cmd, sizeof cmd, "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',%u));"
             "s.sendall(b'{\\\"kind\\\":\\\"attach\\\",\\\"token\\\":\\\"t\\\",\\\"todoId\\\":\\\"T\\\",\\\"blockId\\\":\\\"B\\\",\\\"size\\\":100}\\nPNG');"
             "s.shutdown(1);print(s.recv(99))\"", R.port);
    run(cmd, 0, out, sizeof out);
    assert(strstr(out, "truncated") && strstr(frames, "\"abort\":true") && strstr(frames, "\"size\":100"));
    printf("ok 5b short stream aborted\n");

    // 5c. Attach without size → bad request, nothing relayed.
    reset();
    snprintf(cmd, sizeof cmd, "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',%u));"
             "s.sendall(b'{\\\"kind\\\":\\\"attach\\\",\\\"token\\\":\\\"t\\\",\\\"todoId\\\":\\\"T\\\",\\\"blockId\\\":\\\"B\\\"}\\n');"
             "s.shutdown(1);print(s.recv(99))\"", R.port);
    run(cmd, 0, out, sizeof out);
    assert(strstr(out, "bad request") && frames_len == 0);
    printf("ok 5c size required\n");

    // 6. Backend down → clear error.
    reset(); connected = 0;
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat build/sr/a.png; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "not connected to the backend") && strstr(out, "rc=1"));
    printf("ok 6 disconnected\n");

    // 7. No relay port → explains, rc 1.
    reset();
    run("env -u TODOFORAI_BRIDGE_PORT TODOFORAI_BLOCK_ID=B1 build/sr/tfa-cat build/sr/a.png; echo rc=$?", 1, out, sizeof out);
    assert(strstr(out, "TODOFORAI_BRIDGE_PORT") && strstr(out, "rc=1"));
    printf("ok 7 no port\n");

    // 8. __live: tee is exact; daemon sends batched, rate-limited lines + END.
    reset();
    snprintf(cmd, sizeof cmd, "env TODOFORAI_MESSAGE_ID=M1 TODOFORAI_BRIDGE_PORT=%u TODOFORAI_API_TOKEN=dst_x TODOFORAI_TODO_ID=T1 TODOFORAI_BLOCK_ID=B1 "
             "sh -c 'seq 1 500 | build/todoforai-bridge __live | md5sum; seq 1 500 | md5sum'", R.port);
    run(cmd, 0, out, sizeof out);
    { char *nl = strchr(out, '\n'); assert(nl && !strncmp(out, nl + 1, 32)); }
    assert(strstr(frames, "\"kind\":\"live\"") && strstr(frames, "\"messageId\":\"M1\""));
    assert(count(frames, "\"shell:end\"") == 1);
    dn = decoded(dec, sizeof dec); dec[dn] = 0;
    assert(strstr(dec, "lines]") && strstr(dec, "500\n"));   // skipped marker + last line
    printf("ok 8 live tee + batched lines\n");

    // 9. __live with no relay: plain cat, never breaks the pipe.
    reset();
    run("env -u TODOFORAI_BRIDGE_PORT TODOFORAI_MESSAGE_ID=M1 TODOFORAI_BLOCK_ID=B1 sh -c 'printf \"a\\nb\\n\" | build/todoforai-bridge __live'", 0, out, sizeof out);
    assert(!strcmp(out, "a\nb\n") && frames_len == 0);
    printf("ok 9 live without relay\n");

    // 10. live line batching unit: skip marker and cut.
    { char b[512]; char src[] = "1\n2\n3\n"; size_t n = shell_live_body(b, sizeof b, 0, src, 6, 1); b[n] = 0; assert(!strcmp(b, "[\xe2\x80\xa6 2 lines]\n3\n")); }
    printf("ok 10 live body\n");

    // 11. A silent local client can't pin a slot: header deadline frees it.
    reset();
    { int c = socket(AF_INET, SOCK_STREAM, 0);
      struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(R.port) }; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      assert(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
      for (int i = 0; i < 10; i++) pump(5);
      assert(shell_relay_stream_count(&R) == 1);
      int64_t until = ws_monotonic_ms() + SHELL_HDR_MS + 400;
      while (ws_monotonic_ms() < until && shell_relay_stream_count(&R)) pump(50);
      assert(shell_relay_stream_count(&R) == 0);
      close(c); }
    printf("ok 11 header deadline\n");

    // 12. Image over the model's cap → refused locally, nothing sent.
    reset();
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat build/sr/big.png; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "downscale") && strstr(out, "rc=1") && frames_len == 0);
    printf("ok 12 image cap\n");

    // 13. skill:<name>[/file] from cwd's parents; unknown skill explains.
    reset();
    snprintf(cmd, sizeof cmd, "cd build/sr/repo/sub && %s HOME=/nonexistent ../../tfa-cat skill:demo skill:demo/ref.md; %s ../../tfa-cat skill:nope; echo rc=$?", env, env);
    run(cmd, 0, out, sizeof out);
    assert(strstr(out, "skill body\nref\n") && strstr(out, "no such skill") && strstr(out, "rc=1") && frames_len == 0);
    printf("ok 13 skill refs\n");

    // 14. fetch: body streamed (3MB, backpressure through a pipe), exact bytes.
    reset();
    { static char body[3 << 20]; for (size_t i = 0; i < sizeof body; i++) body[i] = (char)('a' + i % 26);
      fetch_body = body; fetch_len = sizeof body;
      FILE *w = fopen("build/sr/want.txt", "wb"); fwrite(body, 1, sizeof body, w); fclose(w); }
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat todoforai:todos/T1/x.txt | (sleep 0.3; cat) > build/sr/got.txt; cmp build/sr/want.txt build/sr/got.txt && echo same", env);
    run(cmd, 0, out, sizeof out);
    assert(strstr(out, "same"));
    assert(strstr(frames, "\"kind\":\"fetch\"") && strstr(frames, "\"ref\":\"todoforai:todos/T1/x.txt\"") && !strstr(frames, "\"tty\""));
    printf("ok 14 fetch streamed\n");

    // 15. fetch on a TTY: attached by the backend (silent, rc 0); error surfaced.
    reset(); fetch_attach = 1;
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat todoforai:todos/T1/p.png; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "rc=0") && strstr(frames, "\"tty\":true"));
    reset(); fetch_err = "No such resource";
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "No such resource") && strstr(out, "rc=1"));
    printf("ok 15 fetch attach/error\n");

    // 16. fetch of a binary on a TTY → a hint, not bytes; redirected → bytes.
    reset(); fetch_body = "PK\003\004\0\0xyz"; fetch_len = 9;
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat todoforai:todos/T1/a.docx; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "binary (text/plain, 9 bytes)") && strstr(out, "> 'a.docx' && anydoc 'a.docx'") && strstr(out, "rc=1") && !strstr(out, "xyz"));
    reset(); fetch_body = "PK\003\004\0\0xyz"; fetch_len = 9;
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat todoforai:todos/T1/a.docx > build/sr/a.docx; wc -c < build/sr/a.docx", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "9"));
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat build/sr/a.docx; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "As text: anydoc 'build/sr/a.docx'") && strstr(out, "rc=1") && !strstr(out, "xyz"));
    printf("ok 16 binary hint\n");

    // 17. FILE:FROM:TO / FILE:FROM line ranges (file, pipe, ref); a real file named `x:3` wins;
    //     todoforai:todos/ ranges only after an attachment UUID; no file before the range explains.
    reset();
    assert(system("cd build/sr && printf 'a\\nb\\nc\\nd\\n' > l.txt && printf 'name\\n' > 'n:3'") == 0);
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat build/sr/l.txt:2:3 build/sr/l.txt:4 build/sr/n:3; %s build/sr/tfa-cat build/sr/l.txt:3:3 | od -c | head -1; %s build/sr/tfa-cat 5:9; echo rc=$?", env, env, env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "b\r\nc\r\nd\r\nname") && strstr(out, "c  \\n") && strstr(out, "no file before the range") && strstr(out, "rc=1"));
    reset(); fetch_body = "l1\nl2\nl3\nl4\n"; fetch_len = 12;
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat todoforai:todos/T1/0123abcd-0123-0123-0123-0123456789ab:2:3 | cat; echo rc=$?", env);
    run(cmd, 0, out, sizeof out);
    assert(strstr(out, "l2\nl3\nrc=0") && !strstr(out, "l4") && strstr(frames, "\"ref\":\"todoforai:todos/T1/0123abcd-0123-0123-0123-0123456789ab\""));
    reset(); fetch_body = "x\n"; fetch_len = 2;
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-cat todoforai:todos/T1/bash:1 | cat", env);
    run(cmd, 0, out, sizeof out);
    assert(strstr(frames, "\"ref\":\"todoforai:todos/T1/bash:1\""));
    printf("ok 17 line ranges\n");

    // 18. -w: stdin replaces a todoforai: resource (an attach with a ref, kind put); local paths refused.
    reset();
    snprintf(cmd, sizeof cmd, "printf 'hi\\n' | %s build/sr/tfa-cat -w todoforai:projects/P/memory/x.md; echo rc=$?; %s build/sr/tfa-cat -w x.md </dev/null; echo rc=$?", env, env);
    run(cmd, 0, out, sizeof out);
    assert(strstr(out, "rc=0") && strstr(out, "only todoforai: refs") && strstr(out, "rc=1"));
    assert(count(frames, "\"shell:open\"") == 1 && strstr(frames, "\"kind\":\"put\"") && strstr(frames, "\"ref\":\"todoforai:projects/P/memory/x.md\"")
        && strstr(frames, "\"size\":3") && decoded(dec, sizeof dec) == 3 && !memcmp(dec, "hi\n", 3));
    printf("ok 18 put\n");
    assert(shell_relay_stream_count(&R) == 0);

    // 19. cli: argv goes up as one sized request, the backend's code/stdout/stderr come back. stdin untouched.
    assert(system("cd build/sr && for n in tfa-search tfa-question tfa-show tfa-surface; do ln -sf ../todoforai-bridge $n; done") == 0);
    reset(); cli_answer("{\"code\":3,\"out\":6,\"err\":5}", "hello\noops\n");
    snprintf(cmd, sizeof cmd, "cd build/sr && echo keep | (%s TODOFORAI_PROJECT_ID=P1 TODOFORAI_FRONTEND_ID=F1 ./tfa-search -n 3 'a \"b\"' 2>e.txt; echo rc=$?; cat; cat e.txt)", env);
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "hello\nrc=3\nkeep\noops\n"));
    assert(count(frames, "\"shell:open\"") == 1 && strstr(frames, "\"kind\":\"cli\"") && strstr(frames, "\"name\":\"tfa-search\"") && count(frames, "\"shell:end\"") == 1);
    dn = decoded(dec, sizeof dec); dec[dn] = 0;
    assert(strstr(dec, "{\"argv\":[\"-n\",\"3\",\"a \\\"b\\\"\"],\"cwd\":\"") && strstr(dec, "/build/sr\",\"projectId\":\"P1\",\"frontendId\":\"F1\",\"inputs\":[]}\n"));
    { char want[64]; snprintf(want, sizeof want, "\"size\":%zu", dn); assert(strstr(frames, want)); }
    printf("ok 19 cli round trip\n");

    // 20. cli: stdin is read only when the backend asks, then the command is asked again with it.
    reset(); cli_answer("{\"need\":\"stdin\"}", ""); cli_answer("{\"code\":0,\"out\":6,\"err\":0}", "asked\n");
    snprintf(cmd, sizeof cmd, "printf '{\"q\":1}' | %s build/sr/tfa-question; echo rc=$?", env);
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "asked\nrc=0\n") && count(frames, "\"shell:open\"") == 2);
    dn = decoded(dec, sizeof dec); dec[dn] = 0;
    assert(strstr(dec, "\"inputs\":[]}\n{\"argv\":[]") && strstr(dec, "\"inputs\":[{\"kind\":\"stdin\",\"size\":7}]}\n{\"q\":1}"));
    // A terminal on stdin is reported, never read.
    reset(); cli_answer("{\"need\":\"stdin\"}", ""); cli_answer("{\"code\":2,\"out\":0,\"err\":6}", "usage\n");
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-question; echo rc=$?", env);
    run(cmd, 1, out, sizeof out);
    assert(strstr(out, "usage") && strstr(out, "rc=2"));
    dn = decoded(dec, sizeof dec); dec[dn] = 0;
    assert(strstr(dec, "{\"kind\":\"stdin\",\"size\":0,\"tty\":true}"));
    printf("ok 20 cli stdin on demand\n");

    // 21. cli: a file the backend asks for is sent (3MB, chunked); a missing one is reported.
    reset(); cli_answer("{\"need\":\"file\",\"path\":\"build/sr/big.bin\"}", ""); cli_answer("{\"code\":0,\"out\":8,\"err\":0}", "T1:plan\n");
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-show build/sr/big.bin --alias plan; echo rc=$?", env);
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "T1:plan\nrc=0\n"));
    dn = decoded(dec, sizeof dec);
    { const char *hdr = "\"inputs\":[{\"kind\":\"file\",\"size\":3000000,\"path\":\"build/sr/big.bin\"}]}\n";
      char *at = memmem(dec, dn, hdr, strlen(hdr)); assert(at);
      FILE *bf = fopen("build/sr/big.bin", "rb"); static char want[3000000]; assert(fread(want, 1, sizeof want, bf) == sizeof want); fclose(bf);
      assert((size_t)(dec + dn - (at + strlen(hdr))) == sizeof want && !memcmp(at + strlen(hdr), want, sizeof want)); }
    reset(); cli_answer("{\"need\":\"file\",\"path\":\"nope.png\"}", ""); cli_answer("{\"code\":1,\"out\":0,\"err\":10}", "not found\n");
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-show nope.png; echo rc=$?", env);
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "not found\nrc=1\n"));
    dn = decoded(dec, sizeof dec); dec[dn] = 0;
    assert(strstr(dec, "{\"kind\":\"file\",\"size\":0,\"missing\":true,\"path\":\"nope.png\"}"));
    printf("ok 21 cli file on demand\n");

    // 22. cli: a refusal (old backend, dead run), no backend, a garbled answer → one line on stderr, rc 1; --version is local.
    reset(); fetch_err = "bad request";
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-search x; echo rc=$?", env);
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "tfa-search: bad request\nrc=1\n"));
    // …also when it comes before the request is through (a backend without `cli`), big input or not.
    reset(); cli_refuse = 1;
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "tfa-search: bad request\nrc=1\n") && shell_relay_stream_count(&R) == 0);
    reset(); cli_refuse = 2; cli_answer("{\"need\":\"file\",\"path\":\"build/sr/big.bin\"}", "");
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-show build/sr/big.bin; echo rc=$?", env);
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "tfa-show: bad request\nrc=1\n") && shell_relay_stream_count(&R) == 0);
    assert(count(frames, "\"shell:data\"") < 70);   // the rest of the 3MB was discarded, not relayed
    snprintf(cmd, sizeof cmd, "%s build/sr/tfa-search x; echo rc=$?", env);
    reset(); connected = 0;
    run(cmd, 0, out, sizeof out);
    assert(strstr(out, "tfa-search: bridge is not connected to the backend") && strstr(out, "rc=1") && frames_len == 0);
    reset(); cli_answer("{\"code\":0,\"out\":99,\"err\":0}", "short");
    run(cmd, 0, out, sizeof out);
    assert(!strcmp(out, "tfa-search: unexpected answer from the server\nrc=1\n"));
    reset();
    snprintf(cmd, sizeof cmd, "env -u TODOFORAI_BRIDGE_PORT build/sr/tfa-show --version; build/sr/tfa-surface -V; build/todoforai-bridge __cli tfa-search -V; build/todoforai-bridge __cli rm 2>&1 | head -c 0; echo rc=$?");
    run(cmd, 0, out, sizeof out);
    assert(!strncmp(out, "tfa-show ", 9) && strstr(out, "\ntfa-surface ") && strstr(out, "\ntfa-search ") && frames_len == 0);
    assert(shell_relay_stream_count(&R) == 0);
    printf("ok 22 cli errors + version\n");

    // 23. cli: a client that dies mid-request is aborted; one that declares nothing is refused.
    reset();
    snprintf(cmd, sizeof cmd, "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',%u));"
             "s.sendall(b'{\\\"kind\\\":\\\"cli\\\",\\\"name\\\":\\\"tfa-search\\\",\\\"token\\\":\\\"t\\\",\\\"todoId\\\":\\\"T\\\",\\\"blockId\\\":\\\"B\\\",\\\"size\\\":100}\\n{}');"
             "s.close()\"", R.port);
    run(cmd, 0, out, sizeof out);
    for (int i = 0; i < 20; i++) pump(5);
    assert(strstr(frames, "\"abort\":true") && shell_relay_stream_count(&R) == 0);
    reset();
    snprintf(cmd, sizeof cmd, "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',%u));"
             "s.sendall(b'{\\\"kind\\\":\\\"cli\\\",\\\"name\\\":\\\"tfa-search\\\",\\\"token\\\":\\\"t\\\",\\\"todoId\\\":\\\"T\\\",\\\"blockId\\\":\\\"B\\\",\\\"size\\\":0}\\n');"
             "print(s.recv(99));s.close()\"", R.port);
    run(cmd, 0, out, sizeof out);
    for (int i = 0; i < 20; i++) pump(5);
    assert(strstr(out, "bad request") && frames_len == 0 && shell_relay_stream_count(&R) == 0);
    printf("ok 23 cli aborted / empty\n");

    shell_relay_close_all(&R);
    printf("all ok\n");
    return 0;
}

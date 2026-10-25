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
    if (strstr(json, "\"shell:end\"") && !strstr(json, "\"abort\"")) {
        long id = 0; const char *p = NULL; size_t pl = 0;
        json_get_obj(json, len, "payload", &p, &pl);
        json_get_long(p, pl, "streamId", &id);
        reply_after_end = id;
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
    assert(shell_relay_stream_count(&R) == 0);

    shell_relay_close_all(&R);
    printf("all ok\n");
    return 0;
}

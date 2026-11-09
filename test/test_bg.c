// Background tasks (bg_task.h): `background` RUNs settle at once with
// STEP_BACKGROUND, log to <pid>.output, read <pid>.input, and report
// TASK_STATE / TASK_EXIT; `backgroundOnPark` converts a timed-out step in
// place; TASK_KILL ends a task that ignores nothing, TASK_LIST lists it.
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#ifndef _WIN32
#include <poll.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_capture(const char *json, size_t len);

#define noise_ws_send bridge_test_noise_send
#define bridge_main bridge_main_unused
#include "../main.c"
#undef main

static int g_done, g_bg, g_exit, g_state_on, g_state_off, g_list;
static char g_err_code[64];
static long g_pid, g_exit_code; static int g_exit_null, g_killed, g_bg_awaiting;
static char g_out_path[512], g_in_path[512], g_tail[4096], g_reason[32], g_list_json[8192], g_exit_json[16384], g_bg_json[4096];

int bridge_test_noise_send(noise_ws_t *n, ws_t *w, const uint8_t *pt, size_t pt_len) {
    (void)n; (void)w;
    return test_capture((const char *)pt, pt_len);
}

#define T(lit) (tl == sizeof lit - 1 && !memcmp(t, lit, tl))
static int test_capture(const char *json, size_t len) {
    const char *t = NULL; size_t tl = 0;
    if (!json_get_str(json, len, "type", &t, &tl)) return 0;
    size_t n;
    if (T("step_done")) g_done++;
    if (T("step_background")) {
        g_bg++;
        snprintf(g_bg_json, sizeof g_bg_json, "%.*s", (int)len, json);
        json_get_long(json, len, "pid", &g_pid);
        json_get_str_decoded(json, len, "outputPath", g_out_path, sizeof g_out_path, &n);
        json_get_str_decoded(json, len, "inputPath", g_in_path, sizeof g_in_path, &n);
        json_get_str_decoded(json, len, "reason", g_reason, sizeof g_reason, &n);
        json_get_bool(json, len, "awaitingInput", &g_bg_awaiting);
    }
    if (T("task_state")) {
        int on = 0; json_get_bool(json, len, "awaitingInput", &on);
        if (on) g_state_on++; else g_state_off++;
    }
    if (T("task_exit")) {
        g_exit++;
        snprintf(g_exit_json, sizeof g_exit_json, "%.*s", (int)len, json);
        g_exit_null = !json_get_long(json, len, "exitCode", &g_exit_code);
        json_get_bool(json, len, "killed", &g_killed);
        json_get_str_decoded(json, len, "tail", g_tail, sizeof g_tail, &n);
    }
    if (T("error")) json_get_str_decoded(json, len, "code", g_err_code, sizeof g_err_code, &n);
    if (T("task_list")) { g_list++; snprintf(g_list_json, sizeof g_list_json, "%.*s", (int)len, json); }
    return 0;
}

static void reset(void) {
    g_exit_json[0] = g_bg_json[0] = '\0';
    g_done = g_bg = g_exit = g_state_on = g_state_off = g_list = 0;
    g_pid = g_exit_code = 0; g_exit_null = g_killed = g_bg_awaiting = 0;
    g_out_path[0] = g_in_path[0] = g_tail[0] = g_reason[0] = '\0';
}

static void send_run(edge_t *e, const char *cmd, const char *extra) {
    static int seq = 0;
    char b64[4096];
    size_t bl = b64_encode((const uint8_t *)cmd, strlen(cmd), b64, sizeof b64); b64[bl] = '\0';
    char frame[8192];
    int n = snprintf(frame, sizeof frame,
        "{\"type\":\"run\",\"blockId\":\"bg_%d\",\"cmdB64\":\"%s\"%s}", ++seq, b64, extra);
    handle_command(e, frame, (size_t)n);
}

static int active_sessions(edge_t *e) {
    int n = 0;
    for (int i = 0; i < g_max_sessions; i++) n += e->sessions[i].active != 0;
    return n;
}

static int pump_until(edge_t *e, int (*pred)(edge_t *), int ms) {
    int64_t end = monotonic_ms() + ms;
    while (monotonic_ms() < end) {
        if (pred(e)) return 1;
#ifdef _WIN32
        Sleep(10);
#else
        struct pollfd pfd = { .fd = -1 };
        poll(&pfd, 0, 10);
#endif
        service_sessions(e);
    }
    return pred(e);
}
static int exited(edge_t *e)   { (void)e; return g_exit > 0; }
static int bg_seen(edge_t *e)  { (void)e; return g_bg > 0; }
static int state_on(edge_t *e) { (void)e; return g_state_on > 0; }
static int no_active(edge_t *e) { return active_sessions(e) == 0; }
// The command itself is running (begin marker seen) — ^C before that would hit
// the shell's line reader, not the command.
static int started(edge_t *e) {
    for (int i = 0; i < g_max_sessions; i++)
        if (e->sessions[i].active && e->sessions[i].bg && !e->sessions[i].draining_begin) return 1;
    return 0;
}
static void settle(edge_t *e, int ms) { pump_until(e, started, 5000); int64_t end = monotonic_ms() + ms; while (monotonic_ms() < end) { pump_until(e, exited, 10); } }

static int file_has(const char *path, const char *needle) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char buf[65536]; size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = '\0';
    fclose(f);
    return strstr(buf, needle) != NULL;
}
static int exists(const char *p) { struct stat st; return stat(p, &st) == 0; }
static void append(const char *path, const char *s) {
    FILE *f = fopen(path, "ab"); assert(f); fputs(s, f); fclose(f);
}

static edge_t *mk_edge(void) {
    edge_t *e = calloc(1, sizeof *e);
    e->sessions = calloc((size_t)g_max_sessions, sizeof *e->sessions);
    e->noise.handshake_done = 1;
    snprintf(e->api_url, sizeof e->api_url, "http://test");
    return e;
}

#define CHECK(cond, ...) do { if (!(cond)) { fprintf(stderr, "  FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); fails++; } } while (0)

int main(void) {
#ifdef _WIN32
    char home[MAX_PATH];
    snprintf(home, sizeof home, "%s\\bgtest-%lu", getenv("TEMP"), (unsigned long)GetCurrentProcessId());
    CreateDirectoryA(home, NULL);
    _putenv_s("USERPROFILE", home);
#else
    char home[] = "/tmp/bgtest.XXXXXX";
    assert(mkdtemp(home));
    setenv("HOME", home, 1);
#endif
    g_max_sessions = 8;
    int fails = 0;
    edge_t *e = mk_edge();

    // 1. background: settles at once, logs, exits with code + tail, cleans up.
    reset();
    send_run(e, "echo start; sleep 0.4; echo end; exit 3", ",\"background\":true");
    CHECK(g_bg == 1 && g_done == 0, "[basic] step_background=%d step_done=%d", g_bg, g_done);
    CHECK(!strcmp(g_reason, "requested"), "[basic] reason=%s", g_reason);
    CHECK(g_pid > 0 && strstr(g_out_path, "/.todoforai/tasks/") && exists(g_in_path), "[basic] pid=%ld out=%s", g_pid, g_out_path);
    CHECK(pump_until(e, exited, 5000), "[basic] no task_exit");
    CHECK(!g_exit_null && g_exit_code == 3 && !g_killed, "[basic] exit=%ld null=%d killed=%d", g_exit_code, g_exit_null, g_killed);
    CHECK(strstr(g_tail, "start") && strstr(g_tail, "end") && !strstr(g_tail, "__BRIDGE"), "[basic] tail=%s", g_tail);
    CHECK(file_has(g_out_path, "end") && !exists(g_in_path), "[basic] files: out has end=%d input exists=%d", file_has(g_out_path, "end"), exists(g_in_path));
    CHECK(pump_until(e, no_active, 3000), "[basic] one-shot session not freed");
    fprintf(stderr, "[basic] done\n");

    // 2. .input feeds the PTY; probe reports awaiting input as TASK_STATE.
    reset();
    send_run(e, "printf 'name? '; read -r x; echo got:$x", ",\"background\":true");
#ifndef _WIN32   // ConPTY has no blocked-on-stdin signal: no TASK_STATE there
    CHECK(pump_until(e, state_on, 3000), "[input] no task_state awaitingInput:true");
#endif
    // Another process appends (Windows: must not hit a sharing violation).
    char ap[700]; snprintf(ap, sizeof ap, "echo hello>> \"%s\"", g_in_path);
    CHECK(system(ap) == 0, "[input] external append failed");
    CHECK(pump_until(e, exited, 5000), "[input] no task_exit");
    CHECK(strstr(g_tail, "got:hello") != NULL, "[input] tail=%s", g_tail);
#ifndef _WIN32
    CHECK(g_state_off >= 1, "[input] no task_state awaitingInput:false after input (off=%d)", g_state_off);
#endif
    pump_until(e, no_active, 3000);
    fprintf(stderr, "[input] done\n");

    // 3. backgroundOnPark: the deadline converts the step in place.
    reset();
    send_run(e, "echo before; sleep 0.8; echo after", ",\"backgroundOnPark\":true,\"timeoutMs\":300");
    CHECK(pump_until(e, bg_seen, 2000), "[park] no step_background");
    CHECK(!strcmp(g_reason, "timeout") && g_done == 0, "[park] reason=%s done=%d", g_reason, g_done);
    CHECK(pump_until(e, exited, 3000), "[park] no task_exit");
    CHECK(g_exit_code == 0 && strstr(g_tail, "after"), "[park] exit=%ld tail=%s", g_exit_code, g_tail);
    // The file is the whole log: what ran before the handoff too.
    CHECK(file_has(g_out_path, "before") && file_has(g_out_path, "after"), "[park] file lacks pre-handoff output");
    pump_until(e, no_active, 3000);
    fprintf(stderr, "[park] done\n");

    // 4. noInput + backgroundOnPark still becomes a task (not a timed-out settle).
    reset();
    send_run(e, "sleep 0.6; echo late", ",\"backgroundOnPark\":true,\"noInput\":true,\"timeoutMs\":200");
    CHECK(pump_until(e, bg_seen, 2000) && g_done == 0, "[noinput] bg=%d done=%d", g_bg, g_done);
    CHECK(pump_until(e, exited, 3000) && strstr(g_tail, "late"), "[noinput] tail=%s", g_tail);
    pump_until(e, no_active, 3000);

    // 5. TASK_LIST + TASK_KILL (^C ends sleep).
    reset();
    send_run(e, "sleep 30", ",\"background\":true,\"chatMessageId\":\"m-1\",\"chatBlockId\":\"b-1\"");
    settle(e, 300);
    char f[256]; int n = snprintf(f, sizeof f, "{\"type\":\"task_list\",\"requestId\":\"r1\"}");
    handle_command(e, f, (size_t)n);
    char want[48]; snprintf(want, sizeof want, "\"pid\":%ld", g_pid);
    CHECK(g_list == 1 && strstr(g_list_json, want), "[kill] task_list=%s", g_list_json);
    // A stale or malformed startedAt (pid reused by a later task) must not kill this one.
    const char *sa = strstr(g_list_json, "\"startedAt\":");
    long long started = sa ? strtoll(sa + 12, NULL, 10) : 0;
    CHECK(started > 0xFFFFFFFFLL, "[kill] startedAt not epoch ms: %lld", started);
    const char *bad[] = { "1", "\"x\"", "null", "%lld.5", "%llde1", "99999999999999999999999" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char v[64]; snprintf(v, sizeof v, bad[i], started);
        g_err_code[0] = 0;
        n = snprintf(f, sizeof f, "{\"type\":\"task_kill\",\"pid\":%ld,\"startedAt\":%s,\"requestId\":\"k%zu\"}", g_pid, v, i);
        handle_command(e, f, (size_t)n);
        CHECK(!strcmp(g_err_code, "TASK_NOT_FOUND"), "[kill] startedAt=%s: error=%s", v, g_err_code);
    }
    CHECK(!pump_until(e, exited, 500), "[kill] stale startedAt killed the task");
    n = snprintf(f, sizeof f, "{\"type\":\"task_kill\",\"pid\":%ld,\"startedAt\":%lld}", g_pid, started);
    handle_command(e, f, (size_t)n);
    CHECK(pump_until(e, exited, BG_KILL_GRACE_MS - 500), "[kill] no task_exit after ^C (escalation would be 3 s)");
    CHECK(g_killed, "[kill] killed flag missing");
    CHECK(strstr(g_bg_json, "\"chatMessageId\":\"m-1\",\"chatBlockId\":\"b-1\"") &&
          strstr(g_list_json, "\"chatMessageId\":\"m-1\",\"chatBlockId\":\"b-1\"") &&
          strstr(g_exit_json, "\"chatBlockId\":\"b-1\""), "[kill] chat pair bg=%s list=%s exit=%s", g_bg_json, g_list_json, g_exit_json);
    pump_until(e, no_active, 3000);

    // 6. TASK_KILL escalates when ^C is ignored.
    reset();
    send_run(e, "trap '' INT; sleep 30", ",\"background\":true");
    settle(e, 300);  // let the trap install
    n = snprintf(f, sizeof f, "{\"type\":\"task_kill\",\"pid\":%ld}", g_pid);
    handle_command(e, f, (size_t)n);
    CHECK(pump_until(e, exited, BG_KILL_GRACE_MS + 2000), "[kill9] no task_exit after escalation");
    CHECK(g_killed, "[kill9] killed flag");
    CHECK(!strstr(g_exit_json, "chatBlockId"), "[kill9] chat pair leaked from previous run: %s", g_exit_json);
    CHECK(pump_until(e, no_active, 3000), "[kill9] session not freed");

    // 6b. ^C-immune child under a ^C-immune shell: escalation kills the group,
    //     no orphan keeps running.
    reset();
    send_run(e, "trap '' INT; (trap '' INT HUP; sleep 31; echo orphan) ; echo shell-after", ",\"background\":true");
    settle(e, 300);
    n = snprintf(f, sizeof f, "{\"type\":\"task_kill\",\"pid\":%ld}", g_pid);
    handle_command(e, f, (size_t)n);
    CHECK(pump_until(e, exited, BG_KILL_GRACE_MS + 2000), "[tree] no task_exit");
    pump_until(e, no_active, 3000);
#ifndef _WIN32   // Windows: TerminateJobObject owns the tree
    FILE *pg = popen("pgrep -fx 'sleep 31' | wc -l", "r");
    int left = -1; if (pg) { if (fscanf(pg, "%d", &left) != 1) left = -1; pclose(pg); }
    CHECK(left == 0, "[tree] %d 'sleep 31' survivors", left);
#endif

    // 6c. Input written before the task reads stdin is delivered later, intact.
    reset();
    send_run(e, "sleep 0.5; read -r a; read -r b; echo got:$a:$b", ",\"background\":true");
    append(g_in_path, "one\ntwo\n");
    CHECK(pump_until(e, exited, 4000) && strstr(g_tail, "got:one:two"), "[early-input] tail=%s", g_tail);
    pump_until(e, no_active, 3000);

    // 6d. `| tail -N` is not cut for a background run: the file is the whole log.
    reset();
    send_run(e, "seq 1 50 | tail -2", ",\"background\":true");
    CHECK(pump_until(e, exited, 3000) && file_has(g_out_path, "49") && !strstr(g_tail, "\n1\n") && !file_has(g_out_path, "\n10\n"),
          "[tail] pipeline not literal: %s", g_tail);
    pump_until(e, no_active, 3000);

    // 6e. Native python: TASK_KILL's ^C ends it without escalation.
    reset();
    send_run(e, "py=$(command -v python || command -v python3) || exit 77; \"$py\" -c 'import time; print(\"up\", flush=True); time.sleep(30)'", ",\"background\":true");
    settle(e, 1500);
    if (!g_exit) {
        n = snprintf(f, sizeof f, "{\"type\":\"task_kill\",\"pid\":%ld}", g_pid);
        handle_command(e, f, (size_t)n);
        CHECK(pump_until(e, exited, BG_KILL_GRACE_MS - 500), "[python] ^C did not end python (escalation would be 3 s)");
        // 130 = ^C, not the escalation's 9. The traceback text itself may land
        // after the result line: SIGINT also kills the wrapper subshell, which
        // can report before python finishes printing (wrapper-wide race).
        CHECK(g_exit_code == 130 && strstr(g_tail, "up"), "[python] exit=%ld tail=%s", g_exit_code, g_tail);
    } else fprintf(stderr, "[python] skipped (exit %ld)\n", g_exit_code);
    pump_until(e, no_active, 3000);

    // 6f. Persistent sessions cannot host tasks (pid would be reused).
    reset();
    {
        int errs0 = 0;
        char fr[512];
        int fn = snprintf(fr, sizeof fr, "{\"type\":\"run\",\"blockId\":\"p1\",\"cmdB64\":\"ZWNobyBo\",\"sessionId\":\"00000000-0000-4000-8000-000000000000\",\"background\":true}");
        handle_command(e, fr, (size_t)fn);
        (void)errs0;
        CHECK(g_bg == 0 && active_sessions(e) == 0, "[persistent] background on a sessionId was accepted");
    }

    // 6g. Probe handoff reports awaitingInput in STEP_BACKGROUND itself.
#ifndef _WIN32
    reset();
    send_run(e, "printf 'Continue? '; read -r x; echo ok", ",\"backgroundOnPark\":true");
    CHECK(pump_until(e, bg_seen, 3000) && !strcmp(g_reason, "probe") && g_bg_awaiting, "[probe] reason=%s awaiting=%d", g_reason, g_bg_awaiting);
    n = snprintf(f, sizeof f, "{\"type\":\"task_kill\",\"pid\":%ld}", g_pid);
    handle_command(e, f, (size_t)n);
    pump_until(e, exited, 2000);
    pump_until(e, no_active, 3000);
#endif

    // 7. Plain foreground runs are untouched.
    reset();
    send_run(e, "echo fg", "");
    pump_until(e, no_active, 3000);
    CHECK(g_done == 1 && g_bg == 0 && g_exit == 0, "[fg] done=%d bg=%d exit=%d", g_done, g_bg, g_exit);

#ifndef _WIN32
    char cmd[600]; snprintf(cmd, sizeof cmd, "rm -rf %s", home); (void)!system(cmd);
#endif
    fprintf(stderr, fails ? "test-bg: %d FAILED\n" : "test-bg: all passed\n", fails);
    return fails ? 1 : 0;
}

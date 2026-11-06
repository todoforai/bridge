// Background task files — see bg_task.h.
#include "bg_task.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <dirent.h>
#  include <fcntl.h>
#  include <pwd.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

// <home>/.todoforai/tasks with forward slashes; created (0700) if missing.
static int tasks_dir(char *buf, size_t cap) {
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
#else
    const char *home = getenv("HOME");
    if (!home || !*home) { struct passwd *pw = getpwuid(getuid()); home = pw ? pw->pw_dir : NULL; }
#endif
    if (!home || !*home) { errno = ENOENT; return -1; }
    int n = snprintf(buf, cap, "%s/.todoforai/tasks", home);
    if (n < 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return -1; }
#ifdef _WIN32
    for (char *p = buf; *p; p++) if (*p == '\\') *p = '/';
    char parent[BG_PATH_CAP];
    snprintf(parent, sizeof parent, "%s/.todoforai", home);
    CreateDirectoryA(parent, NULL);
    if (!CreateDirectoryA(buf, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { errno = EACCES; return -1; }
#else
    char parent[BG_PATH_CAP];
    snprintf(parent, sizeof parent, "%s/.todoforai", home);
    mkdir(parent, 0700);
    if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
#endif
    return n;
}

int64_t bg_wall_ms(void) {
#ifdef _WIN32
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return (int64_t)(u.QuadPart / 10000ULL) - 11644473600000LL;
#else
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

#ifdef _WIN32
#  define BG_SHARE (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
static HANDLE win_open(const char *path, DWORD access, DWORD disp) {
    return CreateFileA(path, access, BG_SHARE, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
}
#endif

int bg_task_open(bg_task_t *t, long pid) {
    memset(t, 0, sizeof *t);
    char dir[BG_PATH_CAP - 32];
    if (tasks_dir(dir, sizeof dir) < 0) return -1;
    snprintf(t->out_path, sizeof t->out_path, "%s/%ld.output", dir, pid);
    snprintf(t->in_path,  sizeof t->in_path,  "%s/%ld.input",  dir, pid);
    // Truncate on create: a dead task with a recycled pid may have left a pair.
#ifdef _WIN32
    HANDLE in = win_open(t->in_path, GENERIC_WRITE, CREATE_ALWAYS);
    if (in == INVALID_HANDLE_VALUE) { errno = EACCES; return -1; }
    CloseHandle(in);
    HANDLE h = win_open(t->out_path, GENERIC_WRITE, CREATE_ALWAYS);
    if (h == INVALID_HANDLE_VALUE) { DeleteFileA(t->in_path); errno = EACCES; return -1; }
    t->h = (intptr_t)h;
#else
    int in = open(t->in_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (in < 0) return -1;
    close(in);
    int fd = open(t->out_path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { int er = errno; unlink(t->in_path); errno = er; return -1; }
    t->h = fd;
#endif
    t->open = 1;
    return 0;
}

// Restart the file at the cap: `tail -f` follows a truncation, and the end
// of the file — what anyone reads — stays current for a never-ending server.
static void out_restart(bg_task_t *t) {
    static const char note[] = "[bridge: output exceeded 50 MB; earlier output discarded]\n";
#ifdef _WIN32
    HANDLE h = (HANDLE)t->h;
    LARGE_INTEGER z; z.QuadPart = 0;
    SetFilePointerEx(h, z, NULL, FILE_BEGIN);
    SetEndOfFile(h);
    DWORD w; WriteFile(h, note, sizeof note - 1, &w, NULL);
#else
    if (ftruncate((int)t->h, 0) != 0) return;
    ssize_t w = write((int)t->h, note, sizeof note - 1); (void)w;
#endif
    t->out_len = sizeof note - 1;
}

void bg_task_write(bg_task_t *t, const void *data, size_t len) {
    if (!t->open || len == 0) return;
    if (t->out_len + (long long)len > BG_OUT_CAP) out_restart(t);
#ifdef _WIN32
    HANDLE h = (HANDLE)t->h;
    LARGE_INTEGER z; z.QuadPart = 0;
    SetFilePointerEx(h, z, NULL, FILE_END);
    DWORD w = 0;
    if (WriteFile(h, data, (DWORD)len, &w, NULL)) t->out_len += w;
#else
    ssize_t w = write((int)t->h, data, len);
    if (w > 0) t->out_len += w;
#endif
}

long bg_task_peek_input(bg_task_t *t, void *buf, size_t cap) {
    if (!t->open || cap == 0) return 0;
    // Open per tick: holding .input would block a Windows writer's delete and
    // keep a stale inode on POSIX if someone replaced the file.
#ifdef _WIN32
    HANDLE h = win_open(t->in_path, GENERIC_READ, OPEN_EXISTING);
    if (h == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz;
    long r = 0;
    if (GetFileSizeEx(h, &sz)) {
        if (sz.QuadPart < t->in_off) t->in_off = 0;
        if (sz.QuadPart > t->in_off) {
            LARGE_INTEGER off; off.QuadPart = t->in_off;
            DWORD got = 0;
            if (SetFilePointerEx(h, off, NULL, FILE_BEGIN) && ReadFile(h, buf, (DWORD)cap, &got, NULL)) r = (long)got;
        }
    }
    CloseHandle(h);
#else
    int fd = open(t->in_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return 0;
    struct stat st;
    long r = 0;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        if (st.st_size < t->in_off) t->in_off = 0;
        if (st.st_size > t->in_off) {
            ssize_t got = pread(fd, buf, cap, (off_t)t->in_off);
            if (got > 0) r = (long)got;
        }
    }
    close(fd);
#endif
    return r;
}

size_t bg_task_tail(const bg_task_t *t, char *buf, size_t cap) {
    if (!t->out_path[0] || cap == 0) return 0;
    FILE *f = fopen(t->out_path, "rb");
    if (!f) return 0;
    size_t n = 0;
    if (fseek(f, 0, SEEK_END) == 0) {
        long sz = ftell(f);
        long from = sz > (long)cap ? sz - (long)cap : 0;
        if (sz > 0 && fseek(f, from, SEEK_SET) == 0) n = fread(buf, 1, cap, f);
    }
    fclose(f);
    // Skip UTF-8 continuation bytes a byte cut may have left at the start.
    size_t s = 0;
    while (s < n && s < 4 && ((unsigned char)buf[s] & 0xC0) == 0x80) s++;
    if (s) memmove(buf, buf + s, n - s);
    return n - s;
}

void bg_task_close(bg_task_t *t) {
    if (!t->open) return;
#ifdef _WIN32
    CloseHandle((HANDLE)t->h);
    DeleteFileA(t->in_path);
#else
    close((int)t->h);
    unlink(t->in_path);
#endif
    t->open = 0;
}

static int is_task_file(const char *name) {
    const char *dot = strrchr(name, '.');
    return dot && (strcmp(dot, ".output") == 0 || strcmp(dot, ".input") == 0);
}

void bg_task_reap_old(void) {
    char dir[BG_PATH_CAP - 64];
    if (tasks_dir(dir, sizeof dir) < 0) return;   // also creates it for the jail grant
    int64_t cutoff = bg_wall_ms() - BG_REAP_AGE_MS;
    char path[BG_PATH_CAP + 260];
#ifdef _WIN32
    char pat[BG_PATH_CAP];
    snprintf(pat, sizeof pat, "%s/*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!is_task_file(fd.cFileName)) continue;
        ULARGE_INTEGER u; u.LowPart = fd.ftLastWriteTime.dwLowDateTime; u.HighPart = fd.ftLastWriteTime.dwHighDateTime;
        int64_t mt = (int64_t)(u.QuadPart / 10000ULL) - 11644473600000LL;
        if (mt >= cutoff) continue;
        snprintf(path, sizeof path, "%s/%s", dir, fd.cFileName);
        DeleteFileA(path);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!is_task_file(de->d_name)) continue;
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if ((int64_t)st.st_mtime * 1000 >= cutoff) continue;
        unlink(path);
    }
    closedir(d);
#endif
}

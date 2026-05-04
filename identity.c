#define _POSIX_C_SOURCE 200809L
#include "identity.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

// Read first matching `KEY=value` line from a small text file. Strips surrounding
// quotes. Returns 0 on found, -1 otherwise. Caller-owned `out` is NUL-terminated.
static int read_kv(const char *path, const char *key, char *out, size_t out_cap) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    size_t klen = strlen(key);
    int found = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) != 0 || line[klen] != '=') continue;
        const char *v = line + klen + 1;
        // Strip newline + surrounding quotes directly into out (size-aware).
        size_t oi = 0;
        for (const char *p = v; *p && *p != '\n' && *p != '\r' && oi + 1 < out_cap; p++) {
            if (*p == '"') continue;
            out[oi++] = *p;
        }
        out[oi] = '\0';
        found = 0;
        break;
    }
    fclose(f);
    return found;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

// Detect SANDBOX-ness from the host. Two signals (any one suffices):
//   1. Marker file dropped into the rootfs at build time.
//   2. Firecracker DMI product name (Linux, when DMI is exposed).
static int is_sandbox(void) {
    if (file_exists("/etc/todoforai-sandbox")) return 1;
    char buf[64] = {0};
    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            // strip trailing whitespace
            size_t n = strlen(buf);
            while (n && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' ')) buf[--n] = '\0';
        }
        fclose(f);
        if (strcasecmp(buf, "Firecracker") == 0) return 1;
    }
    return 0;
}

// Best-effort: fill distro + distro_version from OS-specific sources.
// Linux:   /etc/os-release (ID, VERSION_ID)
// macOS:   sw_vers via popen (ProductName, ProductVersion) — small and standard
// Windows builds aren't supported here yet; leaves empty strings.
static void detect_distro(const char *os_sysname, char *distro, size_t dcap, char *ver, size_t vcap) {
    distro[0] = ver[0] = '\0';
    if (strcasecmp(os_sysname, "Linux") == 0) {
        if (read_kv("/etc/os-release", "ID", distro, dcap) < 0) {
            snprintf(distro, dcap, "linux");
        }
        read_kv("/etc/os-release", "VERSION_ID", ver, vcap);
    } else if (strcasecmp(os_sysname, "Darwin") == 0) {
        snprintf(distro, dcap, "macos");
        FILE *p = popen("sw_vers -productVersion 2>/dev/null", "r");
        if (p) {
            if (fgets(ver, (int)vcap, p)) {
                size_t n = strlen(ver);
                while (n && (ver[n-1] == '\n' || ver[n-1] == '\r')) ver[--n] = '\0';
            }
            pclose(p);
        }
    }
}

// Map host info to a DeviceType enum value the backend understands.
// Only the bridge itself enrolls via this code path → the answer is PC, SANDBOX,
// or (defensively) UNKNOWN. Other device types come from other binaries.
static void detect_device_type(const char *os_sysname, char *out, size_t cap) {
    if (is_sandbox()) {
        snprintf(out, cap, "SANDBOX");
        return;
    }
    if (strcasecmp(os_sysname, "Linux")  == 0 ||
        strcasecmp(os_sysname, "Darwin") == 0) {
        snprintf(out, cap, "PC");
        return;
    }
    // MSYS/Cygwin/MinGW report "MINGW64_NT-…", "CYGWIN_NT-…" — treat as PC.
    if (strncasecmp(os_sysname, "MINGW",  5) == 0 ||
        strncasecmp(os_sysname, "MSYS",   4) == 0 ||
        strncasecmp(os_sysname, "CYGWIN", 6) == 0 ||
        strncasecmp(os_sysname, "Windows", 7) == 0) {
        snprintf(out, cap, "PC");
        return;
    }
    snprintf(out, cap, "UNKNOWN");
}

void bridge_identity_gather(bridge_identity_t *id) {
    memset(id, 0, sizeof(*id));

    struct utsname un;
    if (uname(&un) == 0) {
        snprintf(id->os,       sizeof(id->os),       "%s", un.sysname);
        snprintf(id->arch,     sizeof(id->arch),     "%s", un.machine);
        snprintf(id->hostname, sizeof(id->hostname), "%s", un.nodename);
        snprintf(id->kernel,   sizeof(id->kernel),   "%s", un.release);
    } else {
        snprintf(id->os,       sizeof(id->os),       "unknown");
        snprintf(id->arch,     sizeof(id->arch),     "unknown");
        snprintf(id->hostname, sizeof(id->hostname), "unknown");
        snprintf(id->kernel,   sizeof(id->kernel),   "unknown");
    }

    detect_distro(id->os, id->distro, sizeof(id->distro), id->distro_version, sizeof(id->distro_version));
    detect_device_type(id->os, id->device_type, sizeof(id->device_type));

    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        snprintf(id->user,  sizeof(id->user),  "%s", pw->pw_name ? pw->pw_name : "unknown");
        snprintf(id->shell, sizeof(id->shell), "%s", pw->pw_shell ? pw->pw_shell : "/bin/sh");
        snprintf(id->home,  sizeof(id->home),  "%s", pw->pw_dir ? pw->pw_dir : "/");
    } else {
        snprintf(id->user,  sizeof(id->user),  "unknown");
        snprintf(id->shell, sizeof(id->shell), "/bin/sh");
        snprintf(id->home,  sizeof(id->home),  "/");
    }

    if (!getcwd(id->cwd, sizeof(id->cwd))) {
        snprintf(id->cwd, sizeof(id->cwd), "/");
    }
}

// Append a JSON-escaped string (no surrounding quotes). Returns 0/-1 on overflow.
static int append_escaped(char *out, size_t cap, size_t *used, const char *s) {
    size_t o = *used;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *esc = NULL;
        char buf[8];
        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            default:
                if (c < 0x20) { snprintf(buf, sizeof(buf), "\\u%04x", c); esc = buf; }
                break;
        }
        if (esc) {
            size_t el = strlen(esc);
            if (o + el >= cap) return -1;
            memcpy(out + o, esc, el); o += el;
        } else {
            if (o + 1 >= cap) return -1;
            out[o++] = (char)c;
        }
    }
    *used = o;
    return 0;
}

int bridge_identity_json(char *out, size_t out_cap, int top_level) {
    bridge_identity_t id;
    bridge_identity_gather(&id);

    size_t u = 0;
    #define LIT(s) do { size_t _l = sizeof(s) - 1; \
        if (u + _l >= out_cap) return -1; \
        memcpy(out + u, (s), _l); u += _l; } while (0)
    #define FIELD(key, val) do { LIT("\"" key "\":\""); \
        if (append_escaped(out, out_cap, &u, (val)) != 0) return -1; \
        LIT("\""); } while (0)

    LIT("{");
    if (!top_level) LIT("\"type\":\"identity\",\"data\":{");

    LIT("\"edge_version\":\"" BRIDGE_VERSION "\",");
    FIELD("os",             id.os);             LIT(",");
    FIELD("arch",           id.arch);           LIT(",");
    FIELD("hostname",       id.hostname);       LIT(",");
    FIELD("kernel",         id.kernel);         LIT(",");
    FIELD("distro",         id.distro);         LIT(",");
    FIELD("distro_version", id.distro_version); LIT(",");
    FIELD("deviceType",     id.device_type);    LIT(",");
    FIELD("user",           id.user);           LIT(",");
    FIELD("shell",          id.shell);          LIT(",");
    FIELD("home",           id.home);           LIT(",");
    FIELD("cwd",            id.cwd);

    if (!top_level) LIT("}");
    LIT("}");
    if (u >= out_cap) return -1;
    out[u] = '\0';
    return (int)u;
    #undef FIELD
    #undef LIT
}

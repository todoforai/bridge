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

#include "mongoose.h"

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

    // Sanitize all fields: replace control bytes with space. mg_print_esc
    // only escapes \b\f\n\r\t\\\"; raw 0x00–0x1f would produce invalid JSON.
    char *fields[] = { id->os, id->arch, id->hostname, id->kernel, id->distro,
                       id->distro_version, id->device_type, id->user,
                       id->shell, id->home, id->cwd };
    for (size_t f = 0; f < sizeof(fields)/sizeof(fields[0]); f++) {
        for (char *p = fields[f]; *p; p++) {
            if ((unsigned char)*p < 0x20) *p = ' ';
        }
    }
}

int bridge_identity_json(char *out, size_t out_cap, int top_level) {
    bridge_identity_t id;
    bridge_identity_gather(&id);

    // mg_snprintf %m + MG_ESC handles JSON escaping for free.
    // Two near-identical formats — only the outer wrapper differs.
    #define IDENTITY_FIELDS \
        MG_ESC("edge_version"),   MG_ESC(BRIDGE_VERSION), \
        MG_ESC("os"),             MG_ESC(id.os), \
        MG_ESC("arch"),           MG_ESC(id.arch), \
        MG_ESC("hostname"),       MG_ESC(id.hostname), \
        MG_ESC("kernel"),         MG_ESC(id.kernel), \
        MG_ESC("distro"),         MG_ESC(id.distro), \
        MG_ESC("distro_version"), MG_ESC(id.distro_version), \
        MG_ESC("deviceType"),     MG_ESC(id.device_type), \
        MG_ESC("user"),           MG_ESC(id.user), \
        MG_ESC("shell"),          MG_ESC(id.shell), \
        MG_ESC("home"),           MG_ESC(id.home), \
        MG_ESC("cwd"),            MG_ESC(id.cwd)
    #define INNER "{%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m}"

    size_t n = top_level
        ? mg_snprintf(out, out_cap, INNER, IDENTITY_FIELDS)
        : mg_snprintf(out, out_cap, "{%m:%m,%m:" INNER "}",
                      MG_ESC("type"), MG_ESC("identity"), MG_ESC("data"),
                      IDENTITY_FIELDS);

    #undef INNER
    #undef IDENTITY_FIELDS
    return (n > 0 && n < out_cap) ? (int)n : -1;
}

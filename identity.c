#define _POSIX_C_SOURCE 200809L
#include "identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <lmcons.h>      // UNLEN
#  include <direct.h>      // _getcwd
#  define strcasecmp  _stricmp
#  define strncasecmp _strnicmp
#else
#  include <pwd.h>
#  include <strings.h>
#  include <sys/utsname.h>
#  include <unistd.h>
#endif

#include "json.h"

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
    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    if (f) {
        char buf[64] = {0};
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

#ifdef _WIN32
    snprintf(id->os, sizeof(id->os), "Windows");
    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    const char *arch = "unknown";
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "x86_64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: arch = "aarch64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "i686"; break;
    }
    snprintf(id->arch, sizeof(id->arch), "%s", arch);

    DWORD hn = sizeof(id->hostname);
    if (!GetComputerNameExA(ComputerNameDnsHostname, id->hostname, &hn))
        snprintf(id->hostname, sizeof(id->hostname), "unknown");

    // RtlGetVersion gives the actual OS version (GetVersionEx lies post-Win8.1).
    typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOEXW *);
    OSVERSIONINFOEXW vi = { .dwOSVersionInfoSize = sizeof(vi) };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    RtlGetVersion_t fn = ntdll ? (RtlGetVersion_t)(void*)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    if (fn && fn(&vi) == 0) {
        snprintf(id->kernel, sizeof(id->kernel), "%lu.%lu.%lu",
                 (unsigned long)vi.dwMajorVersion,
                 (unsigned long)vi.dwMinorVersion,
                 (unsigned long)vi.dwBuildNumber);
        snprintf(id->distro, sizeof(id->distro), "windows");
        snprintf(id->distro_version, sizeof(id->distro_version), "%lu.%lu.%lu",
                 (unsigned long)vi.dwMajorVersion,
                 (unsigned long)vi.dwMinorVersion,
                 (unsigned long)vi.dwBuildNumber);
    } else {
        snprintf(id->kernel, sizeof(id->kernel), "unknown");
        snprintf(id->distro, sizeof(id->distro), "windows");
    }

    snprintf(id->device_type, sizeof(id->device_type), "PC");

    char ubuf[UNLEN + 1]; DWORD ulen = sizeof(ubuf);
    if (GetUserNameA(ubuf, &ulen)) snprintf(id->user, sizeof(id->user), "%s", ubuf);
    else                           snprintf(id->user, sizeof(id->user), "unknown");

    const char *home = getenv("USERPROFILE");
    snprintf(id->home, sizeof(id->home), "%s", home ? home : "C:\\");

    const char *sh = getenv("BRIDGE_SHELL");
    if (!sh) sh = getenv("SHELL");
    snprintf(id->shell, sizeof(id->shell), "%s", sh ? sh : "bash.exe");

    if (!_getcwd(id->cwd, sizeof(id->cwd)))
        snprintf(id->cwd, sizeof(id->cwd), "C:\\");
#else
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
#endif

    // Sanitize all fields: replace control bytes with space — keeps the
    // resulting JSON identifiers ASCII-clean even if a hostname/distro field
    // accidentally contains a stray byte.
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

    size_t u = 0;
    if (!top_level) {
        if (json_emit_raw(out, out_cap, &u, "{", 1) < 0) return -1;
        if (json_emit_str(out, out_cap, &u, "type", -1) < 0) return -1;
        if (json_emit_raw(out, out_cap, &u, ":", 1) < 0) return -1;
        if (json_emit_str(out, out_cap, &u, "identity", -1) < 0) return -1;
        if (json_emit_raw(out, out_cap, &u, ",", 1) < 0) return -1;
        if (json_emit_str(out, out_cap, &u, "data", -1) < 0) return -1;
        if (json_emit_raw(out, out_cap, &u, ":", 1) < 0) return -1;
    }

    #define KV(k, v) do { \
        if (json_emit_raw(out, out_cap, &u, sep, 1) < 0) return -1; \
        if (json_emit_str(out, out_cap, &u, (k), -1) < 0) return -1; \
        if (json_emit_raw(out, out_cap, &u, ":", 1) < 0) return -1; \
        if (json_emit_str(out, out_cap, &u, (v), -1) < 0) return -1; \
        sep = ","; \
    } while (0)

    const char *sep = "{";
    KV("edge_version",   BRIDGE_VERSION);
    KV("os",             id.os);
    KV("arch",           id.arch);
    KV("hostname",       id.hostname);
    KV("kernel",         id.kernel);
    KV("distro",         id.distro);
    KV("distro_version", id.distro_version);
    KV("deviceType",     id.device_type);
    KV("user",           id.user);
    KV("shell",          id.shell);
    KV("home",           id.home);
    KV("cwd",            id.cwd);
    if (json_emit_raw(out, out_cap, &u, "}", 1) < 0) return -1;

    if (!top_level && json_emit_raw(out, out_cap, &u, "}", 1) < 0) return -1;
    if (u + 1 >= out_cap) return -1;
    out[u] = '\0';
    #undef KV
    return (int)u;
}

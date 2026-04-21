#define _POSIX_C_SOURCE 200809L
#include "identity.h"

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

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

int bridge_identity_json(char *out, size_t out_cap) {
    bridge_identity_t id;
    bridge_identity_gather(&id);

    int n = snprintf(out, out_cap,
        "{\"type\":\"identity\",\"data\":{"
        "\"edge_version\":\"%s\","
        "\"os\":\"%s\","
        "\"arch\":\"%s\","
        "\"hostname\":\"%s\","
        "\"kernel\":\"%s\","
        "\"user\":\"%s\","
        "\"shell\":\"%s\","
        "\"home\":\"%s\","
        "\"cwd\":\"%s\"}}",
        BRIDGE_VERSION, id.os, id.arch, id.hostname, id.kernel,
        id.user, id.shell, id.home, id.cwd);

    if (n < 0 || (size_t)n >= out_cap) return -1;
    return n;
}

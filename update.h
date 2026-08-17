// Self-update: re-run the official installer over our own install dir, then
// exit so the supervisor (systemd, launchd) restarts us on the new binary.
// The binary is never patched in place — install.sh already does the download,
// sha256 verify and atomic replace it does for a fresh install, and the
// restart IS the apply step.
#ifndef BRIDGE_UPDATE_H
#define BRIDGE_UPDATE_H

// `todoforai-bridge update`. 0 on success.
int cmd_update(int argc, char **argv);

// Download + install the latest release over our own prefix. Returns 0 on
// success, and the caller must then exit so the supervisor restarts us.
int bridge_update_apply(void);

// 1 if `latest` is a newer release than the running build and applying it
// unattended is safe here (release build, supervised, POSIX, not opted out).
int bridge_update_wanted(const char *latest);

#endif

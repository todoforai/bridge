// CLI subcommands: login / enroll / whoami / help.
// Separated from main.c so the daemon hot path stays focused.
#ifndef BRIDGE_SUBCMD_H
#define BRIDGE_SUBCMD_H

extern const char *USAGE_MAIN;

// cmd_login returns CMD_RC_HELP (not 0) when `-h/--help` was handled, so
// main() can distinguish "help printed → done" from "logged in → run daemon".
// Other cmd_* functions terminate main directly via `return cmd_*(...)`, so
// they don't need this distinction.
enum { CMD_RC_HELP = 2 };

int  cmd_login(int argc, char **argv);
// Run the login flow with already-resolved overrides (no argv parsing).
// device_name/token/host/port_s/pub_hex may be NULL.
int  bridge_login_run(const char *device_name, const char *token,
                      const char *host, const char *port_s, const char *pub_hex);
int  cmd_logout(int argc, char **argv);
int  cmd_enroll(int argc, char **argv);
int  cmd_whoami(int argc, char **argv);
void print_help(void);

#endif

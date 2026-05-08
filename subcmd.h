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
int  cmd_logout(int argc, char **argv);
int  cmd_enroll(int argc, char **argv);
int  cmd_whoami(int argc, char **argv);
void print_help(void);

#endif

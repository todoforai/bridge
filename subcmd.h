// CLI subcommands: login / logout / enroll / whoami / help.
#ifndef BRIDGE_SUBCMD_H
#define BRIDGE_SUBCMD_H

extern const char *USAGE_MAIN;

// cmd_login returns CMD_RC_HELP on `-h/--help` so main() can skip the daemon.
enum { CMD_RC_HELP = 2 };

int  cmd_login(int argc, char **argv);
// NULL args fall through to env / saved-creds / defaults.
int  bridge_login_run(const char *device_name, const char *token,
                      const char *host, const char *port_s);
int  cmd_logout(int argc, char **argv);
int  cmd_enroll(int argc, char **argv);
int  cmd_whoami(int argc, char **argv);
void print_help(void);

#endif

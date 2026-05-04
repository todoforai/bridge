// CLI subcommands: login / enroll / whoami / help.
// Separated from main.c so the daemon hot path stays focused.
#ifndef BRIDGE_SUBCMD_H
#define BRIDGE_SUBCMD_H

extern const char *USAGE_MAIN;

int  cmd_login(int argc, char **argv);
int  cmd_enroll(int argc, char **argv);
int  cmd_whoami(int argc, char **argv);
void print_help(void);

#endif

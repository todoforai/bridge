// Reproduces the bridge's one-shot RUN teardown in isolation, so we can measure
// what it does to deliberately-backgrounded children.
//
// The sequence mirrors main.c:run_finish() exactly:
//   forkpty() a /bin/sh  -> SIGKILL the shell -> close the master fd
// which is also what makes the shell a session leader owning the controlling
// terminal, the detail that decides whether `cmd &` children get SIGHUP'd.
//
// Build: gcc -o ptykill pty_teardown_probe.c -lutil
// Usage: ./ptykill '<shell command>'
#define _GNU_SOURCE
#include <pty.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s '<cmd>'\n", argv[0]); return 2; }
    const char *cmd = argv[1];

    int master;
    pid_t pid = forkpty(&master, NULL, NULL, NULL);
    if (pid < 0) { perror("forkpty"); return 1; }
    if (pid == 0) {
        setenv("PS1", "", 1);
        execl("/bin/sh", "sh", (char *)NULL);
        _exit(127);
    }

    dprintf(master, "%s\n", cmd);
    sleep(2);                                   // let the shell start the child
    char buf[4096];
    ssize_t r = read(master, buf, sizeof buf);  // drain, mirrors the event loop
    (void)r;

    kill(pid, SIGKILL);   // run_finish(): bridge_pty_signal(SIGKILL)
    close(master);        // run_finish(): bridge_pty_close()
    waitpid(pid, NULL, 0);
    return 0;
}

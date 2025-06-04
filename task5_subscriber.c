#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void handler(int sig, siginfo_t *info, void *ctx) {
    printf("Received %d from PID %d with value %d\n", sig, info->si_pid, info->si_value.sival_int);
}

int main() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN, &sa, NULL);
    printf("Subscriber PID: %d\n", getpid());
    while (1) pause();

    return 0;
}

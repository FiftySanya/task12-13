#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handler(int sig, siginfo_t *info, void *ucontext) {
    printf("Caught signal %d\n", sig);
    printf("Fault address: %p\n", info->si_addr);
    exit(1);
}

int main() {
    struct sigaction sa = {0};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    int *p = NULL;
    *p = 42; // викликає SIGSEGV

    return 0;
}

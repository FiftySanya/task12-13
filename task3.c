#include <signal.h>
#include <stdio.h>
#include <unistd.h>
void handle_sigint(int sig) {
    printf("Caught SIGINT (Ctrl+C)\n");
}

void handle_sigterm(int sig) {
    printf("Caught SIGTERM, exiting...\n");
    _exit(0);
}

int main() {
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigterm);
    printf("PID: %d\n", getpid());
    
    while (1) {
        sleep(1);
    }

    return 0;
}

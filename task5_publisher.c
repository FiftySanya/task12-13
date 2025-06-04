#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    pid_t pid = atoi(argv[1]);
    union sigval val;
    val.sival_int = 99;
    sigqueue(pid, SIGRTMIN, val);

    return 0;
}

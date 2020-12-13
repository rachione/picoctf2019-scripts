
#include <signal.h>
#include <unistd.h>

int main(){

    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGALRM);
    sigprocmask(SIG_BLOCK, &sigs, 0);

    execl("./times-up-one-last-time", "times-up-one-last-time", NULL);

}
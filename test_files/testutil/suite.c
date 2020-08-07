#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "suite.h"


static pid_t daemon_pid = -1;
static pid_t server_pid = -1;


void sigchild_fail_handler(int signal) {

    int original_errno = errno;
    int daemon_ret, server_ret;

    daemon_ret = waitpid(daemon_pid, NULL, WNOHANG);
    if (daemon_ret > 0) {
        fprintf(stderr, "\nFatal Error: daemon prematurely terminated\n");
        daemon_pid = -1;
    }
    
    server_ret = waitpid(server_pid, NULL, WNOHANG);
    if (server_ret > 0) {
        fprintf(stderr, "\nFatal Error: server prematurely terminated\n");
        server_pid = -1;
    }

    if (daemon_ret > 0 || server_ret > 0) {
        
        if (daemon_pid != -1) {
            kill(daemon_pid, SIGINT);
            waitpid(daemon_pid, NULL, 0);
        }

        if (server_pid != -1) {
            kill(server_pid, SIGINT);
            waitpid(server_pid, NULL, 0);
        }
        exit(1);
    }

    errno = original_errno;
}

void sigio_stub_handler (int signal) {
    return;
}


void start_daemon(const char* daemon_config, int use_valgrind) {

    sigset_t set;
    int returned_sig, ret;

    sigemptyset(&set);
    sigaddset(&set, SIGIO);

    signal(SIGCHLD, sigchild_fail_handler);
    signal(SIGIO, sigio_stub_handler);

    char pid_env[128] = {0};
    snprintf(pid_env, 127, "TESTING_PROCESS=%i", getpid());

    daemon_pid = fork();
    if (daemon_pid == 0) {

        setpgid(0, 0);

        if (use_valgrind) {
            char* env[1] = {NULL};
            char* flags[10] = {"/usr/bin/sudo", "-s", pid_env, "valgrind", 
                        "--leak-check=full", "--track-fds=yes" , 
                        ".././ssa_daemon", "-s", strdup(daemon_config), NULL};

            execve("/usr/bin/sudo", flags, env);

        } else {
            char* env[1] = {NULL};
            char* flags[7] = {"/usr/bin/sudo", "-s", pid_env, 
                        ".././ssa_daemon", "-s", strdup(daemon_config), NULL};

            execve("/usr/bin/sudo", flags, env);
        }

        fprintf(stderr, "\nDaemon execve failed\n");
        exit(1);
        
    }

    ret = sigwait(&set, &returned_sig);
    if (ret > 0 || returned_sig != SIGIO) {
        int stat;

        perror("sigwait() failed--unable to start daemon\n");
        kill(daemon_pid, SIGINT);
        waitpid(daemon_pid, &stat, 0);
        exit(1);
    }
}


void start_server(const char* server_path) {

    sigset_t set;
    int returned_sig, ret;

    sigemptyset(&set);
    sigaddset(&set, SIGIO);

    server_pid = fork();
    if (server_pid == 0) {
        close(0);
        close(1);
        close(2);
        char* args[2] = {strdup(server_path), NULL};
        execv(server_path, args);

        fprintf(stderr, "\nServer execve failed\n");
        exit(1);
    }

    ret = sigwait(&set, &returned_sig);
    if (ret > 0 || returned_sig != SIGIO) {
        int stat;

        perror("sigwait() failed--unable to start server\n");
        kill(daemon_pid, SIGINT);
        waitpid(daemon_pid, &stat, 0);
        exit(1);
    }
}

void cleanup() {

    int ret;

    signal(SIGCHLD, NULL);

    if (server_pid != -1) {
        ret = kill(server_pid, SIGINT);
        if (ret < 0)
            perror("server kill failed\n");
        else
            waitpid(server_pid, NULL, 0);
    }

    /* killing a sudoed process requires sudo permissions... :( */
    if (fork() == 0) {
        char daemon_pid_str[128] = {0};
        snprintf(daemon_pid_str, 127, "%i", (int) -daemon_pid);

        char* flags[4] = {"/usr/bin/sudo", "kill", daemon_pid_str, NULL};
        char* env[1] = {NULL};
        execve("/usr/bin/sudo", flags, env);

        fprintf(stderr, "\nDaemon cleanup failed; execute `sudo kill %i`\n",
                    daemon_pid);
    }

    waitpid(daemon_pid, NULL, 0);

    server_pid = -1;
    daemon_pid = -1;
    //sleep(1); /* give time for valgrind to print out messages */
}
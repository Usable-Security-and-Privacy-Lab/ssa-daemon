#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../in_tls.h"


#define CERT_PATH "certs/server_chain.pem"
#define KEY_PATH "certs/server_key.pem"


#define BUF_SIZE 1000


int main(int argc, char** argv) {

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(4433);

    int ret, fd;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        exit(1);

    ret = setsockopt(fd, IPPROTO_TLS, 
            TLS_CERTIFICATE_CHAIN, CERT_PATH, strlen(CERT_PATH)+1);
    if (ret < 0)
        exit(1);

    ret = setsockopt(fd, IPPROTO_TLS, 
            TLS_PRIVATE_KEY, KEY_PATH, strlen(KEY_PATH)+1);
    if (ret < 0)
        exit(1);

    ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0)
        exit(1);

    ret = listen(fd, SOMAXCONN);
    if (ret < 0)
        exit(1);

    pid_t ppid = getppid();

    ret = kill(ppid, SIGIO);
    if (ret < 0)
        exit(1);

    while (1) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        char buf[BUF_SIZE+1] = {0};
        int c_fd;
        
        
        c_fd = accept(fd, (struct sockaddr*)&addr, &addr_len);
        if (c_fd < 0) {
            if (errno == ECONNABORTED)
                continue;
            else
                exit(1);
        }

        int num_received = recv(c_fd, buf, BUF_SIZE, 0);
        if (num_received > 0)
            send(c_fd, buf, num_received+1, 0); /* +1 for EOF */

        close(c_fd);
        if (num_received < 0)
            exit(1);
    }

    return 0;
}
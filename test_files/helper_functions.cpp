#include <gtest/gtest.h>

#include "helper_functions.h"


extern "C" {

#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../in_tls.h"
}


#define MAX_HEADER_SIZE 8192
#define MAX_RESPONSE 10000
#define ERR_STRING_MAX_LEN 256


/**
 * Prints all error information available for the given socket (errno and 
 * potentially TLS_ERROR string).
 * @param fd The file descriptor to print error information for.
 */
void print_socket_error(int fd, const std::string source) {

    char buf[256] = {0};
    socklen_t buf_len = 255;
    int errno_err = errno;
    int ret;

    fprintf(stderr, "%s failed--returned errno %i: %s\n", 
                source.c_str(), errno_err, strerror(errno_err));

    ret = getsockopt(fd, IPPROTO_TLS, TLS_ERROR, buf, &buf_len);
    if (ret == 0)
        fprintf(stderr, "Daemon err string: %s\n",
                    buf);
    else
        fprintf(stderr, "Daemon had no err string\n");
    

    errno = errno_err;
}



/**
 * Performs `getaddrinfo()` DNS resolution on the given host and populates 
 * \p addr and \p addrlen with a viable address to connect to. The address 
 * will be an IPv4 address suitable for a TCP connection.
 * @param host The hostname to perform DNS resolution on.
 * @param addr The returned address of hostname.
 * @param addrlen The length of \p addr.
 */
void resolve_dns(std::string host, std::string port, 
            struct sockaddr** addr, socklen_t* addrlen) {

    struct addrinfo hints = {0};
    struct addrinfo* res;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo() failed with return code %i: %s\n", 
                    ret, gai_strerror(ret));
        FAIL();
    }

    *addr = (struct sockaddr*) malloc(res->ai_addrlen);
    if (*addr == NULL) {
        perror("DNS resolution failed with malloc error");
        freeaddrinfo(res);
        FAIL();
    }

    memcpy(*addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;

    freeaddrinfo(res);
    return;
}


int create_socket(bool is_nonblocking) {

    int fd;
    
    if (is_nonblocking)
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    else
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    
    if (fd < 0) {
        print_socket_error(fd, "socket()");
    } else if (errno != 0) {
        fprintf(stderr, "Unexpected errno with socket() success: %i %s\n", 
                errno, strerror(errno));
        ADD_FAILURE();
    }

    return fd;
}

void set_hostname(int fd, std::string hostname) {

    int ret = setsockopt(fd, IPPROTO_TLS, TLS_HOSTNAME, 
                hostname.c_str(), hostname.length()+1);
    
    if (ret != 0) {
        print_socket_error(fd, "TLS_HOSTNAME setsockopt()");
        close(fd);
        FAIL();
    }

    if (errno != 0) {
        fprintf(stderr, 
                "TLS_HOSTNAME setsockopt had errno despite success (%i: %s)\n", 
                errno, strerror(errno));
        ADD_FAILURE();
    }
}

void set_hostname_fail(int fd, std::string hostname, int expected_errno) {

    int ret = setsockopt(fd, IPPROTO_TLS, TLS_HOSTNAME, 
                hostname.c_str(), hostname.length()+1);

    if (ret == 0) {
        fprintf(stderr, 
                "TLS_HOSTNAME setsockopt succeeded when it shouldn't have\n");
        close(fd);
        FAIL();
    }
    
    if (errno != expected_errno) {
        fprintf(stderr, 
                "TLS_HOSTNAME setsockopt errno: %i, %s. Expected %i: %s\n", 
                errno, strerror(errno), 
                expected_errno, strerror(expected_errno));
        close(fd);
        FAIL();
    }
}

void get_hostname(int fd, std::string* hostname) {

    socklen_t hostname_len = 256;
    char hostname_char[hostname_len] = {0};

    int ret = getsockopt(fd, IPPROTO_TLS, TLS_HOSTNAME,
                &hostname_char, &hostname_len);

    if (ret < 0) {
        print_socket_error(fd, "TLS_HOSTNAME getsockopt()");
        close(fd);
        FAIL();
    }
    
    if (errno != 0) {
        fprintf(stderr, 
                "TLS_HOSTNAME getsockopt() had errno %i (%s) despite success\n",
                errno, strerror(errno));
        ADD_FAILURE();
    }

    hostname->erase();
    hostname->append(hostname_char);

    if (hostname->size() != hostname_len) {
        fprintf(stderr, 
                "Hostname size returned from getsockopt() doesn't match strlen\n");
        ADD_FAILURE();
    }
}

void get_hostname_fail(int fd, int expected_errno) {

    socklen_t hostname_len = 256;
    char hostname_char[hostname_len] = {'a'};

    int ret = getsockopt(fd, IPPROTO_TLS, TLS_HOSTNAME,
                &hostname_char, &hostname_len);

    if (ret == 0) {
        fprintf(stderr, 
                "TLS_HOSTNAME getsockopt succeeded when it shouldn't have\n");
        close(fd);
        FAIL();
    }
    
    if (errno != expected_errno) {
        fprintf(stderr, 
                "TLS_HOSTNAME getsockopt errno: %i, %s. Expected %i: %s\n", 
                errno, strerror(errno), 
                expected_errno, strerror(expected_errno));
        close(fd);
        FAIL();
    }
}


void connect_to_host_fail(int fd, std::string hostname, 
            std::string port, int expected_errno) {
    
    static std::string cached_hostname = "";
    static struct sockaddr* addr = NULL;
    static socklen_t addrlen;
    int ret;

    /* reuse the address used before it the same hostname is inputted */
    if (hostname.compare(cached_hostname) != 0 || addr == NULL) {
        resolve_dns(hostname, port, &addr, &addrlen);
        cached_hostname = hostname;
    }
    
    ret = connect(fd, addr, addrlen);
    if (ret == 0) {
        fprintf(stderr, "connect() succeeded when it shouldn't have\n");
        close(fd);
        FAIL();
    }
    
    if (errno != expected_errno) {
        fprintf(stderr, 
                "Wrong returned errno code. Expected %i:%s; returned %i:%s\n", 
                expected_errno, strerror(expected_errno), 
                errno, strerror(errno));
        ADD_FAILURE();
    }
}

void connect_to_host(int fd, 
            std::string hostname, std::string port) {

    static std::string cached_hostname = "";
    static struct sockaddr* addr = NULL;
    static socklen_t addrlen;
    int ret;

    /* reuse the address used before it the same hostname is input */
    if (hostname.compare(cached_hostname) != 0 || addr == NULL) {
        resolve_dns(hostname, port, &addr, &addrlen);
        cached_hostname = hostname;
    }

    ret = connect(fd, addr, addrlen);
    if (ret != 0) {
        print_socket_error(fd, "connect()");
        close(fd);
        FAIL();
    }

    if (errno != 0) {
        fprintf(stderr, "connect() had errno despite success (%i:%s)\n",
                    errno, strerror(errno));
        ADD_FAILURE();
    }   
}



void connect_to_localhost_fail(int fd, int expected_errno) {

    std::string hostname = "localhost";
    std::string port = "4433";

    connect_to_host_fail(fd, hostname, port, expected_errno);
}

void connect_to_localhost(int fd) {

    std::string hostname = "localhost";
    std::string port = "4433";

    connect_to_host(fd, hostname, port);
}



void enable_revocation_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 1;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_REVOCATION_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_REVOCATION_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_REVOCATION_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void disable_revocation_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 0;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_REVOCATION_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_REVOCATION_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_REVOCATION_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}



void enable_ocsp_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 1;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_OCSP_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_OCSP_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_OCSP_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void disable_ocsp_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 0;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_OCSP_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_OCSP_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_OCSP_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}



void enable_stapled_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 1;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_OCSP_STAPLED_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_OCSP_STAPLED_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_OCSP_STAPLED_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void disable_stapled_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 0;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_OCSP_STAPLED_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_OCSP_STAPLED_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_OCSP_STAPLED_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}



void enable_cached_ocsp_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 1;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_CACHED_REV_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_CACHED_REV_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_CACHED_REV_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void disable_cached_ocsp_checks(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 0;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_CACHED_REV_CHECKS, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_CACHED_REV_CHECKS setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_CACHED_REV_CHECKS setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}



void get_tls_context(int fd, bool should_succeed, unsigned long* tls_context) {

    socklen_t len = sizeof(unsigned long);
    int ret;
    
    ret = getsockopt(fd, IPPROTO_TLS, TLS_CONTEXT, tls_context, &len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_CONTEXT getsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_CONTEXT getsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}


void set_tls_context(int fd, bool should_succeed, unsigned long tls_context) {

    socklen_t len = sizeof(unsigned long);
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_CONTEXT, &tls_context, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_CONTEXT setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_CONTEXT setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}



void disable_session_reuse(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 0;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_SESSION_REUSE, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_SESSION_REUSE setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_SESSION_REUSE setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void enable_session_reuse(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 1;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_SESSION_REUSE, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_SESSION_REUSE setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_SESSION_REUSE setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void is_resumed_session(int fd, bool should_succeed, bool* is_resumed) {

    socklen_t len = sizeof(int);
    int resumed = -1;
    int ret;
    
    ret = getsockopt(fd, IPPROTO_TLS, TLS_RESUMED_SESSION, &resumed, &len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_RESUMED_SESSION getsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_RESUMED_SESSION getsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }

    if (resumed == 1) {
        *is_resumed = true;
    } else if (resumed == 0) {
        *is_resumed = false;
    } else {
        fprintf(stderr, "TLS_RESUMED_SESSION getsockopt() return != 0 or 1\n");
        close(fd);
        FAIL();
    }
}


void enable_compression(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 1;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_COMPRESSION, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_COMPRESSION setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_COMPRESSION setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void disable_compression(int fd, bool should_succeed) {

    socklen_t len = sizeof(int);
    int enabled = 0;
    int ret;
    
    ret = setsockopt(fd, IPPROTO_TLS, TLS_COMPRESSION, &enabled, len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_COMPRESSION setsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_COMPRESSION setsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }
}

void get_compression(int fd, bool should_succeed, bool* enabled) {

    socklen_t len = sizeof(int);
    int compression = -1;
    int ret;
    
    ret = getsockopt(fd, IPPROTO_TLS, TLS_COMPRESSION, &compression, &len);
    if (ret < 0 && should_succeed) {
        print_socket_error(fd, "TLS_COMPRESSION getsockopt()\n");
        close(fd);
        FAIL();
    
    } else if (ret == 0 && !should_succeed) {
        fprintf(stderr, "TLS_COMPRESSION getsockopt() succeeded when it shouldn't\n");
        close(fd);
        FAIL();
    }

    if (compression == 1) {
        *enabled = true;
    } else if (compression == 0) {
        *enabled = false;
    } else {
        fprintf(stderr, "TLS_COMPRESSION getsockopt() return != 0 or 1\n");
        close(fd);
        FAIL();
    }
}

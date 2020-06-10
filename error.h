#ifndef SSA_ERROR_H
#define SSA_ERROR_H

#include "daemon_structs.h"


#define NO_ERROR 0



int has_error_string(socket_ctx* sock_ctx);

int determine_errno_error();
int determine_and_set_error(socket_ctx* sock_ctx);
int set_socket_error(socket_ctx* sock_ctx, unsigned long ssl_err);

void set_err_string(socket_ctx* sock_ctx, char* string, ...);
void set_badfd_err_string(socket_ctx* sock_ctx);
void set_wrong_state_err_string(socket_ctx* sock_ctx);

void clear_global_errors();
void clear_socket_error(socket_ctx* sock_ctx);
void clear_global_and_socket_errors(socket_ctx* sock_ctx);



#endif
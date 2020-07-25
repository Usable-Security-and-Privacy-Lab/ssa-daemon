#ifndef SSA_SETSOCKOPT_H
#define SSA_SETSOCKOPT_H

#include "daemon_structs.h"


/**
 * Performs the socket operation specified by \p option on the given socket.
 * @param sock_ctx The context of the socket to perform the operation on.
 * @param option The operation to be performed.
 * @param value The value to be used in the operation (passed in by the 
 * calling program).
 * @param len The length of \p value.
 * @returns 0 on success, or a negative errno value on failure.
 */
int do_setsockopt_action(socket_ctx* sock_ctx, 
            int option, void* value, socklen_t len);


#endif
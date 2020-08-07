#ifndef SSA_GETSOCKOPT_H
#define SSA_GETSOCKOPT_H

#include "daemon_structs.h"


/**
 * Performs the operations necessary to retrieve the specified information 
 * desired for the given socket.
 * @param sock_ctx The context of the socket to retrieve information from.
 * @param option The socket option to retrieve information associated with.
 * @param need_free Whether \p data will need to be freed after use.
 * @param data A pointer to data to be sent back to the calling program.
 * @param len The size of \p data.
 * @returns 0 on success, or a negative errno value on failure.
 */
int do_getsockopt_action(socket_ctx* sock_ctx, 
            int option, void** data, unsigned int* len);


#endif

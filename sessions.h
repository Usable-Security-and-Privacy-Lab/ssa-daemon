#ifndef SSA_SESSIONS_H
#define SSA_SESSIONS_H

#include "daemon_structs.h"



/**
 * Checks to see whether client-side session resumption is enabled for the given
 * SSL context \p ctx.
 * @param ctx The SSL context to check.
 * @returns 1 if client-side session caching is enabled, or 0 otherwise.
 */
int session_resumption_enabled(SSL_CTX* ctx);


/**
 * Checks to see if the given SSL context \p ctx has had a session cache
 * hashmap put into its internal data already. Note that the cache it is 
 * searching for is the hsmap_t* cache defined in hashmap_str.c/h, not the
 * internal OpenSSL session cache.
 * @param ctx The SSL_CTX to check for a session cache.
 * @returns 1 if the session cache was found; 0 otherwise.
 */
int has_session_cache(SSL_CTX* ctx);


/**
 * Creates a new session cache within the given SSL context \p ctx. On success,
 * this session cache will passively store sessions whenever a server sends them
 * for future use.
 * @param ctx The SSL_CTX to create a session cache for.
 * @returns 0 if successful, or -ECANCELED on failure.
 */
int session_cache_new(SSL_CTX* ctx);


/**
 * Increments the reference count of the session cache associated with \p ctx.
 * @param ctx The SSL context to retrieve the session cache from.
 * @returns 0 if successful, or -ECANCELED if the session cache's reference
 * count couldn't be retrieved (usually happens when the context has no session 
 * cache associated with it).
 */
int session_cache_up_ref(SSL_CTX* ctx);


/**
 * Frees the session cache associated with \p ctx. If no such session cache is
 * is found, nothing will be done.
 * @param ctx The SSL context containing the session cache to be freed.
 */
void session_cache_free(SSL_CTX* ctx);


/**
 * Prepares \p ssl to add new sessions to the cache contained in its SSL 
 * context, and adds an existing session to \p ssl from the cache if such
 * an applicable session exists.
 * @param ssl The SSL connection to enable session resumption on.
 * @param hostname_port The hostname:port null-terminated string that acts 
 * as an identifier for sessions.
 * @returns 0 on success, or -errno if an error occurred.
 */
int session_resumption_setup(SSL* ssl, char* hostname_port);


/**
 * Clears any data associated with session resumption from \p ssl.
 * @param ssl The SSL connection to free session resumption info from.
 */
void session_cleanup(SSL* ssl);


#endif
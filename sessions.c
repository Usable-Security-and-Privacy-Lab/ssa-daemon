#include <string.h>

#include <openssl/ssl.h>

#include "hashqueue.h"
#include "log.h"
#include "sessions.h"


#define SESS_CACHE_INDEX 1
#define SESS_CACHE_REF_CNT_INDEX 2
#define HOSTNAME_PORT_INDEX 3
#define SESS_HOSTNAME_PORT_INDEX 4

#define SESSION_CACHE_NUM_BUCKETS 255



int new_session_cb(SSL* ssl, SSL_SESSION* session);
void remove_session_cb(SSL_CTX *ctx, SSL_SESSION *session);

void free_ssl_session(void* session);



/**
 * Checks to see whether client-side session resumption is enabled for the given
 * SSL context \p ctx.
 * @param ctx The SSL context to check.
 * @returns 1 if client-side session caching is enabled, or 0 otherwise.
 */
int session_resumption_enabled(SSL_CTX* ctx) {

    int cache_mode = SSL_CTX_get_session_cache_mode(ctx);

    return ((cache_mode & SSL_SESS_CACHE_CLIENT) 
                && (cache_mode & SSL_SESS_CACHE_SERVER)) ? 1 : 0;
}


/**
 * Checks to see if the given SSL context \p ctx has had a session cache 
 * hashmap put into its internal data already. Note that the cache it is 
 * searching for is the hashqueue cache defined in hashmap_str.c/h, not the 
 * internal OpenSSL session cache. 
 * @param ctx The SSL_CTX to check for a session cache.
 * @returns 1 if the session cache was found; 0 otherwise.
 */
int has_session_cache(SSL_CTX* ctx) {

    int* ref_cnt = SSL_CTX_get_ex_data(ctx, SESS_CACHE_REF_CNT_INDEX);
    hqueue_t* cache = SSL_CTX_get_ex_data(ctx, SESS_CACHE_INDEX);

    if (ref_cnt == NULL || cache == NULL)
        return 0;
    else
        return 1;
}


/**
 * Creates a new session cache within the given SSL context \p ctx. On success,
 * this session cache will passively store sessions whenever a server sends them
 * for future use.
 * @param ctx The SSL_CTX to create a session cache for.
 * @returns 0 if successful, or -ECANCELED on failure.
 */
int session_cache_new(SSL_CTX* ctx) {

    hqueue_t* session_cache = NULL;
    int* cache_reference_cnt = NULL;
    int ret;

    session_cache = hashqueue_create(SESSION_CACHE_NUM_BUCKETS);
    if (session_cache == NULL)
        goto err;

    ret = SSL_CTX_set_ex_data(ctx, SESS_CACHE_INDEX, session_cache);
    if (ret != 1)
        goto err;

    cache_reference_cnt = malloc(sizeof(int));
    if (cache_reference_cnt == NULL)
        goto err;

    *cache_reference_cnt = 1;

    ret = SSL_CTX_set_ex_data(ctx, 
                SESS_CACHE_REF_CNT_INDEX, cache_reference_cnt);
    if (ret != 1)
        goto err;

    
    SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
    /*
    SSL_CTX_sess_set_remove_cb(ctx, remove_session_cb);
        */
    return 0;
err:
    if (session_cache != NULL)
        hashqueue_free(session_cache);

    if (cache_reference_cnt != NULL)
        free(cache_reference_cnt);

    SSL_CTX_set_ex_data(ctx, SESS_CACHE_INDEX, NULL);
    SSL_CTX_set_ex_data(ctx, SESS_CACHE_REF_CNT_INDEX, NULL);

    return -ECANCELED;
}


/**
 * Increments the reference count of the session cache associated with \p ctx.
 * @param ctx The SSL context to retrieve the session cache from.
 * @returns 0 if successful, or -ECANCELED if the session cache's reference
 * count couldn't be retrieved (usually happens when the context has no session 
 * cache associated with it).
 */
int session_cache_up_ref(SSL_CTX* ctx) {

    int* ref_cnt;

    if (!has_session_cache(ctx))
        return -ECANCELED;

    ref_cnt = SSL_CTX_get_ex_data(ctx, SESS_CACHE_REF_CNT_INDEX);
    if (ref_cnt == NULL)
        return -ECANCELED;
    
    *ref_cnt += 1;
    log_printf(LOG_DEBUG, "Session cache upref'd: now %i\n", *ref_cnt);

    return 0;
}


/**
 * Frees the session cache associated with \p ctx. If no such session cache is
 * is found, nothing will be done.
 * @param ctx The SSL context containing the session cache to be freed.
 */
void session_cache_free(SSL_CTX* ctx) {

    hqueue_t* session_cache = SSL_CTX_get_ex_data(ctx, SESS_CACHE_INDEX);
    int* cache_ref_cnt = SSL_CTX_get_ex_data(ctx, SESS_CACHE_REF_CNT_INDEX);

    if (*cache_ref_cnt > 1) {
        *cache_ref_cnt -= 1;
        log_printf(LOG_DEBUG, "Session cache downref'd: now %i\n", *cache_ref_cnt);

    } else {
        log_printf(LOG_DEBUG, "Session cache freed\n");
        free(cache_ref_cnt);
        hashqueue_deep_free(session_cache, free_ssl_session);

        SSL_CTX_set_ex_data(ctx, SESS_CACHE_INDEX, NULL);
        SSL_CTX_set_ex_data(ctx, SESS_CACHE_REF_CNT_INDEX, NULL);

        SSL_CTX_sess_set_new_cb(ctx, NULL);
        SSL_CTX_sess_set_remove_cb(ctx, NULL);
    }
}


/**
 * Prepares \p ssl to add new sessions to the cache contained in its SSL 
 * context, and adds an existing session to \p ssl from the cache if such
 * an applicable session exists.
 * @param ssl The SSL connection to enable session resumption on.
 * @param hostname_port The hostname:port null-terminated string that acts 
 * as an identifier for sessions.
 * @returns 0 on success, or -errno if an error occurred.
 */
int session_resumption_setup(SSL* ssl, char* hostname_port) {

    SSL_CTX* ctx;
    SSL_SESSION* session;
    hqueue_t* session_cache;
    int ret;

    ret = SSL_set_ex_data(ssl, HOSTNAME_PORT_INDEX, hostname_port);
    if (ret != 1)
        goto err;

    ctx = SSL_get_SSL_CTX(ssl);
    if (ctx == NULL)
        goto err;

    session_cache = SSL_CTX_get_ex_data(ctx, SESS_CACHE_INDEX);
    if (session_cache == NULL)
        return 0;

    /* TODO: go through every element until one is found that can resume */
    while ((session = hashqueue_front(session_cache, hostname_port)) != NULL) {
        
        hashqueue_pop(session_cache, hostname_port);

        if (SSL_SESSION_is_resumable(session)) {
            break;

        } else {
            SSL_CTX_remove_session(ctx, session);
            SSL_SESSION_free(session);

        }
    }

    ret = SSL_set_session(ssl, session);
    if (ret != 1)
        SSL_CTX_remove_session(ctx, session);

    SSL_SESSION_free(session);

    return 0;
err:
    return -ECANCELED;
}


/**
 * Clears any data associated with session resumption from \p ssl.
 * @param ssl The SSL connection to free session resumption info from.
 */
void session_cleanup(SSL* ssl) {

    char* host_port = SSL_get_ex_data(ssl, HOSTNAME_PORT_INDEX);
    if (host_port != NULL)
        free(host_port);

    SSL_set_ex_data(ssl, HOSTNAME_PORT_INDEX, NULL);
}



/*******************************************************************************
 *                        HELPER FUNCTIONS / CALLBACKS
 ******************************************************************************/


/**
 * Called whenever the SSL connection \p ssl receives a new session ticket or
 * ID during a connection; the session is cached within an internal opaque 
 * cache in addition to the caching done here.
 * @param ssl The SSL connection that received the session.
 * @param session The session to be cached.
 * @returns 1 if the session was successfully cached, or 0 otherwise.
 */
int new_session_cb(SSL* ssl, SSL_SESSION* session) {

    hqueue_t* session_cache;
    SSL_CTX* ctx;
    char* host_port = NULL;
    int ret;

    log_printf(LOG_DEBUG, "new_session_cb called\n");
     
    ctx = SSL_get_SSL_CTX(ssl);
    if (ctx == NULL)
        goto err;
    
    host_port = SSL_get_ex_data(ssl, HOSTNAME_PORT_INDEX);
    if (host_port == NULL)
        goto err;
    
    host_port = strdup(host_port);
    if (host_port == NULL)
        goto err;

    
    session_cache = (hqueue_t*) SSL_CTX_get_ex_data(ctx, SESS_CACHE_INDEX);
    if (session_cache == NULL)
        goto err;
    
    ret = hashqueue_push(session_cache, host_port, session);
    if (ret != 0)
        goto err;

    log_printf(LOG_DEBUG, "New session successfully added!\n");
    
    return 1;
err:
    if (host_port != NULL)
        free(host_port);
    
    return 0;
}


/**
 * Called whenever the SSL session \p session is deemed to be not reusable 
 * and is to be removed from the internal opaque session cache that \p ctx 
 * holds. This callback effectively allows the hashqueue session cache to stay 
 * in sync with the internal session cache and keep the same maximum capacity 
 * as it. It is particularly useful since the OpenSSL internal session cache 
 * automatically checks for old sessions that can't be reused anymore and 
 * calls this callback for each of them.
 * @param ctx The context containing the cached session. 
 * @param session The session to be removed from the cache. 
 */

/*
void remove_session_cb(SSL_CTX *ctx, SSL_SESSION *session) {

    hqueue_t* session_cache;
    char* host_port;

    log_printf(LOG_DEBUG, "Session removed via remove_session_cb\n");

    session_cache = SSL_CTX_get_ex_data(ctx, SESS_CACHE_INDEX);
    if (session_cache == NULL)
        return;

    host_port = SSL_SESSION_get_ex_data(session, SESS_HOSTNAME_PORT_INDEX);
    if (host_port == NULL)
        return;

    int ret = hashqueue_pop(session_cache, host_port, session);
    if (ret != 0)
        log_printf(LOG_WARNING, "queue_del didn't work on session\n");
    
    SSL_SESSION_set_ex_data(session, HOSTNAME_PORT_INDEX, NULL);
    SSL_SESSION_free(session);
}

 */

/**
 * Wrapper function to deep-free SSL sessions from a hashmap.
 * @param session The session to be freed.
 */
void free_ssl_session(void* session) {

    SSL_SESSION_free((SSL_SESSION*) session);
}
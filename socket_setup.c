#include <fcntl.h> /* for S_IFDIR/S_IFREG constants */
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "config.h"
#include "connection_callbacks.h"
#include "error.h"
#include "log.h"
#include "sessions.h"

#define UBUNTU_DEFAULT_CA "/etc/ssl/certs/ca-certificates.crt"
#define FEDORA_DEFAULT_CA "/etc/pki/tls/certs/ca-bundle.crt"

#define DEFAULT_CIPHER_LIST "ECDHE-ECDSA-AES256-GCM-SHA384:"  \
                            "ECDHE-RSA-AES256-GCM-SHA384:"    \
                            "ECDHE-ECDSA-CHACHA20-POLY1305:"  \
                            "ECDHE-RSA-CHACHA20-POLY1305:"    \
                            "ECDHE-ECDSA-AES128-GCM-SHA256:"  \
                            "ECDHE-RSA-AES128-GCM-SHA256"

#define DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:"       \
                             "TLS_AES_128_GCM_SHA256:"       \
                             "TLS_CHACHA20_POLY1305_SHA256:" \
                             "TLS_AES_128_CCM_SHA256:"       \
                             "TLS_AES_128_CCM_8_SHA256"

#define DEBUG_TEST_CA "test_files/certs/rootCA.pem"
#define DEBUG_CERT_CHAIN "test_files/certs/server_chain.pem"
#define DEBUG_PRIVATE_KEY "test_files/certs/server_key.pem"

#define EXT_CONN_TIMEOUT 15 /* seconds */



/* SSL_CTX loading */
long get_tls_version(enum tls_version version);
int load_certificate_authority(SSL_CTX* ctx, char* CA_path);
int load_cipher_list(SSL_CTX* ctx, char** list, int num);
int load_ciphersuites(SSL_CTX* ctx, char** list, int num);

int concat_ciphers(char** list, int num, char** out);

int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);
int check_key_cert_pair(socket_ctx* sock_ctx);
int load_certificates(SSL_CTX* ctx, global_config* settings);

/**
 * Allocates an SSL_CTX struct and populates it with the settings found in 
 * \p settings. 
 * @param settings a struct filled with the settings that should be applied
 * to the SSL_CTX.
 * @returns A pointer to an allocated SSL_CTX struct, or NULL on error.
 */
SSL_CTX* SSL_CTX_create(global_config* settings) {

    SSL_CTX* ctx = NULL;
    long tls_version;
    int ret;

    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
        goto err;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (settings->session_resumption)
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    else 
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    
    if (!settings->tls_compression)
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    else
        SSL_CTX_clear_options(ctx, SSL_OP_NO_COMPRESSION);

    if (!settings->session_tickets)
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    else
        SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);
    

    tls_version = get_tls_version(settings->min_tls_version);
    if (SSL_CTX_set_min_proto_version(ctx, tls_version) != 1) 
        goto err;

    tls_version = get_tls_version(settings->max_tls_version);
    if (SSL_CTX_set_max_proto_version(ctx, tls_version) != 1)
        goto err;


    if (settings->cipher_list_cnt > 0) {
        ret = load_cipher_list(ctx, 
                settings->cipher_list, settings->cipher_list_cnt);
    } else {
        ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
    }
    if (ret != 1)
        goto err;
    

    if (settings->ciphersuite_cnt > 0) {
        ret = load_ciphersuites(ctx, 
                settings->ciphersuites, settings->ciphersuite_cnt);
    } else {
        ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
    }
    if (ret != 1)
        goto err;

    ret = load_certificate_authority(ctx, settings->ca_path);
    if (ret != 1)
        goto err;

    SSL_CTX_set_timeout(ctx, settings->session_timeout);
    SSL_CTX_set_verify_depth(ctx, settings->max_chain_depth);

    if(settings->ct_checks) {
        ret = SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_STRICT);
        if (ret != 1)
            goto err;

        ret = SSL_CTX_set_ctlog_list_file(ctx, "ct_log_list.cnf");
        if(ret != 1)
            goto err;
    }

    ret = load_certificates(ctx, settings); 
    if (ret != 1) 
        goto err;

    return ctx;
err:
    if (ERR_peek_error())
        log_printf(LOG_ERROR, "OpenSSL error initializing client SSL_CTX: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
    
    if (ctx != NULL)
        SSL_CTX_free(ctx);

    return NULL;
}




/**
 * Check if null terminated string ends with ".pem".
 * @param path String to check for ".pem".
 * @return 1 if last four chars are ".pem", else 0.
 */
int is_pem_file(char* path) {
    int len = strlen(path);
    int pem_len = 4;
    if(len < pem_len)
        return 0;

    char* type = &path[len - pem_len];
    if(strcmp(type, ".pem") == 0) 
        return 1;
    else
        return 0;
}

/**
 * Searches cert_list for the certificate that isn't a CA (the end entity).
 * If a certificate is not a CA, it is assumed to be the end entity. 
 * @param cert_list Array of certificates to search.
 * @return The index of the end cert or -1 on error.
 */
int get_end_entity(X509** cert_list, int num_certs) {
    for(int i = 0; i < num_certs; ++i) {
        if(X509_check_ca(cert_list[i]) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Frees num_certs certificates in cert_list and closes directory
 */
void free_certificates(X509** cert_list, int num_certs, DIR* directory) {
    for(int j = 0; j < num_certs; ++j) {
        X509_free(cert_list[j]);
    }
    closedir(directory);
}

/**
 * Get number of files in directory.
 * @param directory An open directory containing certificate files. 
 * @returns number of files in directory.
 */
int get_directory_size(DIR* directory) {
    int num_files = 0;
    struct dirent* file;

    while((file = readdir(directory))) {
        if (!strcmp (file->d_name, ".")) 
            continue;

        if (!strcmp (file->d_name, ".."))    
            continue;

        ++num_files;
    }
    
    return num_files;
}

/**
 * Reads a directory of certificate files, converts them to X509 certificates, 
 * and adds them to cert_list. 
 * @param cert_list Array of certificate pointers to be populated with certificates in directory.
 * @param directory The directory containing certificates to put into cert_list.
 * @param dir_name Path of directory.
 * @return 0 on success, else -1. 
 */
int get_directory_certs(X509** cert_list, DIR* directory, char* dir_name) {
    struct dirent* in_file;
    int num_certs = 0; 
    int max_file_name_len = 128;
    char file_name[max_file_name_len];

    while ((in_file = readdir(directory))) {

        if (!strcmp (in_file->d_name, ".")) 
            continue;

        if (!strcmp (in_file->d_name, ".."))    
            continue;

        char* cert_name = in_file->d_name;
        file_name[0] = 0;
        sprintf(file_name, "%s/%s", dir_name, cert_name);
        FILE* current_file = fopen(file_name, "r"); 

        if(current_file == NULL) {
            log_printf(LOG_ERROR, "Error: Could not open file %s (Errno %d).\n", file_name, errno);
            free_certificates(cert_list, num_certs, directory);
            return -1;
        }
        
        if(is_pem_file(file_name)) {
            cert_list[num_certs] = PEM_read_X509(current_file, NULL, 0, NULL);
        }
        else { 
            cert_list[num_certs] = d2i_X509_fp(current_file, NULL);
        }

        if(cert_list[num_certs] == NULL) {
            log_printf(LOG_ERROR, "Error converting \"%s\" file to certificate.\n", cert_name);
            free_certificates(cert_list, num_certs, directory);
            return -1;
        }
        
        fclose(current_file); 
        ++num_certs;
        errno = 0;
    }
    if(errno != 0) {
        log_printf(LOG_ERROR, "Error reading directory %s.\n", dir_name);
        return -1;
    }
    return 0;
}

/**
 * Sorts certificates and loads them in order (from end entity to root) into a context.
 * @param ctx Context to load certificates into.
 * @param cert_list Array of certificates to load into context.
 * @param num_certs Number of certificates in cert_list array.
 * @return 1 on success, 0 on error.
 */
int add_directory_certs(SSL_CTX* ctx, X509** cert_list, int num_certs) { 
    int end_index = get_end_entity(cert_list, num_certs);
    if(end_index < 0) {
        log_printf(LOG_ERROR, "Could not locate end entity certificate.\n");
        return 0;
    }

    if(SSL_CTX_use_certificate(ctx, cert_list[end_index]) != 1) {
        log_printf(LOG_ERROR, "Error loading end certificate.\n");
        return 0;
    }

    const ASN1_STRING* issuer = X509_get0_authority_key_id(cert_list[end_index]);
    if(issuer == NULL) {
        log_printf(LOG_ERROR, "X509 authority key extension not found.\n");
        return 0;
    }
    
    for(int j = 1; j < num_certs; ++j) {
        for(int k = 0; k < num_certs; ++k) {

            const ASN1_STRING* subject = X509_get0_subject_key_id(cert_list[k]);
            if(subject == NULL) {
                log_printf(LOG_ERROR, "X509 subject key extension not found.\n");
                return 0;
            }

            if(ASN1_STRING_cmp(issuer, subject) == 0) {
                if(SSL_CTX_add0_chain_cert(ctx, cert_list[k]) != 1) { 
                    log_printf(LOG_ERROR, "Error adding CA to chain.\n");
                    return 0;
                }
                issuer = X509_get0_authority_key_id(cert_list[k]);
                break;
            }
        }
    }

    return 1;
}

/**
 * Each certificate file or directory in the config file are built and loaded  
 * into ctx with their associated private key. Private keys are checked to
 * ensure they match the end entity.
 * @param ctx The context that certificates will be loaded into.
 * @param settings The settings struct from the config file. Used to get 
 * the certificates and keys that will be loaded. 
 * @returns 1 on success, 0 on error.
 */
int load_certificates(SSL_CTX* ctx, global_config* settings) {
    char** cert_chain = settings->certificates;
    int cert_cnt = settings->cert_cnt;

    if(settings->key_cnt != cert_cnt) {
        log_printf(LOG_ERROR, "Number of keys and certificate chains differ.\n");
        return 0;
    }

    for(int i = 0; i < cert_cnt; ++i) {
        char* path = cert_chain[i];
        DIR* directory = opendir(path);

        if(is_pem_file(path)) {
            if(SSL_CTX_use_certificate_chain_file(ctx, path) != 1) {
                log_printf(LOG_ERROR, "Failed to load certificate chain file.\n");
                return 0;
            }
        }
        else if(directory != NULL) {
            int num_certs = get_directory_size(directory);
            closedir(directory);
            X509* cert_list[num_certs];
            directory = opendir(path);

            int ret = get_directory_certs(cert_list, directory, path);
            if(ret < 0) {
                log_printf(LOG_ERROR, "Failed to get certificates from directory.\n");
                return 0;
            }
            
            ret = add_directory_certs(ctx, cert_list, num_certs);
            if(ret < 1) {
                free_certificates(cert_list, num_certs, directory);
                log_printf(LOG_ERROR, "Failed to add certificates from directory.\n");
                return 0;
            }

            free_certificates(cert_list, num_certs, directory);
        }
        else {
            log_printf(LOG_ERROR, "[cert-path] must be a pem file or directory.\n");
            return 0;
        }

        int file_type;
        char* key_path = settings->private_keys[i];
        if(is_pem_file(key_path)) 
            file_type = SSL_FILETYPE_PEM;
        else 
            file_type = SSL_FILETYPE_ASN1;

        int ret = SSL_CTX_use_PrivateKey_file(ctx, key_path, file_type);
        if (ret != 1) { 
            log_printf(LOG_ERROR, "Couldn't use private key file\n");
            return 0;
        }

        ret = SSL_CTX_check_private_key(ctx);
        if (ret != 1) {
            log_printf(LOG_ERROR, "Loaded Private Key didn't match cert chain\n");
            return 0;
        }
        
        ret = SSL_CTX_build_cert_chain(ctx, 0); 
        if (ret != 1) {
            log_printf(LOG_ERROR, "Incomplete server certificate chain\n");
            return 0;
        }

    }

    return 1;
}





/**
 * Allocates and sets the correct settings for the bufferevents of a given 
 * socket. The socket may be either a connecting client socket (in which case 
 * the plain_fd must be set to -1) or an `accept()`ed server socket (in which
 * case the plain_fd must be set to the fd of the socket).
 * @param sock_ctx The context of the socket to prepare bufferevents for.
 * @param plain_fd The file descriptor that will be connected internally to
 * our program.
 * @returns 0 on success, or a negative errno code on failure. The bufferevents 
 * and the plain_fd are cleaned up on failure.
 */
int prepare_bufferevents(socket_ctx* sock_ctx, int plain_fd) {

    daemon_ctx* daemon = sock_ctx->daemon;
    enum bufferevent_ssl_state state;
    bufferevent_event_cb event_cb;
    int ret;

    if (plain_fd == NO_FD) {
        state = BUFFEREVENT_SSL_CONNECTING;
        event_cb = client_bev_event_cb;
    
    } else {
        state = BUFFEREVENT_SSL_ACCEPTING;
        event_cb = server_bev_event_cb;
    }

    clear_global_and_socket_errors(sock_ctx);

    sock_ctx->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base,
                sock_ctx->sockfd, sock_ctx->ssl, state, BEV_OPT_CLOSE_ON_FREE);
    if (sock_ctx->secure.bev == NULL)
        goto err;

    bufferevent_openssl_set_allow_dirty_shutdown(sock_ctx->secure.bev, 1);

    ret = bufferevent_enable(sock_ctx->secure.bev, EV_READ | EV_WRITE);
    if (ret < 0)
        goto err;

    sock_ctx->plain.bev = bufferevent_socket_new(daemon->ev_base,
                plain_fd, BEV_OPT_CLOSE_ON_FREE);
    if (sock_ctx->plain.bev == NULL)
        goto err;

    bufferevent_setcb(sock_ctx->secure.bev, common_bev_read_cb,
            common_bev_write_cb, event_cb, sock_ctx);
    bufferevent_setcb(sock_ctx->plain.bev, common_bev_read_cb,
            common_bev_write_cb, event_cb, sock_ctx);

     return 0;
err:
    log_global_error(LOG_ERROR, "Failed to set up bufferevents for connection");

    if (sock_ctx->plain.bev != NULL) {
        bufferevent_free(sock_ctx->plain.bev);
        sock_ctx->plain.bev = NULL;

    } else if (plain_fd != NO_FD) {
        close(plain_fd);
    }

    if (sock_ctx->secure.bev != NULL) {
        bufferevent_free(sock_ctx->secure.bev);

        sock_ctx->secure.bev = NULL;
        sock_ctx->ssl = NULL;
        sock_ctx->sockfd = NO_FD;
    }
    
    sock_ctx->state = SOCKET_ERROR;

    return -ECANCELED;
}


/**
 * Prepares the given socket context for a TLS connection with an endpoint. 
 * This function mostly has to do with setting up the `SSL` object used by 
 * the socket--allocation, setting it to perform certificate verification, 
 * giving it a session to resume (if one exists), and assigning it the hostname 
 * in \p sock_ctx.
 * @param sock_ctx The context of the socket to prepare an SSL object for. 
 * @returns 0 on success, or a negative errno value if an error occurred.
 */
int prepare_SSL_client(socket_ctx* sock_ctx) {

    int ret;

    if (has_revocation_checks(sock_ctx->rev_ctx.checks))
        ret = SSL_CTX_set_tlsext_status_type(sock_ctx->ssl_ctx, 
                    TLSEXT_STATUSTYPE_ocsp);
    else
        ret = SSL_CTX_set_tlsext_status_type(sock_ctx->ssl_ctx, 0);

    if (ret != 1)
        goto err;

    sock_ctx->ssl = SSL_new(sock_ctx->ssl_ctx);
    if (sock_ctx->ssl == NULL)
        goto err;

    SSL_set_verify(sock_ctx->ssl, SSL_VERIFY_PEER, NULL);

    if (strlen(sock_ctx->rem_hostname) <= 0) {
        set_err_string(sock_ctx, "TLS error: "
                    "hostname required for verification (via setsockopt())");
        goto err;
    }

    ret = SSL_set_tlsext_host_name(sock_ctx->ssl, sock_ctx->rem_hostname);
    if (ret != 1) {
        log_printf(LOG_ERROR, "Connection setup error: "
                "couldn't assign the socket's hostname for SNI\n");
        goto err;
    }

    ret = SSL_set1_host(sock_ctx->ssl, sock_ctx->rem_hostname);
    if (ret != 1) {
        log_printf(LOG_ERROR, "Connection setup error: "
                "couldn't assign the socket's hostname for validation\n");
        goto err;
    }
    if (session_resumption_enabled(sock_ctx->ssl_ctx)) {
        char* host_port = get_hostname_port_str(sock_ctx);
        if (host_port == NULL)
            goto err;

        ret = session_resumption_setup(sock_ctx->ssl, host_port);
        if (ret != 0) {
            free(host_port);
            goto err;
        }
    }

    return 0;
err:

    if (sock_ctx->ssl != NULL)
        SSL_free(sock_ctx->ssl);
    sock_ctx->ssl = NULL;

    if (has_error_string(sock_ctx))
        return -EPROTO;

    return -ECANCELED;
}


/**
 * Allocates an SSL object for a connection accepted by a server.
 * @param sock_ctx The context of the socket to prepare the SSL object for.
 * @returns 0 on success, or a negative errno on failure.
 */
int prepare_SSL_server(socket_ctx* sock_ctx) {

    sock_ctx->ssl = SSL_new(sock_ctx->ssl_ctx);
    if (sock_ctx->ssl == NULL)
        return -ECANCELED;

    return 0;
}



/**
 *******************************************************************************
 *                   HELPER FUNCTIONS FOR CONFIG LOADING
 *******************************************************************************
 */

/**
 * Converts the given tls_version enum into the OpenSSL-specific version.
 * @param version The version given to us by the config file.
 * @returns The OpenSSL representation of the TLS Version, or TLS1_2_VERSION
 * if no version was set (a safe default).
 */
long get_tls_version(enum tls_version version) {

    long tls_version = 0;

    switch(version) {
    case TLS_DEFAULT_ENUM:
        tls_version = TLS_MAX_VERSION;
        break;
    case TLS1_0_ENUM:
        tls_version = TLS1_VERSION;
        break;
    case TLS1_1_ENUM:
        tls_version = TLS1_1_VERSION;
        break;
    case TLS1_2_ENUM:
        tls_version = TLS1_2_VERSION;
        break;
    case TLS1_3_ENUM:
        tls_version = TLS1_3_VERSION;
        break;
    default:
        /* shouldn't happen */
        log_printf(LOG_ERROR, "Unknown TLS version specified\n");
    }

    return tls_version;
}

/**
 * Erases all previously-set ciphers in ciphers and sets them to the list of
 * ciphers in list.
 * @param ctx The context to load the given ciphers into.
 * @param list The list of names of ciphers to load.
 * @param num The size of list.
 * @returns 1 on success, or 0 if some of the ciphers could not be added.
 */
int load_cipher_list(SSL_CTX* ctx, char** list, int num) {

    char* ciphers;
    int ret;

    ret = concat_ciphers(list, num, &ciphers);
    if (ret != 1)
        return 0;

    ret = SSL_CTX_set_cipher_list(ctx, ciphers);
    if (ret != 1)
        goto end;
    
    /* returns some false negatives... but it's the best we've got */
    if (sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx)) < num) {
        /* Fewer ciphers were added than were specified */
        log_printf(LOG_ERROR, "Some cipher names were not recognized\n");
        ret = 0;
        goto end;
    }

end:
    free(ciphers);
    return ret;
}

/**
 * Erases all previously-set TLS 1.3 ciphers in ciphers and sets them to the
 * list of ciphers in list.
 * @param ctx The context to load the given ciphers into.
 * @param list The list of names of ciphers to load.
 * @param num The size of list.
 * @returns 1 on success, or 0 if some of the ciphers could not be added.
 */
int load_ciphersuites(SSL_CTX* ctx, char** list, int num) {

    char* ciphers;
    int ret;

    ret = concat_ciphers(list, num, &ciphers);
    if (ret != 1)
        return 0;

    ret = SSL_CTX_set_ciphersuites(ctx, ciphers);
    if (ret != 1)
        goto end;

    if (sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx)) < num) {
        log_printf(LOG_ERROR, "Some cipher names were not recognized\n");
        ret = 0;
        goto end;
    }

end:
    free(ciphers);
    return ret;
}

/**
 * Helper function for load_cipher_list and load_ciphersuites; takes a given
 * list of ciphers and converts them into the OpenSSL-defined format required
 * to set the cipher list or ciphersuites.
 * @param list The list of ciphers to be converted into OpenSSL cipherlist 
 * format.
 * @param num The number of ciphers in list.
 * @param out The converted cipherlist string (NULL-terminated).
 * @returns 1 on success, or 0 on error.
 */
int concat_ciphers(char** list, int num, char** out) {

    char* ciphers;
    int offset = 0;
    int len = 0;

    for (int i = 0; i < num; i++)
        len += strlen(list[i]) + 1; /* +1 for colon (or '\0' at end) */

    ciphers = malloc(len);
    if (ciphers == NULL) {
        log_printf(LOG_ERROR, "Malloc failed while loading cipher list: %s\n",
                strerror(errno));
        return 0;
    }

    for (int i = 0; i < num; i++) {
        int cipher_len = strlen(list[i]);

        memcpy(&ciphers[offset], list[i], cipher_len);
        ciphers[offset + cipher_len] = ':';

        offset += cipher_len + 1;
    }

    ciphers[len - 1] = '\0';

    if (len != offset) {
        log_printf(LOG_WARNING, "load_cipher_list had unexpected results\n");
        free(ciphers);
        return 0;
    }

    *out = ciphers;
    return 1;
}

/**
 * Loads the given certificate authority .pem or .der-encoded certificates into
 * ctx from the file or directory specified by path. This function will load in
 * all certificates found in a directory, or all certificates found in an 
 * individual file (if the file is capable of containing more than one 
 * certificate). If CA_path is null, this function will attempt to find the 
 * default location of CA certificates on your machine.
 * @param ctx The SSL_CTX to load certificate authorities in to.
 * @param CA_path A NULL-terminated string representing the path to the 
 * directory/file; or NULL if the default locations are desired.
 * @returns 1 on success, or 0 if an error occurred.
 */
int load_certificate_authority(SSL_CTX* ctx, char* CA_path) {

    struct stat file_stats;

    if (CA_path == NULL) { /* No CA file given--search for one based on system */
        if (access(UBUNTU_DEFAULT_CA, F_OK) != -1) {
            CA_path = UBUNTU_DEFAULT_CA;
            /* log_printf(LOG_INFO, "Found the Ubuntu CA file.\n"); */
        
        } else if(access(FEDORA_DEFAULT_CA, F_OK) != -1) {
            CA_path = FEDORA_DEFAULT_CA;
            /* log_printf(LOG_INFO, "Found the Fedora CA file.\n"); */
        
        } else { /* UNSUPPORTED OS */
            /* log_printf(LOG_ERROR, "Unable to find valid CA location.\n"); */
            return 0;
        }
    }

    
    if (stat(CA_path, &file_stats) != 0) {
        log_printf(LOG_ERROR, "Failed to access CA file %s: %s\n", 
                CA_path, strerror(errno));
        return 0;
    }

    if (S_ISREG(file_stats.st_mode)) {
        /* is a file */
        return SSL_CTX_load_verify_locations(ctx, CA_path, NULL);

    } else if (S_ISDIR(file_stats.st_mode)) {
        /* is a directory */
        return SSL_CTX_load_verify_locations(ctx, NULL, CA_path);

    } else {
        log_printf(LOG_ERROR, "Loading CA certs--path not file or directory\n");
        return 0;
    }
}


/**
 * Associates the given file descriptor with the given connection and 
 * enables its bufferevent to read and write freely.
 * @param sock_ctx The connection to have the file descriptor associated with.
 * @param ifd The file descriptor of an internal program that will
 * communicate to the daemon through plaintext.
 * @returns 0 on success, or -ECONNABORTED on failure.
 */
int associate_fd(socket_ctx* sock_ctx, evutil_socket_t ifd) {

    /* Possibility of failure is acutally none in current libevent code */
    if (bufferevent_setfd(sock_ctx->plain.bev, ifd) != 0)
        goto err;

    /* This function *unlikely* to fail, but if we want to be really robust...*/
    if (bufferevent_enable(sock_ctx->plain.bev, EV_READ | EV_WRITE) != 0)
        goto err;

    return 0;
err:
    log_printf(LOG_ERROR, "associate_fd failed.\n");
    return -ECONNABORTED; /* Only happens while client is connecting */
}
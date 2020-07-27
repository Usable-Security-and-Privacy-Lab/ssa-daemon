#include "config.h"
#include "log.h"
#include "error.h"
#include "daemon_structs.h"
#include "cipher_selection.h"

#include <fcntl.h> /* for S_IFDIR/S_IFREG constants */
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define UBUNTU_DEFAULT_CA "/etc/ssl/certs/ca-certificates.crt"
#define FEDORA_DEFAULT_CA "/etc/pki/tls/certs/ca-bundle.crt"
#define MAX_NUM_CIPHERS 37
#define MAX_CIPHERSUITE_STRINGLEN 150
#define DISABLE_INSECURE_CIPHERS ":!SSLv3:!TLSv1:!TLSv1.1:!eNULL:!aNULL:!RC4:!MD4:!MD5"

int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);

/**
* gets cipher used in connection
* @param conn connection object
* @param data stores info to be passed to the user
* @param data_len length of data
* @returns last_negotiated last negotiated cipher
*/
int get_last_negotiated(socket_ctx* conn, const char** data, unsigned int* data_len) { //maybe delete

    SSL* ssl = (conn->ssl);
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    const char* cipher_name = SSL_CIPHER_get_name(cipher);

    if(cipher_name != NULL) {

        unsigned int cipher_len = strlen(cipher_name);
        char* cipher_str = (char*) malloc(cipher_len + 1);

        strcpy(cipher_str, cipher_name);
        //free(*data);
        *data = cipher_str;
        *data_len = cipher_len + 1;

        log_printf(LOG_INFO, "Negotiated cipher: %s\n", cipher_str);

        return 0;
    }
    else {
        return -1;
    }
}



/*******************************************************************************
 *                            GETSOCKOPT FUNCTIONS
 ******************************************************************************/

/**
 * Allocates a string list of enabled ciphers to data.
 * @param conn The specified connection context to retrieve the ciphers from
 * @param data A pointer to a char pointer where the cipherlist string will be
 * allocated to, or NULL if no ciphers were available from the given connection.
 * This should be freed after use.
 * @returns 0 on success; -errno otherwise.
 */
int get_enabled_ciphers(socket_ctx* sock_ctx, 
            char** data, unsigned int* len) {
    
    char* ciphers_str = NULL;

    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(sock_ctx->ssl);
    /* FEATURE: use SSL_get1_supported_ciphers if connected */
    if (ciphers == NULL)
        goto end; /* no ciphers available; just return NULL. */

    int ciphers_len = get_ciphers_strlen(ciphers);
    if (ciphers_len == 0)
        goto end;

    ciphers_str = (char*) malloc(ciphers_len + 1);
    if (ciphers_str == NULL) {
        set_err_string(sock_ctx, "Daemon error: failed to allocate buffer");
        return -errno;
    }

    if (get_ciphers_string(ciphers, ciphers_str, ciphers_len + 1) != 0)
        log_printf(LOG_ERROR, "Buffer had to be truncated--shouldn't happen\n");

    *len = ciphers_len + 1;
end:
    *data = ciphers_str;
    return 0;
}


/*
*******************************************************************************
*                           SETSOCKOPT FUNCTIONS
*******************************************************************************
*/

/**
 * detects cipher version and loads appropiate cipher list
 * @param conn  connection object
 *    @param cipher cipher to load
 * @returns 0 on success and -1 on failure
 */
int disable_ciphers(socket_ctx* conn, char* cipher) {
    log_printf(LOG_DEBUG, "Received disable cipher notification %s\n", cipher);
    SSL_CTX* ctx = (conn->ssl_ctx);
    char* cipherlist;
    unsigned int len;
    int ret;
    char* version = get_string_version(cipher);
    if(strcmp(version, "TLSv1.3") == 0) { //make a loop to handle both versions at once
        get_ciphersuite_string(conn, &cipherlist, &len);
        log_printf(LOG_DEBUG, "finished receiving suite string %s\n", cipherlist);
        ret = deletion_loop(cipher, &cipherlist);
        if (ret == -1) {
            log_printf(LOG_DEBUG, "Unable to remove name\n");
            return -1;
        }
        if (SSL_CTX_set_ciphersuites(ctx, cipherlist) == 1) {
            log_printf(LOG_DEBUG, "Successful SSL ciphersuite update %s\n", cipherlist);
            ret = 0;
        } else {
            log_printf(LOG_DEBUG, "Failed SSL ciphersuite update %s\n", cipherlist);
            ret = -1;
        }
    
    } else {

        get_cipher_list_string(conn, &cipherlist, &len);

        char* blacklist = DISABLE_INSECURE_CIPHERS;

        ret = deletion_loop(cipher, &cipherlist);

        strcat(cipherlist, blacklist);
        log_printf(LOG_DEBUG, "appended blacklist\n");

        if(SSL_CTX_set_cipher_list(ctx, cipherlist) == 1) {
            log_printf(LOG_DEBUG, "Successful SSL cipherlist update %s\n", cipherlist);
            ret = 0;
        
        } else {
            log_printf(LOG_DEBUG, "Failed SSL cipherlist update %s\n", cipherlist);
            ret = -1;
        }
    }

    log_printf(LOG_DEBUG, "finished disabling\n");
    return ret;
}
/*
* enables cipher
* @param conn the connection
* @param cipher cipher to be reenabled
* @returns 0 on success, -1 on failure
*/
int enable_cipher(socket_ctx* conn, char* cipher) {
    log_printf(LOG_DEBUG, "Received enable cipher notification%s\n", cipher);
    SSL_CTX* ctx = (conn->ssl_ctx);
    char* cipherlist;
    unsigned int cipherlist_len; //is length necessary
    int ret;
    char* version = get_string_version(cipher); //needs to be tested replace below if statement

    if(strcmp(version, "TLSv1.3") == 0) {

        get_ciphersuite_string(conn, &cipherlist, &cipherlist_len);
        append_to_cipherstring(cipher, &cipherlist);
        if(SSL_CTX_set_ciphersuites(ctx, cipherlist) == 1) {
            log_printf(LOG_DEBUG, "Successful SSL ciphersuite update %s\n", cipherlist);
            ret = 0;
        }
        else {
            log_printf(LOG_DEBUG, "Failed SSL ciphersuite update\n");
            ret = -1;
        }
    }
    else {
        get_cipher_list_string(conn, &cipherlist, &cipherlist_len);
        append_to_cipherstring(cipher, &cipherlist);
        char* blacklist = DISABLE_INSECURE_CIPHERS;
        strcat(cipherlist, blacklist);
        log_printf(LOG_DEBUG, "appended blacklist\n");
        if(SSL_CTX_set_cipher_list(ctx, cipherlist) == 1) {
            log_printf(LOG_DEBUG, "Successful SSL cipherlist update\n %s\n", cipherlist);
            ret = 0;
        }
        else {
            log_printf(LOG_DEBUG, "Failed SSL cipherlist update\n");
            ret = -1;
        }
    }
    free(cipherlist);
    return ret;
}

/*
*******************************************************************************
*                             HELPER FUNCTIONS
*******************************************************************************
*/


/**
 * makes stack of ciphers into a string of ciphersuites
 * ciphers stack of all ciphers associated with ssl object
 * buf buffer to store resulting string
 * buf_len keeps track of string length
 */
int get_ciphersuite_string(socket_ctx* conn, char** buf, unsigned int* buf_len) { //FIXME rename buf
STACK_OF(SSL_CIPHER)* cipherlist = SSL_CTX_get_ciphers(conn->ssl_ctx);
    *buf = "";
    *buf = malloc(MAX_CIPHERSUITE_STRINGLEN);
int index = 0;
    char* ciphersuites = *buf;

    for (int i = 0; i < sk_SSL_CIPHER_num(cipherlist); i++) {
        const SSL_CIPHER* curr = sk_SSL_CIPHER_value(cipherlist, i);
        const char* name = SSL_CIPHER_get_name(curr);
        char* namecpy = malloc(strlen(name) + 1);
        strcpy(namecpy, name);
        //log_printf(LOG_DEBUG, "Cipher %s\n", name);
        //char* version = SSL_CIPHER_get_version(curr); //use this to replace subtring check
        //if (version == "TLSv1.3")
        if (strcmp(get_string_version(namecpy), "TLSv1.3") == 0) {

            strcpy(&ciphersuites[index], name); //CHECKME
            log_printf(LOG_DEBUG, "Cipher2 %s\n", name);
            index += strlen(name);
            ciphersuites[index] = ':';
            index += 1;

        }
        else {
            log_printf(LOG_DEBUG, "Cipher1 %s\n", name);
            break;
        }
        free(namecpy);
    }

    ciphersuites[index - 1] = '\0'; /* change last ':' to '\0' */
    log_printf(LOG_DEBUG, "Cipher3 %s\n", ciphersuites);
    strcpy(*buf, ciphersuites);
    *buf_len = strlen(ciphersuites) + 1;
    log_printf(LOG_DEBUG, "len: %d\n", *buf_len);
    log_printf(LOG_DEBUG, "Finished forming ciphersuites %s\n", *buf);
    return 0;
}

/**
 * sorts ciphers associated with ssl object for TLS version 1.2 and beneath
 * conn associated connection
 *    @param buf buffer to store data
 * @param buf_len keeps track of buffer length
 * @returns 0 on success -1 on failure
 */
int get_cipher_list_string(socket_ctx* conn, char** buf, unsigned int* buf_len) {
    STACK_OF(SSL_CIPHER)* cipherstack = SSL_CTX_get_ciphers(conn->ssl_ctx);

    int ciphers_len = get_ciphers_strlen(cipherstack);
    *buf = ""; //empties buffer //free?
    *buf = malloc(ciphers_len);
int index = 0;
char* cipherlist = *buf;
log_printf(LOG_DEBUG, "Num ciphers: %d\n", sk_SSL_CIPHER_num(cipherstack));
for(int i = 0; i < sk_SSL_CIPHER_num(cipherstack); i++) {
        const SSL_CIPHER* curr_cipher = sk_SSL_CIPHER_value(cipherstack, i);
        const char* name = SSL_CIPHER_get_name(curr_cipher);
        char* cipher_name = malloc(50);
        strcpy(cipher_name, name);
        char* version = get_string_version(cipher_name); //use this to replace subtring check
        free(cipher_name);

        if (strcmp(version, "TLSv1.3") != 0) {


            strcpy(&cipherlist[index], name);
    log_printf(LOG_DEBUG, "Successfullly received: %s\n", name);
    index += strlen(name);
            cipherlist[index] = ':';
            index += 1;

        }

    }
cipherlist[index - 1] = '\0'; /* change last ':' to '\0' */
    log_printf(LOG_DEBUG, "Cipher3 %s\n", cipherlist);
    strcpy(*buf, cipherlist);
    *buf_len = strlen(cipherlist) + 1;
    log_printf(LOG_DEBUG, "len: %d\n", *buf_len);
    log_printf(LOG_DEBUG, "Finished forming cipherlist %s\n", *buf);
    return -1;
}
/**
 * appends given cipher to cipherlist in data
 * @param cipher specific cipher as a string
 * @param data pointer to cipherstring that contains cipher
 * @returns 0 on success -1 on failure
 */
int append_to_cipherstring(char* cipher, char** cipherstring) {
    char cipher_division[2] = ":";
    if(cipher[0] != '-' && cipher[0] != '!') { //won't occur in tls 1.3

        strcat(cipher, cipher_division);
        char* cipher_with_colon = malloc(strlen(*cipherstring) + 100 + strlen(cipher) + 2);
        // datalen + strlen of cipher + black list len + cipher_division + null

        strcpy(cipher_with_colon, cipher);
        strcat(cipher_with_colon, *cipherstring);
        strcpy(*cipherstring, cipher_with_colon);
        free(cipher_with_colon);

        return 0;
    }
    else {
        log_printf(LOG_ERROR, "Please use TLS_DISABLE_CIPHER to disable cipher.\n"); //change, seen by developers only
        return -1;
    }
}

char* get_string_version(char* cipher_to_check) {
    //todo hardcode list of tlsv1.3 strings here and check if provided cipher matches
    //will have to update if new ciphers are added to TLSv1.3
    int len = strlen(cipher_to_check);
    if(cipher_to_check[len - 1] == ':') {
        cipher_to_check[len - 1] = '\0';
    }
    char* gcm_384 = "TLS_AES_256_GCM_SHA384";
char* gcm_256 = "TLS_AES_128_GCM_SHA256";
char* chacha_256 = "TLS_CHACHA20_POLY1305_SHA256";
char* ccm_256 = "TLS_AES_128_CCM_SHA256";
char* ccm_8_256 = "TLS_AES_128_CCM_8_SHA256";
    char* tlsv13 = "TLSv1.3";
    char* tlsv12 = "TLSv12";

    if(!strcmp(cipher_to_check,gcm_384) || !strcmp(cipher_to_check,gcm_256) || !strcmp(cipher_to_check,chacha_256) ||
    !strcmp(cipher_to_check,ccm_256) || !strcmp(cipher_to_check,ccm_8_256)) {
        return tlsv13;
    }
    else {
        return tlsv12;
    }
}
/**
* Makes a new cipherstring without provided cipher
* @param cipher cipher to be Deleted
* @param cipherlist list to delete ciphers from
* @returns 0 on success error code on failure
*/
int delete_from_cipherlist(char* cipher, char** cipherlist) {
    char* new_cipherlist = malloc(strlen(*cipherlist) + 50); //space for new cipher
    new_cipherlist[0] = '\0';
    int has_cipher = 0;

    const char delimiter[2] = ":";
    char* cipher_token = strtok(*cipherlist, delimiter);


    while (cipher_token != NULL) {
        if(strcmp(cipher_token, cipher) != 0) {
            log_printf(LOG_DEBUG, "Cipher To Keep: %s\n", cipher_token);
            strcat(new_cipherlist, cipher_token);
            strcat(new_cipherlist, delimiter);

        }
        else {
            log_printf(LOG_INFO, "Cipher deleted: %s\n", cipher_token);
            has_cipher = 1;
        }
        cipher_token = strtok(NULL, delimiter);
        log_printf(LOG_DEBUG, "Cipher Token: %s\n", cipher_token);
    }

    new_cipherlist[strlen(new_cipherlist) - 1] = '\0'; //pops back last ":"

    strcpy(*cipherlist, new_cipherlist);
    free(new_cipherlist);
    /* assert: all ciphers to remove now removed */
    if (has_cipher)
        return 0;
    else
        return -1;

}
/**
* Iterates through ciphers provided and deletes them
*    @param cipher cipherstring (one or many ciphers) to be deleted
* @param cipherlist list thet ciphers will be deleted from
* @returns 0 on success -1 on failure
*/
int deletion_loop(char* cipher, char** cipherlist) { //return error code from deletion
const char delimiter[2] = ":";
char* cipher_token = strtok(cipher, delimiter);
char** to_delete = malloc(strlen(*cipherlist));
int index = 0;
int ret = 0;

while (cipher_token != NULL) {

        to_delete[index] = cipher_token;
        index++;
        if(index > MAX_NUM_CIPHERS) {
                ret = -1;
        }

        cipher_token = strtok(NULL, delimiter);
}

for(int i = 0; i < index; i++) {
    log_printf(LOG_INFO, "Index: %d\n", index);
    log_printf(LOG_INFO, "Cipher to delete: %s\n", to_delete[i]);
    log_printf(LOG_INFO, "Cipher list: %s\n", *cipherlist);
    ret = delete_from_cipherlist(to_delete[i], cipherlist);
    log_printf(LOG_INFO, "Cipher list after deletion: %s\n", *cipherlist);
        if(ret == -1) {
        return ret;
    }
}

free(to_delete);
return ret;
}


/**
 * Converts a stack of SSL_CIPHER objects into a single string representation
 * of all the ciphers, with each individual cipher separated by a ':'.
 * @param ciphers The stack of ciphers to convert
 * @param buf The provided buffer to put the string into.
 * @param buf_len The length of the provided buffer.
 * @returns 0 on success; -1 if the buffer was not big enough to store all of
 * the ciphers and had to be truncated.
 */
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len) {
    int index = 0;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
        const SSL_CIPHER* curr = sk_SSL_CIPHER_value(ciphers, i);
        const char* cipher = SSL_CIPHER_get_name(curr);

        if ((index + strlen(cipher) + 1) > buf_len) {
            buf[index-1] = '\0';
            return -1; /* buf not big enough */
        }

        strcpy(&buf[index], cipher);
        index += strlen(cipher);
        buf[index] = ':';
        index += 1;
    }
    buf[index - 1] = '\0'; /* change last ':' to '\0' */
    return 0;
}

/**
 * Determines the combined string length of all the cipher strings.
 * @param ciphers The cipher list to measure string lengths from.
 * @returns The combined string length of the ciphers in the list (as if
 * there were ':' characters between each cipher and a terminating
 * '\0' at the end). Never returns an error code.
 */
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers) {
    int len = 0;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
        const char* curr = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i));
        len += strlen(curr) + 1; /* add ':' */
    }
    if (len != 0)
        len -= 1; /* removes the last ':' */
    return len;
}
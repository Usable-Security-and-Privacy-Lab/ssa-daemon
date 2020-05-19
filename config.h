#ifndef CONFIG_H
#define CONFIG_H

#include <openssl/ssl.h>


#define DEFAULT_CONFIG_PATH "test_files/config.yml"

#define MAX_CERTS 5
#define MAX_KEYS 5


enum tls_version_t {
    TLS_DEFAULT_ENUM = 0,
    TLS1_0_ENUM,
    TLS1_1_ENUM,
    TLS1_2_ENUM,
    TLS1_3_ENUM
};

typedef struct cert_pair_st {

} cert_pair;

typedef struct client_settings_st {

    char* ca_path; /* can be file or folder */

    /* WARNING: make sure each only contains one cipher (eg AES_GCM:NULL). */
    /* ANOTHER WARNING: also watch out for '\b' */
    char** cipher_list; 
    int cipher_list_cnt;

    char** ciphersuites;
    int ciphersuite_cnt;
 
    int tls_compression;

    enum tls_version_t min_tls_version;
    enum tls_version_t max_tls_version;

    char* certificate_path[MAX_CERTS]; /* can be file or folder */
    int num_certs;

    char* privatekey_file[MAX_KEYS];
    int num_keys;

} client_settings;

typedef struct server_settings_st {
    
    char* ca_path;

    char** cipher_list;
    int cipher_list_cnt;

    char** ciphersuites;
    int ciphersuite_cnt;

    int tls_compression;
    int session_tickets;

    enum tls_version_t min_tls_version;
    enum tls_version_t max_tls_version;

    char* certificate_path[MAX_CERTS]; /* can be file or folder */
    int num_certs;

    char* privatekey_file[MAX_KEYS];
    int num_keys;

    /* TODO: future stuff for session caching and whatnot here */

} server_settings;

typedef struct global_settings_st {
    
    client_settings *client;
    server_settings *server;

} global_settings;


global_settings* parse_config(char* file_path);
void global_settings_free(global_settings* settings);



#endif
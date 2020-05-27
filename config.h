#ifndef CONFIG_H
#define CONFIG_H

#include <openssl/ssl.h>


#define DEFAULT_CONFIG_PATH "test_files/config.yml"

#define MAX_CERTKEY_PAIRS 5


enum tls_version_t {
    TLS_DEFAULT_ENUM = 0,
    TLS1_0_ENUM,
    TLS1_1_ENUM,
    TLS1_2_ENUM,
    TLS1_3_ENUM
};


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

    char* certificate_path[MAX_CERTKEY_PAIRS]; /* can be file or folder */
    int num_certs;

    char* privatekey_file[MAX_CERTKEY_PAIRS];
    int num_keys;

    int session_timeout;
    int max_cert_chain_depth;

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

    char* certificates[MAX_CERTKEY_PAIRS]; /* can be file or folder */
    int cert_cnt;

    char* private_keys[MAX_CERTKEY_PAIRS];
    int key_cnt;

    int session_timeout;

    /* TODO: future stuff for session caching and whatnot here */

} server_settings;

typedef struct global_settings_st {
    
    client_settings *client;
    server_settings *server;

} global_settings;


int parse_config(char* file_path, global_settings** settings);
void global_settings_free(global_settings* settings);



#endif
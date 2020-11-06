#ifndef SSA_CONFIG_H
#define SSA_CONFIG_H

#include "daemon_structs.h"

#define DEFAULT_CONFIG_PATH "config.yml"
#define PARSER_KEY_CNT 15

typedef struct file_stream_st file_stream;
typedef struct label_pair_st label_pair;

extern const label_pair parser_keys[PARSER_KEY_CNT];



struct label_pair_st {
    char *label;
    int (*func)(file_stream *, global_config *);
};

/**
 * Parses a given config file and fills an allocated global_config struct 
 * with the configurations to be used by the daemon. Once the parser has 
 * finished reading in information from the .yml config file, the global_config
 * struct should remain unchanged--any modifications of settings (such as by
 * `setsockopt() or `getsockopt()` calls) should only affect individual 
 * connections, not the overarching configuration of the daemon.
 * @param file_path The path to the .yml config file, or NULL if the default
 * file path is desired.
 * @returns A pointer to a newly allocated global_config struct, or NULL on 
 * error. If the file specified by file_path cannot be opened, this function
 * will fail.
 */
global_config* parse_config(char* file_path);


/**
 * Performs a deep free of all data structures allocated within global_config.
 * @param settings The global_config to be freed.
 */
void global_settings_free(global_config* settings);

char* utf8_to_ascii(unsigned char* src, ssize_t len);



//==============================================================================
// Helper functions for config_options.c
//==============================================================================

int parser_read_string(file_stream *fs, char **str);
int parser_read_int(file_stream *fs, int *val, int min, int max);
int parser_read_boolean(file_stream *fs, int *val);
int parser_read_list(file_stream *fs, char **str_list[]);


#endif

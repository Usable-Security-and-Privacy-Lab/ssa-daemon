#ifndef SSA_CONFIG_H
#define SSA_CONFIG_H

#include "daemon_structs.h"


#define DEFAULT_CONFIG_PATH "config.yml"


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



#endif

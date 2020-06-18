#ifndef SSA_CONFIG_H
#define SSA_CONFIG_H

#include "daemon_structs.h"


#define DEFAULT_CONFIG_PATH "test_files/config.yml"


global_config* parse_config(char* file_path);
void global_settings_free(global_config* settings);



#endif
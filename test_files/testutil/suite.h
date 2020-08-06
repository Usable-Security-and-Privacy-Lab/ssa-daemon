#ifndef SSA_SUITE_H
#define SSA_SUITE_H


#define NO_SERVER NULL

void start_daemon(const char* daemon_config, int use_valgrind);
void start_server(const char* server_path);
void cleanup();


#endif
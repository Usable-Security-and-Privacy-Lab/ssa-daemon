
/**
 * Any libcyaml-specific functions should go in here and not the .h file;
 * we want this to be the only file that references the library in case
 * we decide to modify it in the future.
 */

#include <ctype.h>
#include <errno.h>
#include <yaml.h>
#include <limits.h>
#include <bsd/stdlib.h>

#include "config.h"
#include "log.h"

#define MAX_STRLIST_SIZE 100

/* These are all of the possible config labels. To add, define another here
 * and add it to the if/else chain in parse_next_<client/server>_setting().
 * Note that these should be in lowercase--it's what we convert input to. */
#define CA_PATH         "ca-path"
#define CIPHER_LIST     "cipher-list"
#define CIPHERSUITES    "ciphersuites"
#define TLS_COMPRESSION "tls-compression"
#define SESSION_TICKETS "session-tickets"
#define MIN_TLS_VERSION "min-tls-version"
#define MAX_TLS_VERSION "max-tls-version"
#define CERT_PATH       "cert-path"
#define KEY_PATH        "key-path"
#define SESSION_TIMEOUT "session-timeout"
#define CERT_V_DEPTH    "cert-verification-depth"


/* different values that we accept in place of just 'true' or 'false' */
#define SETTING_TRUE     "true"
#define SETTING_YES      "yes"
#define SETTING_Y        "y"
#define SETTING_ON       "on"
#define SETTING_ENABLED  "enabled"

#define SETTING_FALSE    "false"
#define SETTING_NO       "no"
#define SETTING_N        "n"
#define SETTING_OFF      "off"
#define SETTING_DISABLED "disabled"

/* acceptable tls version parameters */
#define TLS1_0_STRING "tls-1.0"
#define TLS1_1_STRING "tls-1.1"
#define TLS1_2_STRING "tls-1.2"
#define TLS1_3_STRING "tls-1.3"

#define TLS1_0_ALT_STRING "1.0"
#define TLS1_1_ALT_STRING "1.1"
#define TLS1_2_ALT_STRING "1.2"
#define TLS1_3_ALT_STRING "1.3"


int parse_next_client_setting(yaml_parser_t* parser, client_settings* client);
int parse_next_server_setting(yaml_parser_t* parser, server_settings* server);

int parse_string(yaml_parser_t* parser, char** string);
int parse_string_list(yaml_parser_t* parser, char** strings[], int* num);
int parse_string_list_member(yaml_parser_t* parser, char** strings, int* num);
int parse_boolean(yaml_parser_t* parser, int* enabled);
int parse_tls_version(yaml_parser_t* parser, enum tls_version_t* version);

int parse_stream(yaml_parser_t* parser, global_settings* settings);
int parse_document(yaml_parser_t* parser, global_settings* settings);
int parse_client(yaml_parser_t* parser, global_settings* settings);
int parse_server(yaml_parser_t* parser, global_settings* settings);

int check_label_to_parse(yaml_parser_t* parser, char* label);
yaml_event_type_t parse_next_event(yaml_parser_t* parser);
char* parse_next_scalar(yaml_parser_t* parser);

char* utf8_to_ascii(unsigned char* src, ssize_t len);
void str_tolower(char* string);
int is_server(char* label);
int is_client(char* label);
int is_enabled(char* label);

void log_parser_error(yaml_parser_t parser);

/*******************************************************************************
 *              UNDERSTANDING THIS FILE (AND LIBYAML IN GENERAL)
 *******************************************************************************
 *
 * In libyaml (and YAML in general), .yml configuration files can be represented
 * by a sequence of tokens, or 'events'. This series of events always starts 
 * with a STREAM_START event and ends with a STREAM_END event, to indicate the 
 * start and end of a given file. Furthermore, a file may have one or multiple
 * 'documents' within it. The start of a document is designated by three dashes,
 * '---'; the end of a document can be designated the same way if another 
 * document is to be started immediately after it, or by three dots '...' if it
 * is the last document in the file. If only one document exists in a file, 
 * these are implied and do not need to be added (this is what we do).
 * Then, if one uses a set of one or more key:value pairs within the document,
 * these are designated by MAPPING_START and MAPPING_END tokens wrapped around
 * the set of them. If a list (designated by dashes '-') is found in the 
 * document, they are designated by a SEQUENCE_START and SEQUENCE_END event
 * at the start and end of the list. Other than that, every value scanned is
 * represented by a SCALAR event (there are more possibilities than this but 
 * this is all we'll use).
 *  
 * So, if you had the document:
 * ---
 * client: hello
 * ...
 * 
 * It would be represented by the following tokens:
 * STREAM_START
 * DOCUMENT_START
 * MAPPING_START
 * SCALAR ('client')
 * SCALAR('hello')
 * MAPPING_END
 * DOCUMENT_END
 * STREAM_END
 * 
 * Similarly, the following document:
 * client:
 *   min-tls-version: 1.2
 *   cipher-list:
 *     - cipher-1
 *     - cipher-2
 *     - cipher-3
 *   tls-compression: off
 *   alpn-protos: on
 * 
 * Would be represented by the following tokens:
 * STREAM_START
 * DOCUMENT_START
 * MAPPING_START
 * SCALAR ('min-tls-version')
 * SCALAR ('1.2')
 * SCALAR ('cipher-list')
 * SEQUENCE_START
 * SCALAR ('cipher-1')
 * SCALAR ('cipher-2')
 * SCALAR ('cipher-3')
 * SEQUENCE_END
 * SCALAR ('tls-compression')
 * SCALAR ('off')
 * MAPPING_END
 * DOCUMENT_END
 * STREAM_END
 * 
 * You'll notice that MAPPING_START/END and SEQUENCE START/END only wraps
 * around the entire set of tokens, not around each one. A corollary of this
 * is that key:value pairs are only implied, with one after the other. Lastly,
 * the key:value pair with the list has a SCALAR key, and then the entire list
 * covered by SEQUENCE_START and SEQUENCE_END is the value of that key.
 * 
 */


/*******************************************************************************
 *    THE IMPORTANT STUFF (WHERE TO ADD ADDITIONAL CONFIG SETTINGS EASILY)
 ******************************************************************************/


/**
 * Parses the next key:value pair in parser, and adds it to the daemon's client
 * settings.
 * @returns 0 on success, 1 if no more key:value or key:list pairs are left to 
 * be parsed, or -1 on error.
 */
int parse_next_client_setting(yaml_parser_t* parser, client_settings* client) {

    yaml_event_t event;
    char* label;
    int ret;
    
    if (yaml_parser_parse(parser, &event) != 1)
        return -1;

    if (event.type == YAML_MAPPING_END_EVENT) {
        yaml_event_delete(&event);
        return 1;
    }

    if (event.type != YAML_SCALAR_EVENT) {
        yaml_event_delete(&event);
        return -1;
    }

    label = utf8_to_ascii(event.data.scalar.value, event.data.scalar.length);
    if (label == NULL)
        return -1;
    
    yaml_event_delete(&event);
    str_tolower(label);

    /* This is the list of all possible client setting labels;
     * ADD ADDITIONAL SETTINGS AS NEEDS BE HERE (as well as to the struct) */
    if (strcmp(label, CA_PATH) == 0) {
        ret = parse_string(parser, &client->ca_path);

    } else if (strcmp(label, CIPHER_LIST) == 0) {
        ret = parse_string_list(parser, 
                &client->cipher_list, &client->cipher_list_cnt);

    } else if (strcmp(label, CIPHERSUITES) == 0) {
        ret = parse_string_list(parser,
                &client->ciphersuites, &client->ciphersuite_cnt);

    } else if (strcmp(label, TLS_COMPRESSION) == 0) {
        ret = parse_boolean(parser, &client->tls_compression);

    } else if (strcmp(label, MIN_TLS_VERSION) == 0) {
        ret = parse_tls_version(parser, &client->min_tls_version);

    } else if (strcmp(label, MAX_TLS_VERSION) == 0) {
        ret = parse_tls_version(parser, &client->max_tls_version);

    } else if (strcmp(label, SESSION_TIMEOUT) == 0) {
        ret = parse_integer(parser, &client->session_timeout);

    } else if (strcmp(label, CERT_V_DEPTH) == 0) {
        ret = parse_integer(parser, &client->cert_verification_depth);

    } else {
        log_printf(LOG_ERROR, "Config: Undefined label %s\n", label);
        ret = -1;
    }
    
    free(label);
    return ret;
}

/**
 * Parses the next key:value pair in parser, and adds it to the daemon's server
 * settings. Note that the settings don't need to be parsed in any particular
 * order; but if a string setting is read twice, it should fail the parsing.
 * @returns 0 on success, 1 if no more key:value or key:list pairs are left to 
 * be parsed, or -1 on error.
 */
int parse_next_server_setting(yaml_parser_t* parser, server_settings* server) {

    yaml_event_t event;
    char* label; 
    int ret;
    
    if (yaml_parser_parse(parser, &event) != 1)
        return -1;

    if (event.type == YAML_MAPPING_END_EVENT) {
        yaml_event_delete(&event);
        return 1;
    }

    if (event.type != YAML_SCALAR_EVENT) {
        yaml_event_delete(&event);
        return -1;
    }

    label = utf8_to_ascii(event.data.scalar.value, event.data.scalar.length);
    if (label == NULL)
        return -1;
    
    yaml_event_delete(&event);
    str_tolower(label);

    /* This is the list of all possible server setting labels--ADD HERE */
    if (strcmp(label, CA_PATH) == 0) {
        ret = parse_string(parser, &server->ca_path);

    } else if (strcmp(label, CIPHER_LIST) == 0) {
        ret = parse_string_list(parser, 
                &server->cipher_list, &server->cipher_list_cnt);

    } else if (strcmp(label, CIPHERSUITES) == 0) {
        ret = parse_string_list(parser,
                &server->ciphersuites, &server->ciphersuite_cnt);

    } else if (strcmp(label, TLS_COMPRESSION) == 0) {
        ret = parse_boolean(parser, &server->tls_compression);

    } else if (strcmp(label, SESSION_TICKETS) == 0) {
        ret = parse_boolean(parser, &server->session_tickets);

    } else if (strcmp(label, MIN_TLS_VERSION) == 0) {
        ret = parse_tls_version(parser, &server->min_tls_version);

    } else if (strcmp(label, MAX_TLS_VERSION) == 0) {
        ret = parse_tls_version(parser, &server->max_tls_version);

    } else if (strcmp(label, SESSION_TIMEOUT) == 0) {
        ret = parse_integer(parser, &server->session_timeout);
    /*
    } else if (strcmp(label, CERT_PATH) == 0) {
        ret = parse_string(parser, &server->certificate_path[server->num_keys]);
        server->num_keys++;

    } else if (strcmp(label, KEY_PATH) == 0)
        ret = parse_string(parser, &server->privatekey_file);
        server->num_keys++;
    */
    } else {
        log_printf(LOG_ERROR, "Undefined label %s\n", label);
        ret = -1;
    }

    free(label);
    return ret;
}

/*
 *******************************************************************************
 *      USE THESE FUNCTIONS TO PARSE INFO INTO THE GLOBAL_SETTINGS STRUCT
 *******************************************************************************
 */ 

/* Helpful parsing functions */

/**
 * Takes the next event from the given parser and converts its value into an 
 * ASCII string, which is then assigned to string. 
 * @param parser The parser to parse the next event from.
 * @param string An address for which to allocate the parsed string to.
 * @returns 0 on success, or -1 if an error occurred.
 */
int parse_string(yaml_parser_t* parser, char** string) {
    
    if (*string != NULL) {
        log_printf(LOG_ERROR, "Config: Label assigned twice\n");
        return -1;
    }

    *string = parse_next_scalar(parser);
    if (*string == NULL)
        return -1;

    return 0;
}

/**
 * Takes the next arbitrary number of events (cannot be more than 
 * MAX_STRLIST_SIZE) from the given parser and converts their value 
 * into an array of ASCII strings, which is then assigned to strings.
 * The value of num is then updated to reflect the new number of strings in
 * the list. 
 * @param parser The parser to parse the next event sequence from.
 * @param string An address for which to allocate the parsed string list to.
 * @returns 0 on success, or -1 if an error occurred.
 */
int parse_string_list(yaml_parser_t* parser, char** strings[], int* num) {

    if (*strings != NULL) {
        log_printf(LOG_ERROR, "Config: Label assigned twice\n");
        return -1;
    }

    /* the following +1 is to ensure the string list is NULL-terminated */
    *strings = calloc(1, (MAX_STRLIST_SIZE + 1) * sizeof(char*));
    if (*strings == NULL) {
        log_printf(LOG_ERROR, "Config: failed to malloc - %s\n", 
                strerror(errno));
    }

    if (parse_next_event(parser) != YAML_SEQUENCE_START_EVENT) {
        log_printf(LOG_ERROR, "Config parsing error: expected list\n");
        return -1;
    }

    int done = 0;

    while (!done)
        done = parse_string_list_member(parser, *strings, num);
    
    if (done < 0) /* error */
        return -1;
    
    return 0;
}

/**
 * Parses an individual string out of a sequence given in parser; helper 
 * function for parse_string_list().
 * @param parser The parser to pull events out of.
 * @param strings The list of strings to put the member into
 * @param num The number of strings already parsed into strings. This will be
 * incremented by the function.
 * @returns 0 on success, 1 if the sequence has ended (no more strings to 
 * parse), or -1 on error.
 */
int parse_string_list_member(yaml_parser_t* parser, char** strings, int* num) {

    yaml_event_t event;
    char* label;

    if (*num > MAX_STRLIST_SIZE) {
        log_printf(LOG_ERROR, "Config: max list size exceeded (%i)\n",
                MAX_STRLIST_SIZE);
        return -1;
    }
    
    if (yaml_parser_parse(parser, &event) != 1)
        return -1;

    if (event.type == YAML_SEQUENCE_END_EVENT) {
        yaml_event_delete(&event);
        return 1;
    }

    if (event.type != YAML_SCALAR_EVENT) {
        yaml_event_delete(&event);
        return -1;
    }

    label = utf8_to_ascii(event.data.scalar.value, event.data.scalar.length);
    if (label == NULL)
        return -1;
    
    yaml_event_delete(&event);

    if (strings[*num] != NULL) {
        /* This really shouldn't happen... if it does it's our code's fault */
        log_printf(LOG_ERROR, "Parser overwriting string list\n");
        return -1;
    }

    strings[*num] = label;
    ++*num;

    /* don't free(label) */
    return 0;
}

/**
 * Parses an individual boolean value, designated by SETTING_TRUE or one of 
 * its substitutes, from the given parser and updates the value of enabled 
 * to reflect whether the value indicated 'true' or 'false'.
 * @param parser The parser to parse the boolean value from.
 * @param enabled A reference to be updated with the boolean value. This will
 * be filled with 1 if the value parsed was 'true'/one of its alternatives, or
 * 0 if the value parsed was 'false'/one of its alternatives.
 * @returns 0 on success, or -1 if an error occurred.
 */
int parse_boolean(yaml_parser_t* parser, int* enabled) {

    char* label = parse_next_scalar(parser);
    if (label == NULL)
        return -1;

    *enabled = is_enabled(label);
    if (*enabled < 0) {
        free(label);
        return -1;
    }

    free(label);
    return 0;
}

/**
 * Parses an individual integer value. Updates the value of num to hold the integer value.
 * @param parser The parser to parse the integer value from.
 * @param value A reference to be updated with the integer value.
 * @returns 0 on success, or -1 if an error occurred.
 */
int parse_integer(yaml_parser_t* parser, int* num) {
    const char *errstr;
    long long llnum;

    char* label = parse_next_scalar(parser);
    if (label == NULL)
        return -1;

    llnum = strtonum(label, 0, INT_MAX, &errstr);
    if(errstr){
        free(label);
        return -1;
    }
    *num = (int) llnum;

    free(label);
    return 0;
}

/**
 * Parses the next event from parser and attempts to read it as a TLS version.
 * If the string does match, version will be updated accordingly with the 
 * appropriate version enum.
 * @param parser The parser to extract the next event from.
 * @param version A reference to be updated if the parsed event represents a 
 * valid TLS version. See enum tls_version_t in config.h for possible versions.
 * @returns 0 on success, or -1 if an error occurred.
 */
int parse_tls_version(yaml_parser_t* parser, enum tls_version_t* version) {
    
    char* tls_version = parse_next_scalar(parser);
    if (tls_version == NULL)
        return -1;

    str_tolower(tls_version);

    if (strcmp(tls_version, TLS1_0_STRING) == 0
            || strcmp(tls_version, TLS1_0_ALT_STRING) == 0) {
        *version = TLS1_0_ENUM;
    } else if (strcmp(tls_version, TLS1_1_STRING) == 0
            || strcmp(tls_version, TLS1_1_ALT_STRING) == 0) {
        *version = TLS1_1_ENUM;
    } else if (strcmp(tls_version, TLS1_2_STRING) == 0
            || strcmp(tls_version, TLS1_2_ALT_STRING) == 0) {
        *version = TLS1_2_ENUM;
    } else if (strcmp(tls_version, TLS1_3_STRING) == 0
            || strcmp(tls_version, TLS1_3_ALT_STRING) == 0) {
        *version = TLS1_3_ENUM;
    } else {
        log_printf(LOG_ERROR, "Config: Unknown TLS version '%s'\n",
                tls_version);
        free(tls_version);
        return -1;
    }

    free(tls_version);
    return 0;
}


/**
 *******************************************************************************
 *   FUNCTIONS TO PARSE THE CONFIG FILE AND ENSURE IT'S CORRECTLY FORMATTED
 *******************************************************************************
 */


/**
 * Parses a given config file and fills an allocated global_settings struct 
 * with the configurations.
 * @param file_path The path to the .yml config file, or NULL if the default
 * file path is desired.
 * @returns An allocated global_settings struct, or NULL on error.
 */
global_settings* parse_config(char* file_path) {
    
    global_settings* settings = NULL;
    yaml_parser_t parser;
    FILE* input = NULL;

    if (file_path == NULL)
        file_path = DEFAULT_CONFIG_PATH;

    if (yaml_parser_initialize(&parser) != 1) {
        log_printf(LOG_ERROR, "Failed to initialize config parser\n");
        return NULL;
    }

    settings = calloc(1, sizeof(global_settings));
    if (settings == NULL) {
        log_printf(LOG_ERROR, "Failed to allocate settings struct: %s\n",
                strerror(errno));
        goto err;
    }
    
    input = fopen(file_path, "r");
    if (input == NULL)
        goto err;

    yaml_parser_set_input_file(&parser, input);

    if (parse_next_event(&parser) != YAML_STREAM_START_EVENT)
        goto err;

    if (parse_stream(&parser, settings) != 0)
        goto err;

    fclose(input);
    yaml_parser_delete(&parser);
    return settings;
 err:
    log_parser_error(parser);
    yaml_parser_delete(&parser);

    if (settings != NULL)
        global_settings_free(settings);
    
    if (input != NULL)
        fclose(input);

    return NULL;
}

/**
 * Parses a given file's contents and verifies their correctness.
 * The file's settings are then stored in settings.
 * @param parser The parser to parse the settings from.
 * @param settings The struct to pass settings from the parser into.
 * @returns 0 on success, or -1 if an error occurred parsing the file.
 */
int parse_stream(yaml_parser_t* parser, global_settings* settings) {

    yaml_event_type_t type = parse_next_event(parser);

    if (type == YAML_STREAM_END_EVENT) {
        return 0; /* empty files are valid */
    } else if (type != YAML_DOCUMENT_START_EVENT) {
        log_printf(LOG_ERROR, "Config: Document start not found\n");
        return -1;
    } 
    /* type == YAML_DOCUMENT_START_EVENT */

    if (parse_document(parser, settings) != 0)
        return -1;

    if (parse_next_event(parser) != YAML_STREAM_END_EVENT) {
        log_printf(LOG_ERROR, "Config: File didn't end correctly\n");
        return -1;
    }
    return 0;
}

/**
 * Similar to parse_stream; ensures that parser contains the correct sequence
 * of events at the start/end of the file and calls functions to parse the
 * settings.
 * @param parser The parser to extract events from.
 * @param settings The struct to put extracted settings into
 * @returns 0 on success, or -1 if an error occurred.
 */
int parse_document(yaml_parser_t* parser, global_settings* settings) {

    yaml_event_type_t type;
    char* label;

    type = parse_next_event(parser);
    
    if (type == YAML_DOCUMENT_END_EVENT) {
        return 0; /* empty documents are also acceptable */
    } else if (type != YAML_MAPPING_START_EVENT) {
        log_printf(LOG_ERROR, "Config: expected either "
                "\'client:\' or \'server:\' at start of document\n");
        return -1;
    }
    /* else (type == YAML_MAPPING_START_EVENT) */

    label = parse_next_scalar(parser);

    if (is_client(label)) {
        free(label);

        if (parse_client(parser, settings) != 0)
            return -1;
    } else if (is_server(label)) {
        free(label);

        if (parse_server(parser, settings) != 0)
            return -1;
    } else {
        log_printf(LOG_ERROR, "Config: expected either "
                "'client:' or 'server:' at start of document\n");
        return -1;
    }

    type = parse_next_event(parser);

    if (type != YAML_DOCUMENT_END_EVENT) {
        log_printf(LOG_ERROR, "Config: expected \'server:\' label\n");
        printf("Label: %i\n", type);
        return -1;
    }

    return 0;
}

/**
 * Parses all events within a given 'client:' label and assigns the
 * information contained to the appropriate settings.
 * @param parser The parser to extract events from.
 * @param settings The struct to fill with the information parsed from parser.
 * @returns 0 on success, -1 on error.
 */
int parse_client(yaml_parser_t* parser, global_settings* settings) {

    int done = 0;
    int ret;

    if (settings->server != NULL) {
        log_printf(LOG_ERROR, "Config: Multiple 'client:' labels\n");
        return -1;
    }

    /* indicates the beginning of the 'client:' key/value pairs */
    if (parse_next_event(parser) != YAML_MAPPING_START_EVENT) {
        log_printf(LOG_ERROR, "Config: Bad syntax after 'client:'\n");
        return -1;
    }


    settings->client = calloc(1, sizeof(client_settings));
    if (settings->client == NULL)
        return -1;

    /* parse all the key:value pairs within client settings */
    while (!done)
        done = parse_next_client_setting(parser, settings->client);
    if (done == -1) /* error */
        return -1;

    ret = check_label_to_parse(parser, "server");
    if (ret == 1)
        return parse_server(parser, settings);

    return ret; /* 0 for clean MAPPING_END, -1 for error */
}

/**
 * Parses all events within a given 'server:' label and assigns the
 * information contained to the appropriate settings.
 * @param parser The parser to extract events from.
 * @param settings The struct to fill with the information parsed from parser.
 * @returns 0 on success, -1 on error.
 */
int parse_server(yaml_parser_t* parser, global_settings* settings) {

    int done = 0;
    int ret;

    if (settings->server != NULL) {
        log_printf(LOG_ERROR, "Config: Multiple 'server:' labels\n");
        return -1;
    }

    /* indicates the beginning of the 'client:' key/value pairs */
    if (parse_next_event(parser) != YAML_MAPPING_START_EVENT) {
        log_printf(LOG_ERROR, "Config: Bad syntax after 'server'\n");
        return -1;
    }

    settings->server = calloc(1, sizeof(server_settings));
    if (settings->server == NULL) {
        log_printf(LOG_ERROR, "Parser: malloc failure--%s\n", strerror(errno));
        return -1;
    }

    /* parse all the key:value pairs within client settings */
    while (!done)
        done = parse_next_server_setting(parser, settings->server);
    if (done == -1) /* error */
        return -1;

    ret = check_label_to_parse(parser, "client");

    if (ret == 1)
        return parse_client(parser, settings);

    return ret; /* 0 for clean MAPPING_END, -1 for error */
}


/**
 *******************************************************************************
 *                HELPER FUNCTIONS FOR PARSING/STRING CHECKING
 *******************************************************************************
 */


/**
 * Parses the next event from parser and checks to see if it is a scalar event 
 * of value label, or if it is a MAPPING_END event. Returns an error if it is
 * neither of these.
 * @param parser the parser to extract the next event from.
 * @param label The ASCII NULL-terminated string to compare the event with.
 * @returns 1 if label matched the next parsed event; 0 if the end of mapping 
 * has been reached; and -1 if an invalid event or event label was parsed.
 */
int check_label_to_parse(yaml_parser_t* parser, char* label) {

    yaml_event_t event;
    char* ev_label;

    if (yaml_parser_parse(parser, &event) != 1)
        return -1; 

    switch (event.type) {
    case YAML_MAPPING_END_EVENT:
        yaml_event_delete(&event);
        return 0;
    
    case YAML_SCALAR_EVENT:
        ev_label = utf8_to_ascii(event.data.scalar.value, event.data.scalar.length);
        str_tolower(ev_label);
        yaml_event_delete(&event);
        
        if (ev_label == NULL)
            return -1;
        
        if (strcmp(ev_label, label) != 0) {
            log_printf(LOG_ERROR, "Config: Invalid or duplicate label '%s'\n",
                    ev_label);
            free(ev_label);
            return -1;
        }
        
        free(ev_label);
        return 1;
    
    default:
        return -1;
    }
}

/**
 * Parses the next event from parser and retrieves its type.
 * @param parser The parser to pull the event from.
 * @returns The type of that event, or YAML_NO_EVENT on failure.
 */
yaml_event_type_t parse_next_event(yaml_parser_t* parser) {

    yaml_event_t event;

    if (yaml_parser_parse(parser, &event) != 1)
        return YAML_NO_EVENT;

    yaml_event_type_t type = event.type;
    yaml_event_delete(&event);

    return type;
}

/**
 * Parses an event from parser and verifies that the event type is a scaler.
 * @param parser The parser to pull an event from.
 * @returns The label of the scalar event, or NULL for an incorrect event type.
 */
char* parse_next_scalar(yaml_parser_t* parser) {

    yaml_event_t event;
    char* name;

    if (yaml_parser_parse(parser, &event) != 1)
        return NULL;

    if (event.type != YAML_SCALAR_EVENT) {
        yaml_event_delete(&event);
        return NULL;
    }

    name = utf8_to_ascii(event.data.scalar.value, event.data.scalar.length);

    yaml_event_delete(&event);
    return name;
}

/**
 * Checks to see if the given string label is a valid identifier for 'on' or
 * 'off', and returns the corresponding value if it is.
 * @param label The null-terminated label to check (can be NULL).
 * @returns 1 if the label corresponds with 'on'; 0 if it corresponds with 
 * 'off'; and < 0 on error.
 */
int is_enabled(char* label) {

    if (label == NULL)
        return -1;

    str_tolower(label);

    if (strcmp(label, SETTING_TRUE) == 0
            || strcmp(label, SETTING_YES) == 0
            || strcmp(label, SETTING_Y) == 0
            || strcmp(label, SETTING_ON) == 0
            || strcmp(label, SETTING_ENABLED) == 0) {
        
        return 1;
    }

    if (strcmp(label, SETTING_FALSE) == 0
            || strcmp(label, SETTING_NO) == 0
            || strcmp(label, SETTING_N) == 0
            || strcmp(label, SETTING_OFF) == 0
            || strcmp(label, SETTING_DISABLED) == 0) {
        
        return 0;
    }

    log_printf(LOG_ERROR, "Label '%s' is not a valid indicator. "
            "Try 'enabled' or 'disabled' instead\n");
    return -1;
}


/**
 * Checks to see if the given string is 'client'
 * @param label A null-terminated string (can be NULL).
 * @returns 1 if the given string is 'client'; 0 otherwise.
 */
int is_client(char* label) {
    if (label == NULL)
        return 0;
    if (strcmp(label, "client") == 0)
        return 1;
    return 0;
}

/**
 * Checks to see if the given string is 'server'
 * @param label A null-terminated string (can be NULL).
 * @returns 1 if the given string is 'server'; 0 otherwise.
 */
int is_server(char* label) {
    if (label == NULL)
        return 0;
    if (strcmp(label, "server") == 0)
        return 1;
    return 0;
}

/**
 * Allocates a new char array the length of src and fills it with an ASCII 
 * conversion of the UTF-8 encoded src. If no conversion is possible, or if
 * allocation fails, this returns NULL.
 * @param src The UTF-8 encoded string to convert.
 * @param len The length of src.
 * @returns An ASCII-formatted string, or NULL on malloc/conversion failure.
 */
char* utf8_to_ascii(unsigned char* src, ssize_t len) {

    char* dest = calloc(1, len+1);
    if (dest == NULL)
        return NULL;
    
    int index = 0;
    for (int i = 0; i < len; i++) {
        if ((int) src[index] >= 127) { /* doesn't convert after 126 */
            free(dest);
            return NULL;
        }

        dest[index] = src[index];
        index++;
    }
    dest[len] = '\0';

    return dest;
}

/**
 * Converts a given string go lowercase ASCII; if non-alphabetic characters 
 * exist in the string then they are left unchanged.
 * @param string The string to convert to lowercase.
 */
void str_tolower(char* string) {
    if (string == NULL)
        return;
    for (int i = 0; i < strlen(string); i++)
        string[i] = tolower(string[i]);
}


/**
 * Logs an error that occured within the libyaml parser, if such an error was
 * registered. Does nothing if no error internal to the given parser occurred.
 * @param parser The parser to log errors from.
 */
void log_parser_error(yaml_parser_t parser) {
    switch (parser.error) {
    case YAML_MEMORY_ERROR:
        log_printf(LOG_ERROR, "Insufficient memory to scan config file\n");
        break;

    case YAML_READER_ERROR:
        if (parser.problem_value != -1) {
            log_printf(LOG_ERROR, 
                    "Config reader error: %s: #%X at %ld\n", parser.problem,
                    parser.problem_value, (long)parser.problem_offset);
        } else {
            log_printf(LOG_ERROR, "Config reader error: %s at %ld\n", 
                    parser.problem, (long)parser.problem_offset);
        }
        break;

    case YAML_SCANNER_ERROR:
        if (parser.context) {
            log_printf(LOG_ERROR, 
                    "Config scanner error: %s at line %d, column %d\n"
                    "%s at line %d, column %d\n", parser.context,
                    (int)parser.context_mark.line+1, 
                    (int)parser.context_mark.column+1,
                    parser.problem, (int)parser.problem_mark.line+1,
                    (int)parser.problem_mark.column+1);
        } else {
            log_printf(LOG_ERROR, 
                    "Config scanner error: %s at line %d, column %d\n",
                    parser.problem, (int)parser.problem_mark.line+1,
                    (int)parser.problem_mark.column+1);
        }
        break;

    case YAML_PARSER_ERROR:
        if (parser.context) {
            log_printf(LOG_ERROR, 
                    "Config parser error: %s at line %d, column %d\n"
                    "%s at line %d, column %d\n", parser.context,
                    (int)parser.context_mark.line+1, 
                    (int)parser.context_mark.column+1,
                    parser.problem, (int)parser.problem_mark.line+1,
                    (int)parser.problem_mark.column+1);
        } else {
            log_printf(LOG_ERROR, 
                    "Config parser error: %s at line %d, column %d\n",
                    parser.problem, (int)parser.problem_mark.line+1,
                    (int)parser.problem_mark.column+1);
        }
        break;

    default:
        /* No libyaml error; probably just one that we threw */
        break;
    }
}


/**
 * Performs a deep free of all data structures allocated within global_settings.
 * @param settings The global_settings to be freed.
 */
void global_settings_free(global_settings* settings) {

    client_settings* client = settings->client;
    server_settings* server = settings->server;

    /* Client settings */
    if (client != NULL) {
        if (client->ca_path != NULL)
            free(client->ca_path);
        
        if (client->cipher_list != NULL) {
            for (int i = 0; i < client->cipher_list_cnt; i++) {
                free(client->cipher_list[i]);
            }
            free(client->cipher_list);
        }

        if (client->ciphersuites != NULL) {
            for (int i = 0; i < client->ciphersuite_cnt; i++) {
                free(client->ciphersuites[i]);
            }
            free(client->ciphersuites);
        }

        free(client);
    }

    /* Server settings */
    if (server != NULL) {

        if (server->ca_path != NULL)
            free(server->ca_path);
        
        if (server->cipher_list != NULL) {
            for (int i = 0; i < server->cipher_list_cnt; i++) {
                free(server->cipher_list[i]);
            }
            free(server->cipher_list);
        }

        if (server->ciphersuites != NULL) {
            for (int i = 0; i < server->ciphersuite_cnt; i++) {
                free(server->ciphersuites[i]);
            }
            free(server->ciphersuites);
        }
        
        free(server);
    }

    free(settings);
}
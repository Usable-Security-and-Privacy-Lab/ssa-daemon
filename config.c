
/**
 * Any libcyaml-specific functions should go in here and not the .h file;
 * we want this to be the only file that references the library in case
 * we decide to modify it in the future.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <yaml.h>

#include "config.h"
#include "log.h"

#define MAX_STRLIST_SIZE 100

/* These are all of the possible config labels. To add, define another here
* and add it to the if/else chain in parse_next_<client/server>_setting().
* Note that these should be in lowercase--it's what we convert input to. */
#define CA_PATH         "ca-path"
#define CIPHER_LIST     "cipher-list"
#define CIPHERSUITES    "ciphersuites"
#define SESSION_TICKETS "session-tickets"
#define MIN_TLS_VERSION "min-tls-version"
#define MAX_TLS_VERSION "max-tls-version"
#define CERT_PATH       "cert-path"
#define KEY_PATH        "key-path"
#define SESSION_TIMEOUT "session-timeout"
#define CERT_V_DEPTH    "cert-verification-depth"
#define VERIFY_CT       "verify-cert-transparency"
#define REV_CHECKS      "revocation-checks"
#define STAPLED_CHECKS  "revocation-stapled"
#define OCSP_CHECKS     "revocation-ocsp"
#define CRL_CHECKS      "revocation-crl"
#define CACHED_CHECKS   "revocation-cached"
#define SESSION_REUSE   "session-resumption"


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



int parse_next_setting(yaml_parser_t* parser, global_config* settings);

int parse_string(yaml_parser_t* parser, char** string);
int parse_string_list(yaml_parser_t* parser, char** strings[], int* num);
int parse_string_list_member(yaml_parser_t* parser, char** strings, int* num);
int parse_boolean(yaml_parser_t* parser, int* enabled);
int parse_integer(yaml_parser_t* parser, int* num);
int parse_tls_version(yaml_parser_t* parser, enum tls_version* version);

int parse_stream(yaml_parser_t* parser, global_config* settings);
int parse_document(yaml_parser_t* parser, global_config* settings);
int parse_settings(yaml_parser_t* parser, global_config* settings);

int check_label_to_parse(yaml_parser_t* parser, char* label);
yaml_event_type_t parse_next_event(yaml_parser_t* parser);
char* parse_next_scalar(yaml_parser_t* parser);

char* utf8_to_ascii(unsigned char* src, ssize_t len);
void str_tolower(char* string);
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
* 
* Would be represented by the following tokens:
* STREAM_START
* DOCUMENT_START
* MAPPING_START
* SCALAR ('client')
* MAPPING_START
* SCALAR ('min-tls-version')
* SCALAR ('1.2')
* SCALAR ('cipher-list')
* SEQUENCE_START
* SCALAR ('cipher-1')
* SCALAR ('cipher-2')
* SCALAR ('cipher-3')
* SEQUENCE_END
* MAPPING_END
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
 * Parses the next key:value pair from the loaded configuration file. This 
 * function is called iteratively on every setting found in the configuration 
 * file, so the if/else chain found in this function checks to see if the 'key'
 * received from the file matches up with any of the accepted labels. If it
 * does match one of the labels, a more tailored function will be called to 
 * parse the 'value' and verify that it is within its acceptable range.
 * @param parser The yaml config parser that provides the next token to parse
 *  (such as the token for the 'key' or the token(s) for the 'value')
 * @param config The struct to populate with setting information as key:value
 * pairs are parsed from the .yml config file.
 * @returns 1 if all settings have been parsed; 0 if the next setting was 
 * successfully parsed from the .yml config file; or -1 if an error occurred.
 */
int parse_next_setting(yaml_parser_t* parser, global_config* config) {

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
        ret = parse_string(parser, &config->ca_path);

    } else if (strcmp(label, CIPHER_LIST) == 0) {
        ret = parse_string_list(parser, 
                &config->cipher_list, &config->cipher_list_cnt);

    } else if (strcmp(label, CIPHERSUITES) == 0) {
        ret = parse_string_list(parser,
                &config->ciphersuites, &config->ciphersuite_cnt);

    } else if (strcmp(label, MIN_TLS_VERSION) == 0) {
        ret = parse_tls_version(parser, &config->min_tls_version);

    } else if (strcmp(label, MAX_TLS_VERSION) == 0) {
        ret = parse_tls_version(parser, &config->max_tls_version);

    } else if (strcmp(label, SESSION_TIMEOUT) == 0) {
        ret = parse_integer(parser, &config->session_timeout);

    } else if (strcmp(label, CERT_V_DEPTH) == 0) {
        ret = parse_integer(parser, &config->max_chain_depth);

    } else if (strcmp(label, VERIFY_CT) == 0) {
        ret = parse_boolean(parser, &config->ct_checks);

    } else if (strcmp(label, SESSION_TICKETS) == 0) {
        ret = parse_boolean(parser, &config->session_tickets);

    } else if (strcmp(label, SESSION_REUSE) == 0) {
        ret = parse_boolean(parser, &config->session_resumption);

    } else if (strcmp(label, REV_CHECKS) == 0) {
        int has_checks;
        ret = parse_boolean(parser, &has_checks);
        if (!has_checks)
            turn_off_revocation_checks(config->revocation_checks);

    } else if (strcmp(label, OCSP_CHECKS) == 0) {
        int has_checks;
        ret = parse_boolean(parser, &has_checks);
        if (!has_checks)
            turn_off_ocsp_checks(config->revocation_checks);

    } else if (strcmp(label, CRL_CHECKS) == 0) {
        int has_checks;
        ret = parse_boolean(parser, &has_checks);
        if (!has_checks)
            turn_off_crl_checks(config->revocation_checks);
    
    } else if (strcmp(label, CACHED_CHECKS) == 0) {
        int has_checks;
        ret = parse_boolean(parser, &has_checks);
        if (!has_checks)
            turn_off_cached_checks(config->revocation_checks);

    } else if (strcmp(label, STAPLED_CHECKS) == 0) {
        int has_checks;
        ret = parse_boolean(parser, &has_checks);
        if (!has_checks)
            turn_off_stapled_checks(config->revocation_checks);

    } else if (strcmp(label, CERT_PATH) == 0) {
        if (config->cert_cnt >= MAX_CERTS) {
            log_printf(LOG_ERROR, "Config: Maximum keys (%i) exceeded\n", 
                    MAX_CERTS);
            ret = -1;
        } else {
            ret = parse_string(parser, &config->certificates[config->cert_cnt]);
            config->cert_cnt++;
        }

    } else if (strcmp(label, KEY_PATH) == 0) {
        if (config->key_cnt >= MAX_CERTS) {
            log_printf(LOG_ERROR, "Config: Maximum keys (%i) exceeded\n", 
                    MAX_CERTS);
            ret = -1;
        } else {
            ret = parse_string(parser, &config->private_keys[config->key_cnt]);
            config->key_cnt++;
        }
    
    } else {
        log_printf(LOG_ERROR, "Config: Undefined label %s\n", label);
        ret = -1;
    }
    
    free(label);
    return ret;
}


/*
*******************************************************************************
*      USE THESE FUNCTIONS TO PARSE INFO INTO THE GLOBAL_CONFIG STRUCT
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
    
    long lnum;

    char* label = parse_next_scalar(parser);
    if (label == NULL)
        return -1;

    lnum = strtol(label, NULL, 10);
    if(lnum >= INT_MAX || lnum == LONG_MIN) {
        free(label);
        return -1;
    }
    *num = (int) lnum;

    free(label);
    return 0;
}

/**
 * Parses the next event from parser and attempts to read it as a TLS version.
 * If the string does match, version will be updated accordingly with the 
 * appropriate version enum.
 * @param parser The parser to extract the next event from.
 * @param version A reference to be updated if the parsed event represents a 
 * valid TLS version. See enum tls_version in config.h for possible versions.
 * @returns 0 on success, or -1 if an error occurred.
 */
int parse_tls_version(yaml_parser_t* parser, enum tls_version* version) {
    
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
*       FUNCTIONS TO PARSE THE CONFIG FILE AND ENSURE CORRECT FORMAT
*******************************************************************************
*/


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
global_config* parse_config(char* file_path) {
    
    global_config* settings;
    yaml_parser_t parser;
    FILE* input = NULL;

    if (file_path == NULL)
        file_path = DEFAULT_CONFIG_PATH;

    if (yaml_parser_initialize(&parser) != 1) {
        log_printf(LOG_ERROR, "Failed to initialize config parser\n");
        return NULL;
    }

    input = fopen(file_path, "r");
    if (input == NULL) {
        log_printf(LOG_ERROR, 
                "Couldn't find configuration file in specified path...\n");
        return NULL;
    }

    settings = calloc(1, sizeof(global_config));
    if (settings == NULL) {
        log_printf(LOG_ERROR, "Failed to allocate settings struct: %s\n",
                strerror(errno));
        goto err;
    }

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
int parse_stream(yaml_parser_t* parser, global_config* settings) {

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
int parse_document(yaml_parser_t* parser, global_config* settings) {

    yaml_event_type_t type;

    type = parse_next_event(parser);
    
    if (type == YAML_DOCUMENT_END_EVENT) {
        return 0; /* empty documents are also acceptable */
        
    } else if (type != YAML_MAPPING_START_EVENT) {
        log_printf(LOG_ERROR, "Config: expected either "
                "\'client:\' or \'server:\' at start of document\n");
        return -1;
    }
    /* else (type == YAML_MAPPING_START_EVENT) */

    if (parse_settings(parser, settings) != 0)
        return -1;

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
int parse_settings(yaml_parser_t* parser, global_config* settings) {

    int done = 0;

    while (!done)
        done = parse_next_setting(parser, settings);
    if (done == -1)
        return -1;

    return 0;
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
        ev_label = utf8_to_ascii(event.data.scalar.value,  
                event.data.scalar.length);
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
 * Performs a deep free of all data structures allocated within global_config.
 * @param settings The global_config to be freed.
 */
void global_settings_free(global_config* settings) {

    if (settings->ca_path != NULL)
        free(settings->ca_path);

    if (settings->cipher_list != NULL) {
        for (int i = 0; i < settings->cipher_list_cnt; i++) {
            free(settings->cipher_list[i]);
        }
        free(settings->cipher_list);
    }

    if (settings->ciphersuites != NULL) {
        for (int i = 0; i < settings->ciphersuite_cnt; i++) {
            free(settings->ciphersuites[i]);
        }
        free(settings->ciphersuites);
    }

    for (int i = 0; i < settings->cert_cnt; i++) {
        if (settings->certificates[i] != NULL)
            free(settings->certificates[i]);
    }

    for (int i = 0; i < settings->key_cnt; i++) {
        if (settings->private_keys[i] != NULL)
            free(settings->private_keys[i]);
    }

    free(settings);
}


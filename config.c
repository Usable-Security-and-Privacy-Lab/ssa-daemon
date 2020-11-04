#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "socket_setup.h"


typedef struct file_stream_st file_stream;
typedef struct label_pair_st label_pair;

static const label_pair keys[];


#define READER_BUF_MAX 4096
#define MAX_TOKEN_SIZE 256
#define MAX_LIST_SIZE 128
#define KEYS_SIZE (sizeof(keys) / sizeof(label_pair))

/* Temporary for testing */
#define TLS_1_0 0x0000
#define TLS_1_1 0x0001
#define TLS_1_2 0x0002
#define TLS_1_3 0x0003



int file_stream_init(file_stream *fs, char *path);
int file_stream_close(file_stream *fs);

char fs_peek(file_stream *fs);
char fs_read(file_stream *fs);

int read_settings(file_stream *fs, global_config *config);
void *read_label(file_stream *fs);

int read_after_space(file_stream *fs);
void read_space(file_stream *fs);
void read_comment(file_stream *fs);
int read_string(file_stream *fs, char **str);
int read_uint(file_stream *fs, int *val);
int read_uint_bounded(file_stream *fs, int *val, int min, int max);
int read_boolean(file_stream *fs, int *val);


int read_ca_path(file_stream *fs, global_config *conf);
int read_chain_depth(file_stream *fs, global_config *conf);
int read_ct_checks(file_stream *fs, global_config *conf);
int read_max_tls_version(file_stream *fs, global_config *conf);
int read_min_tls_version(file_stream *fs, global_config *conf);
int read_revocation_cached(file_stream *fs, global_config *conf);
int read_revocation_checks(file_stream *fs, global_config *conf);
int read_revocation_crl(file_stream *fs, global_config *conf);
int read_revocation_ocsp(file_stream *fs, global_config *conf);
int read_revocation_stapled(file_stream *fs, global_config *conf);
int read_session_resumption(file_stream *fs, global_config *conf);
int read_session_tickets(file_stream *fs, global_config *conf);
int read_session_timeout(file_stream *fs, global_config *conf);


struct file_stream_st {
    char buf[READER_BUF_MAX];
    unsigned int buf_index;
    unsigned int buf_length;
    unsigned int lineno;
    int eof;
    int error;
    int fd;
};

struct label_pair_st {
    char *label;
    int (*func)(file_stream *, global_config *);
    /* put generic parsing function callback here */
};


/* labels MUST (!!) stay sorted alphabetically */
/* dashes ('-') come alphabetically before anything else */
static const label_pair keys[] = {
    { .label = "ca-path", .func = read_ca_path },
    { .label = "cert-transparency-checks", read_ct_checks },
    { .label = "cert-verification-depth", read_chain_depth },
    { .label = "cipher-list" },
    { .label = "ciphersuites" },
    { .label = "max-tls-version", read_max_tls_version },
    { .label = "min-tls-version", read_min_tls_version },
    { .label = "revocation-cached", read_revocation_cached },
    { .label = "revocation-checks", read_revocation_checks },
    { .label = "revocation-crl", read_revocation_crl },
    { .label = "revocation-ocsp", read_revocation_ocsp },
    { .label = "revocation-stapled", read_revocation_stapled },
    { .label = "session-resumption", read_session_resumption },
    { .label = "session-tickets", read_session_tickets },
    { .label = "session-timeout", read_session_timeout },
};


/* Functions for parsing associated labels--ADD HERE */

int read_ca_path(file_stream *fs, global_config *conf)
{
    if (conf->ca_path != NULL)
        free(conf->ca_path);

    return read_string(fs, &conf->ca_path);
}

int read_chain_depth(file_stream *fs, global_config *conf)
{
    return read_uint(fs, &conf->max_chain_depth);
}

int read_ct_checks(file_stream *fs, global_config *conf)
{
    return read_boolean(fs, &conf->ct_checks);
}

int read_max_tls_version(file_stream *fs, global_config *conf)
{
    return read_uint_bounded(fs, &conf->max_tls_version, TLS_1_0, TLS_1_3);
}

int read_min_tls_version(file_stream *fs, global_config *conf)
{
    return read_uint_bounded(fs, &conf->min_tls_version, TLS_1_0, TLS_1_3);
}

int read_revocation_cached(file_stream *fs, global_config *conf)
{
    int enabled;
    int ret = read_boolean(fs, &enabled);

    if (ret == 0) {
        if (enabled)
            turn_on_cached_checks(conf->revocation_checks);
        else
            turn_off_cached_checks(conf->revocation_checks);
    }
    return ret;
}

int read_revocation_checks(file_stream *fs, global_config *conf)
{
    int enabled;
    int ret = read_boolean(fs, &enabled);

    if (ret == 0) {
        if (enabled)
            turn_on_revocation_checks(conf->revocation_checks);
        else
            turn_off_revocation_checks(conf->revocation_checks);
    }
    return ret;
}

int read_revocation_crl(file_stream *fs, global_config *conf)
{
    int enabled;
    int ret = read_boolean(fs, &enabled);

    if (ret == 0) {
        if (enabled)
            turn_on_crl_checks(conf->revocation_checks);
        else
            turn_off_crl_checks(conf->revocation_checks);
    }
    return ret;
}

int read_revocation_ocsp(file_stream *fs, global_config *conf)
{
    int enabled;
    int ret = read_boolean(fs, &enabled);

    if (ret == 0) {
        if (enabled)
            turn_on_ocsp_checks(conf->revocation_checks);
        else
            turn_off_ocsp_checks(conf->revocation_checks);
    }
    return ret;
}

int read_revocation_stapled(file_stream *fs, global_config *conf)
{
    int enabled;
    int ret = read_boolean(fs, &enabled);

    if (ret == 0) {
        if (enabled)
            turn_on_stapled_checks(conf->revocation_checks);
        else
            turn_off_stapled_checks(conf->revocation_checks);
    }
    return ret;
}

int read_session_resumption(file_stream *fs, global_config *conf)
{
    return read_boolean(fs, &conf->session_resumption);
}

int read_session_tickets(file_stream *fs, global_config *conf)
{
    return read_boolean(fs, &conf->session_tickets);
}

int read_session_timeout(file_stream *fs, global_config *conf)
{
    return read_uint(fs, &conf->session_timeout);
}



global_config* parse_config(char* file_path)
{
    global_config *config = NULL;
    file_stream fs;
    char nextchar;
    int ret;

    ret = file_stream_init(&fs, file_path);
    if (ret != 0)
        return NULL;

    config = calloc(1, sizeof(global_config));
    if (config == NULL) {
        LOG_E("Failed to allocate config structure: %s\n", strerror(errno));
        goto out;   
    }

    ret = read_settings(&fs, config);
    if (ret != 0)
        goto out;
    
    return config;

out:
    if (config != NULL)
        global_settings_free(config);

    file_stream_close(&fs);
    return NULL;
}

int file_stream_init(file_stream *fs, char *path)
{
    fs->lineno = 1;
    fs->buf_index = 0;
    fs->buf_length = 0;
    fs->eof = 0;
    fs->error = 0;

    fs->fd = open(path, O_RDONLY);
    if (fs->fd < 0) {
        LOG_E("Unable to open config file: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int file_stream_close(file_stream *fs)
{
    return close(fs->fd);
}

char fs_peek(file_stream *fs)
{
    if (fs->eof || fs->error) 
        return EOF;

    if (fs->buf_index >= fs->buf_length) {
        fs->buf_index = 0;
        fs->buf_length = read(fs->fd, fs->buf, READER_BUF_MAX);

        if (fs->buf_length < 0) {
            fs->error = errno;
            LOG_E("Error occurred while scanning config (line %u): %s\n", 
                        fs->lineno, strerror(errno));
            return EOF; /* errors reported as EOF with `error` field set */
        
        } else if (fs->buf_length == 0) {
            fs->eof = 1;
            return EOF;
        }
    }

    return fs->buf[fs->buf_index];
}

char fs_read(file_stream *fs)
{
    char c = fs_peek(fs);
    if (c != EOF)
        fs->buf_index++;

    if (c == '\n')
        fs->lineno++;

    return c;
}

int read_settings(file_stream *fs, global_config *conf)
{
    char *label;
    char c = fs_peek(fs);
    int ret;

    while (c != EOF) {

        switch (c) {
        case '\n':
            fs_read(fs);
            break;
        
        case '\t':
        case ' ':
        case '\v':
            read_blankline(fs);
            break;
        
        case '#':
            read_comment(fs);
            break;

        default:
            read_setting(fs, conf);
            break;
        }

        c = fs_peek(fs);

        /*
        if (c == '\n') {
            fs_read(fs);

        } else if (isspace(c)) {
            ret = read_after_space(fs);
            if (ret != 0)
                return -1;
        
        } else if (c == '#') {
            read_comment(fs);

        } else {
            label_func = read_label(fs);
            if (label_func == NULL)
                return -1;

            read_space(fs);

            if (fs_read(fs) != ':') {
                LOG_E("Missing ':' within config file (line %u)\n", fs->lineno);
                return -1;
            }

            read_space(fs);
            ret = label_func(fs, config);
            if (ret != 0)
                return -1;
        }
        */
}

    if (fs->error)
        return -1;
    
    return 0;
}

void read_blankline(file_stream *fs)
{
    read_space(fs);

    switch(fs_read(fs)) {
    case '#':
        read_comment(fs);
        break;

    case '\n':
        break;

    default:
        LOG_E("Unexpected character\n"); /* TODO: finish this */
        fs->error = EINVAL;
        break;
    }
}

void read_setting(file_stream *fs, global_config *conf)
{
    int start = 0;
    int end = KEYS_SIZE-1;
    int idx = 0;

    char c = fs_peek(fs);
    while (true) {
        if (isblank(c) || c == ':') /* designates end of label */
            c = '\0';
        else
            fs_read(fs); /* consume peeked character--it's in our label */

        while (start != end && keys[start].label[idx] != c)
            start++; /* narrow scope of possible labels */

        while (end != start && keys[end].label[idx] != c)
            end--; /* narrow scope from the other end */
        
        if (start == end) {
            if (keys[start].label[idx] != c) {
                LOG_E("Invalid label within config (line %u)\n", fs->lineno);
                fs->error = EINVAL;
                return;

            } else {
                break;
                /* return keys[start].func; */
            }
        }

        c = fs_peek(fs);
        idx++;
    }

    keys[start].func(fs, conf);

    return;
}

void *read_label(file_stream *fs)
{
    int start = 0;
    int end = KEYS_SIZE-1;
    int idx = 0;
    char c = fs_peek(fs);
        
    while (c != EOF) {

        if (isblank(c) || c == ':') /* designates end of label */
            c = '\0';
        else
            fs_read(fs); /* consume peeked character--it's in our label */

        while (start != end && keys[start].label[idx] != c)
            start++; /* narrow scope of possible labels */
            
        while (end != start && keys[end].label[idx] != c)
            end--; /* narrow scope from the other end */
        
        if (start == end) {
            if (keys[start].label[idx] != c) {
                LOG_E("Invalid label within config (line %u)\n", fs->lineno);
                return NULL;

            } else {
                return keys[start].func;
            }
        }

        c = fs_peek(fs);
        idx++;
    }

    if (c == EOF && fs->error == 0)
        LOG_E("Unexpected EOF while parsing (line %u)\n", fs->lineno);

    return NULL;
}

/*
int read_after_space(file_stream *fs)
{
    char c;

    read_space(fs);

    c = fs_peek(fs);
    if (c == '#') {
        read_comment(fs);

    } else if (c == '\n') {
        fs_read(fs);

    } else if (c != EOF) {
        LOG_E("Config had unexpected characters (line %u)\n", fs->lineno);
        return -1;
    }

    return 0;
}
*/

void read_space(file_stream *fs)
{
    char c = fs_peek(fs);

    while (isspace(c) && c != '\n') {
        fs_read(fs);
        c = fs_peek(fs);
    }
}

void read_comment(file_stream *fs)
{
    char c = fs_read(fs);
    while (c != '\n' && c > 0)
        c = fs_read(fs);

    return;
}

void read_to_newline(file_stream *fs)
{
    char c;

    read_space(fs);

    switch(fs_read(fs)) {
    case '#':
        read_comment(fs);
        return;
    case '\n':
        return;
    default:
        return; /* Unexpected characters */
    }
}

int read_list(file_stream *fs, char **str_list[])
{
    char list_buf[MAX_LIST_SIZE+1] = {0};
    int list_buf_idx = 0;
    int indentation = 0;
    
    read_to_newline(fs);

    char c = fs_read(fs);
    while (c > 0 && (isspace(c) || c == '-')) {
        if (c == '-') {
            
        }
        
        
        if (c != '\n') {
            
        }

        c = fs_read(fs);
    }
    



}

int read_string(file_stream *fs, char **str)
{
    char buf[MAX_TOKEN_SIZE+1] = {0};
    char c;
    int buf_idx = 0;

    do {
        c = fs_read(fs);
        
        if (c == '\n') {
            break;
        } else if (isspace(c)) {
            read_space(fs);
            if (read_after_space(fs) != 0)
                return -1;
            break;
        } else if (c == '#') {
            read_comment(fs);
            break;
        } else if (c == EOF) {
            break;
        } else {
            buf[buf_idx] = c;
            buf_idx++;
        }
    } while (buf_idx < MAX_TOKEN_SIZE);

    if (buf_idx >= MAX_TOKEN_SIZE) {
        LOG_E("Config: Token exceeded max size of 128 (line %u)\n", fs->lineno);
        return -1;
    }

    if (buf_idx == 0) {
        LOG_E("Config: Token missing for key (line %u)\n", fs->lineno);
        return -1;
    }

    *str = strdup(buf);
    if (*str == NULL) {
        LOG_E("Config: Malloc failure (line %u)\n", fs->lineno);
        return -1;
    }

    return 0;
}

int is_int(char *str)
{
    int i = 0;

    if (str[i] == '0' && str[i+1] != '\0')
        return 0; /* Leading 0's not good */
    
    while (str[i] != '\0') {
        if (str[i] < '0' || str[i] > '9')
            return 0;
        i++;
    }

    if (i > 9)
        return 0; /* Probably too bit to fit into `int` */

    return 1;
}

int read_uint(file_stream *fs, int *val)
{
    char *int_str;
    
    int ret = read_string(fs, &int_str);
    if (ret != 0)
        return -1;

    if (!is_int(int_str)) {
        free(int_str);
        return -1;
    }

    *val = atoi(int_str);

    free(int_str);
    return 0;
}

int read_uint_bounded(file_stream *fs, int *val, int min, int max)
{
    int ret = read_uint(fs, val);
    if (ret != 0 || *val < min || *val > max)
        return -1;

    return 0;
}

int read_boolean(file_stream *fs, int *val)
{
    char *str;

    int ret = read_string(fs, &str);
    if (ret != 0)
        return -1;

    if (strcmp(str, "enabled") == 0) {
        *val = 1;
        ret = 0;
    } else if (strcmp(str, "disabled") == 0) {
        *val = 0;
        ret = 0;
    } else {
        ret = -1;
    }
    
    free(str);
    return ret;
}
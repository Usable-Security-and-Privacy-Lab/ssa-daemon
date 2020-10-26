#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "socket_setup.h"

#define READER_BUF_MAX 4096
#define MAX_TOKEN_SIZE 256


typedef struct file_stream_st {
    char buf[READER_BUF_MAX];
    unsigned int buf_index;
    unsigned int buf_length;
    unsigned int lineno;
    int eof;
    int error;
    int fd;
} file_stream;

struct label_pair {
    char *label;
    int (*func)(file_stream *, global_config *);
    /* put generic parsing function callback here */
};


/* MUST BE SORTED ALPHABETICALLY */
/* dashes ('-') come alphabetically before anything else */
static const struct label_pair keys[] = {
    { .label = "ca-path", .func = read_ca_path },
    { .label = "cert-path" },
    { .label = "cert-verification-depth" },
    { .label = "cipher-list" },
    { .label = "ciphersuites" },
    { .label = "key-path" },
    { .label = "max-tls-version" },
    { .label = "min-tls-version" },
    { .label = "revocation-cached" },
    { .label = "revocation-checks" },
    { .label = "revocation-crl" },
    { .label = "revocation-ocsp" },
    { .label = "revocation-stapled" },
    { .label = "session-resumption" },
    { .label = "session-tickets" },
    { .label = "session-timeout" },
    { .label = "verify-cert-transparency" },
};

#define KEYS_SIZE (sizeof(keys) / sizeof(struct label_pair))


int file_stream_init(file_stream *fs, char *path);
int file_stream_close(file_stream *fs);

char fs_peek(file_stream *fs);
char fs_read(file_stream *fs);

int read_settings(file_stream *fs, global_config *config);
void *read_label(file_stream *fs);

int read_after_space(file_stream *fs);
void read_space(file_stream *fs);
void read_comment(file_stream *fs);

int read_ca_path(file_stream *fs, global_config *conf);




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

int read_settings(file_stream *fs, global_config *config)
{
    char *label;
    void *label_func;
    char c = fs_peek(fs);
    int ret;

    while (c != EOF) {

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

            /* TODO: execute label_func here */
        }

        c = fs_peek(fs);
    }

    if (fs->error)
        return -1;
    
    return 0;
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

/*******************************************************************************
 * 
 ******************************************************************************/

char *read_string(file_stream *fs)
{
    char buf[MAX_TOKEN_SIZE+1] = {0};
    char *str = NULL;
    char c;
    int buf_idx = 0;

    do {
        c = fs_read(fs);
        
        if (c == '\n') {
            break;
        } else if (isspace(c)) {
            read_space(fs);
            if (read_after_space(fs) != 0)
                return NULL;
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
        LOG_E("Config: token exceeded max size of 128 (line %u)\n", fs->lineno);
        return NULL;
    }

    if (buf_idx == 0) {
        LOG_E("Config: Token missing for key (line %u)\n", fs->lineno);
        return NULL;
    }

    str = strdup(buf);
    if (str == NULL) {
        LOG_E("Config: Malloc failure (line %u)\n", fs->lineno);
        return NULL;
    }

    return str;
}


int read_ca_path(file_stream *fs, global_config *conf)
{
    if (conf->ca_path != NULL)
        free(conf->ca_path);

    conf->ca_path = read_string(fs);

    return (conf->ca_path == NULL) ? -1 : 0;
}


#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "socket_setup.h"

#define READER_BUF_MAX 4096
#define MAX_TOKEN_SIZE 256
#define MAX_LIST_SIZE 256

int fs_init(file_stream *fs, char *path);
int fs_close(file_stream *fs);

char fs_peek(file_stream *fs);
char fs_read(file_stream *fs);

int read_settings(file_stream *fs, global_config *config);
int read_setting(file_stream *fs, global_config *conf, int *keys_parsed);

void read_space(file_stream *fs);
int read_blankline(file_stream *fs);
void read_comment(file_stream *fs);

int is_int(char *str);

struct file_stream_st {
    char buf[READER_BUF_MAX];
    unsigned int buf_index;
    unsigned int buf_length;
    unsigned int lineno;
    int eof;
    int error;
    int fd;
};

void global_settings_free(global_config* settings)
{
    if (settings == NULL)
        return;

    if (settings->cipher_list != NULL) {
        for (int i = 0; i < settings->cipher_list_cnt; i++)
            free(settings->cipher_list[i]);
        free(settings->cipher_list);
    }

    if (settings->ciphersuites != NULL) {
        for (int i = 0; i < settings->ciphersuite_cnt; i++)
            free(settings->ciphersuites[i]);
        free(settings->ciphersuites);
    }

    free(settings);
}


global_config* parse_config(char* file_path)
{
    global_config *config = NULL;
    file_stream fs;
    int err;

    err = fs_init(&fs, file_path);
    if (err)
        return NULL;

    config = calloc(1, sizeof(global_config));
    if (config == NULL) {
        LOG_E("Failed to allocate config structure: %s\n", strerror(errno));
        goto out;
    }

    err = read_settings(&fs, config);
    if (err)
        goto out;
    
    return config;

out:
    if (config != NULL)
        global_settings_free(config);

    fs_close(&fs);
    return NULL;
}

int fs_init(file_stream *fs, char *path)
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

int fs_close(file_stream *fs)
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
    int keys_parsed[PARSER_KEY_CNT] = {0};
    char c = fs_peek(fs);
    int err = 0;

    while (c != EOF && err == 0) {

        switch (c) {
        case '\n':
            fs_read(fs);
            break;

        case ' ':
            err = read_blankline(fs);
            break;

        case '#':
            read_comment(fs);
            break;

        default:
            err = read_setting(fs, conf, keys_parsed);
            break;
        }
        
        c = fs_peek(fs);
    }

    if (fs->error)
        err = -1;
    
    return err;
}

int read_blankline(file_stream *fs)
{
    read_space(fs);

    switch(fs_read(fs)) {
    case '#':
        read_comment(fs);
        return 0;
    case '\n':
        return 0;
    default:
        LOG_E("Config: Unexpected character (line %i)\n", fs->lineno);
        return -1;
    }
}

int read_setting(file_stream *fs, global_config *conf, int *keys_parsed)
{
    int start = 0;
    int end = PARSER_KEY_CNT-1;
    int idx = 0;

    char c = fs_peek(fs);
    while (1) {
        if (isblank(c) || c == ':') /* designates end of label */
            c = '\0';
        else
            fs_read(fs); /* consume peeked character--it's in our label */

        while (start != end && parser_keys[start].label[idx] != c)
            start++; /* narrow scope of possible labels */

        while (end != start && parser_keys[end].label[idx] != c)
            end--; /* narrow scope from the other end */
        
        if (start == end) {
            if (parser_keys[start].label[idx] != c) {
                LOG_E("Invalid label within config (line %u)\n", fs->lineno);
                return -1;

            } else if (keys_parsed[start] != 0) {
                LOG_E("Parser: label used twice in config (line %u)\n", fs->lineno);
                return -1;
            } else {
                keys_parsed[start] = 1;
                return parser_keys[start].func(fs, conf);
            }
        }

        c = fs_peek(fs);
        idx++;
    }
}

int parser_read_string(file_stream *fs, char **str)
{
    char buf[MAX_TOKEN_SIZE+1] = {0};
    int buf_idx = 0;
    char c;

    while (buf_idx < MAX_TOKEN_SIZE) {
        c = fs_read(fs);
        switch (c) {
        case '\n':
            break;

        case ' ':
            if (read_blankline(fs) != 0)
                return -1;
            break;
        
        case '#':
            read_comment(fs);
            break;
        
        case EOF:
            break;

        default:
            buf[buf_idx] = c;
            buf_idx++;
        }
    }

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
}

int is_int(char *str)
{
    int i = 0;

    if (str[i] == '-' && str[i+1] != '\0')
        i++;

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

int parser_read_int(file_stream *fs, int *val, int min, int max)
{
    char *int_str;
    int err = 0;

    err = parser_read_string(fs, &int_str);
    if (err)
        return -1;

    if (!is_int(int_str)) {
        LOG_E("Config: Value expected to be int (line %i)\n", fs->lineno);
        return -1;
    
    } else if (*val < min || *val > max) {
        LOG_E("Config: Value was out of bounds (line %i)\n", fs->lineno);
        return -1;

    } else {
        *val = atoi(int_str);
    }

    free(int_str);
    return 0;
}

int parser_read_boolean(file_stream *fs, int *val)
{
    char *str;
    int err = 0;

    err = parser_read_string(fs, &str);
    if (err)
        return -1;

    if (strcmp(str, "enabled") == 0) {
        *val = 1;
    } else if (strcmp(str, "disabled") == 0) {
        *val = 0;
    } else {
        LOG_E("Config: boolean value expected (line %i)\n", fs->lineno);
        return -1;
    }
    
    free(str);
    return 0;
}

int parser_read_list(file_stream *fs, char **str_list[])
{   
    char *tmp_list[MAX_LIST_SIZE];
    int list_idx = 0;
    int indentation = 0;
    int curr_indent = 0;
    int err = 0;
    
    if (read_blankline(fs) != 0)
        return -1;

    char c = fs_read(fs);
    while (c == ' ' || c == '-') {
        if (c == ' ') {
            curr_indent++;
            if (list_idx == 0)
                indentation++;

        } else {
            if (curr_indent != indentation) {
                LOG_E("Config: uneven indentation in list (line %i)\n", fs->lineno);
                goto out;
            }

            if (list_idx == MAX_LIST_SIZE) {
                LOG_E("Config: exceeded maximum list elements (line %i\n", fs->lineno);
                goto out;
            }

            err = parser_read_string(fs, &tmp_list[list_idx]);
            if (err)
                goto out;

            list_idx++;
        }
        
        c = fs_read(fs);
    }

    if (list_idx == 0) {
        LOG_E("Config: list item missing where expected (line %i)\n", fs->lineno);
        goto out;
    }

    *str_list = calloc(list_idx, sizeof(char*));
    if (*str_list == NULL) {
        LOG_E("Config: out of memory (line %i)\n", fs->lineno);
        goto out;
    }

    for (int i = 0; i < list_idx; i++)
        (*str_list)[i] = tmp_list[i];

    return list_idx;
out:
    for (int i = 0; i < list_idx; i++) {
        free(str_list[i]);
    }

    return -1;
}
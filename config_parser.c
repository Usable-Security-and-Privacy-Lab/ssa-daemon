/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
    unsigned int buf_idx;
    unsigned int buf_length;
    unsigned int lineno;
    unsigned int colno;
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

    if (file_path == NULL)
        file_path = DEFAULT_CONFIG_PATH;

    err = fs_init(&fs, file_path);
    if (err)
        return NULL;

    config = calloc(1, sizeof(global_config));
    if (config == NULL) {
        LOG_E("Config parser: Failed to allocate settings struct: %s\n", 
                    strerror(errno));
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
    fs->colno = 0;
    fs->buf_idx = 0;
    fs->buf_length = 0;
    fs->eof = 0;
    fs->error = 0;

    fs->fd = open(path, O_RDONLY);
    if (fs->fd < 0) {
        LOG_E("Config parser: Unable to open config file: %s\n", 
                    strerror(errno));
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

    if (fs->buf_idx >= fs->buf_length) {
        fs->buf_idx = 0;
        fs->buf_length = read(fs->fd, fs->buf, READER_BUF_MAX);

        if (fs->buf_length < 0) {
            fs->error = errno;
            LOG_E("Config parser: File error occurred during scanning "
                        "(Ln %u, Col %u): %s\n", fs->lineno, fs->colno, 
                        strerror(errno));
            return EOF; /* errors reported as EOF with `error` field set */
        
        } else if (fs->buf_length == 0) {
            fs->eof = 1;
            return EOF;
        }
    }

    return fs->buf[fs->buf_idx];
}

char fs_read(file_stream *fs)
{
    char c = fs_peek(fs);
    if (c != EOF) {
        fs->buf_idx++;
        fs->colno++;
    }

    if (c == '\n') {
        fs->lineno++;
        fs->colno = 0;
    }

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
        LOG_E("Config parser: Unexpected character (Ln %u, Col %u)\n",
                    fs->lineno, fs->colno);
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

        if (parser_keys[start].label[idx] != c) {
            LOG_E("Config parser: Invalid label encountered (Ln %u, Col %u)\n",
                        fs->lineno, fs->colno);
            return -1;
        }
        
        if (start == end && c == '\0') {
            if (keys_parsed[start] != 0) {
                LOG_E("Config parser: label used twice in config "
                            "(Ln %u, Col %u)\n", fs->lineno, fs->colno);
                return -1;

            } else {
                read_space(fs);
                if (fs_read(fs) != ':') {
                    LOG_E("Config parser: Expected ':' after label "
                                "(Ln %u, Col %u)\n", fs->lineno, fs->colno);
                    return -1;
                }

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

    read_space(fs);

    while (buf_idx < MAX_TOKEN_SIZE) {
        c = fs_read(fs);
        
        if (c == ' ') {
            if (read_blankline(fs) != 0)
                return -1;
            break;
        } else if (c == '#') {
            read_comment(fs);
            break;
        } else if (c == EOF || c == '\n') {
            break;
        }

        buf[buf_idx] = c;
        buf_idx++;
    }

    if (buf_idx >= MAX_TOKEN_SIZE) {
        LOG_E("Config parser: Token exceeded max size of 128 (Ln %u, Col %u)\n",
                    fs->lineno, fs->colno);
        return -1;
    }

    if (buf_idx == 0) {
        LOG_E("Config parser: Token missing for key (Ln %u, Col %u)\n", 
                    fs->lineno, fs->colno);
        return -1;
    }

    *str = strdup(buf);
    if (*str == NULL) {
        LOG_E("Config parser: Out of memory (Ln %u, Col %u)\n", 
                    fs->lineno, fs->colno);
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

    if (parser_read_string(fs, &int_str) != 0)
        return -1;

    int parsed_int = atoi(int_str);

    if (!is_int(int_str)) {
        LOG_E("Config parser: Value expected to be int (Ln %u, Col %u)\n", 
                    fs->lineno, fs->colno);
        err = -1;   

    } else if (parsed_int < min || parsed_int > max) {
        LOG_E("Config parser: Value was out of bounds (Ln %u, Col %u)\n", 
                    fs->lineno, fs->colno);
        err = -1;
    } else {
        *val = parsed_int;
    }

    free(int_str);
    return err;
}

int parser_read_boolean(file_stream *fs, int *val)
{
    char *str;
    int err = 0;

    if (parser_read_string(fs, &str) != 0)
        return -1;

    if (strcmp(str, "enabled") == 0) {
        *val = 1;
    } else if (strcmp(str, "disabled") == 0) {
        *val = 0;
    } else {
        LOG_E("Config parser: Boolean expected (i.e. 'enabled'/'disabled') "
                    "(Ln %u, Col %u)\n", fs->lineno, fs->colno);
        err = -1;
    }
    
    free(str);
    return err;
}

int parser_read_list(file_stream *fs, char **str_list[])
{   
    char *tmp_list[MAX_LIST_SIZE] = {0};
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
                LOG_E("Config parser: Uneven indentation in list "
                            "(Ln %u, Col %u)\n", fs->lineno, fs->colno);
                goto out;
            }

            if (list_idx == MAX_LIST_SIZE) {
                LOG_E("Config parser: Exceeded maximum number of list elements "
                            "(Ln %u, Col %u)\n", fs->lineno, fs->colno);
                goto out;
            }

            err = parser_read_string(fs, &tmp_list[list_idx]);
            if (err)
                goto out;

            list_idx++;
            curr_indent = 0;
        }
        
        c = fs_read(fs);
    }

    if (list_idx == 0) {
        LOG_E("Config parser: List items expected (Ln %u, Col %u)\n", 
                    fs->lineno, fs->colno);
        goto out;
    }

    *str_list = calloc(list_idx, sizeof(char*));
    if (*str_list == NULL) {
        LOG_E("Config parser: Out of memory (Ln %u, Col %u)\n", 
                    fs->lineno, fs->colno);
        goto out;
    }

    for (int i = 0; i < list_idx; i++)
        (*str_list)[i] = tmp_list[i];

    return list_idx;
out:
    for (int i = 0; i < list_idx; i++)
        free(str_list[i]);

    return -1;
}
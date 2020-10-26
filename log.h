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
#ifndef SSA_LOG_H
#define SSA_LOG_H

#include <stdarg.h>
#include <syslog.h>

#ifndef NO_LOG

/** 
 * Initializes the log to write its output to \p LOG_Cilename, or to stdout 
 * otherwise. Should be followed by a call to `log_close()` once finished.
 * @returns 0 on success, or -1 if the file could not be opened to write to.
 */
int log_init();


/** 
 * Prints the given `printf`-formatted message to logs with log level \p level.
 * If the log level isn't greater than or equal to the minimum set in 
 * `log_init`, then no message will be print.
 * @param level The level of the log to print out.
 * @param format The `printf`-formatted error message to print out.
 */
void log_printf(int level, const char* format, ...);


/**
 * Closes the log file being written to.
 */
void log_close(void);

#define LOG_A(...) log_printf(LOG_ALERT, __VA_ARGS__)
#define LOG_C(...) log_printf(LOG_CRIT, __VA_ARGS__)
#define LOG_E(...) log_printf(LOG_ERR, __VA_ARGS__)
#define LOG_W(...) log_printf(LOG_WARNING, __VA_ARGS__)
#define LOG_N(...) log_printf(LOG_NOTICE, __VA_ARGS__)
#define LOG_I(...) log_printf(LOG_INFO, __VA_ARGS__)
#define LOG_D(...) log_printf(LOG_DEBUG, __VA_ARGS__)


#else
#define noop
#define log_init(X, Y)    ((int)0)
#define log_printf(...) noop
#define log_close() noop

#define LOG_DEBUG(...) noop
#define LOG_INFO(...) noop
#define LOG_WARN(...) noop
#define LOG_ERR(...) noop
#define LOG_CATAL(...) noop
#endif

#endif

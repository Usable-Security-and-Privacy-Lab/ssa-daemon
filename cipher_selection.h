/*
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
 #include <event2/util.h>
 #include "daemon_structs.h"


 #define DISABLE_INSECURE_CIPHERS ":!SSLv3:!TLSv1:!TLSv1.1:!eNULL:!aNULL:!RC4:!MD4:!MD5"

 /* helper */
 int deletion_loop(char* cipher, char** cipherlist);
 int delete_from_cipherlist(char* cipher, char** cipherlist);
 int append_to_cipherstring(char* cipher, char** cipherstring);
 int get_ciphersuite_string(socket_ctx* conn, char** buf, unsigned int* buf_len);
 int get_cipher_list_string(socket_ctx* conn, char** buf, unsigned int* buf_len);
 char* get_string_version(char* cipher_to_check);

 /* setsockopt */
 int disable_cipher(socket_ctx* conn, char* cipher);
 int disable_ciphers(socket_ctx* conn, char* cipher);
 int enable_cipher(socket_ctx* conn, char* cipher);

 /* getsockopt */
 //int get_enabled_ciphers(socket_ctx* conn, char** data, unsigned int* len);
 int get_last_negotiated(socket_ctx* conn, char** data, unsigned int* len);

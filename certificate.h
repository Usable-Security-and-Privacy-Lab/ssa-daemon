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

#ifndef CERTIFICATE
#define CERTIFICATE

#include <dirent.h>
#include <openssl/x509v3.h>

/**
 * Check if null terminated string ends with ".pem".
 * @param path String to check for ".pem".
 * @return 1 if last four chars are ".pem", else 0.
 */
int is_pem_file(char* path);

/**
 * Searches cert_list for the certificate that isn't a CA (the end entity).
 * If a certificate is not a CA, it is assumed to be the end entity. 
 * @param cert_list Array of certificates to search.
 * @return The index of the end cert or -1 on error.
 */
int get_end_entity(X509** cert_list, int num_certs);

/**
 * Get number of files in directory.
 * @param directory An open directory containing certificate files. 
 * @returns number of files in directory.
 */
int get_directory_size(DIR* directory);

/**
 * Reads a directory of certificate files, converts them to X509 certificates, 
 * and adds them to cert_list. 
 * @param cert_list Array of certificate pointers to be populated with certificates in directory.
 * @param directory The directory containing certificates to put into cert_list.
 * @param dir_name Path of directory.
 * @return 0 on success, else -1. 
 */
int get_directory_certs(X509** cert_list, DIR* directory, char* dir_name);

/**
 * Sorts certificates and loads them in order (from end entity to root) into a context.
 * @param ctx Context to load certificates into.
 * @param cert_list Array of certificates to load into context.
 * @param num_certs Number of certificates in cert_list array.
 * @return 1 on success, 0 on error.
 */
int add_directory_certs(SSL_CTX* ctx, X509** cert_list, int num_certs);

/**
 * Loads a private key into SSL_CTX, verifies the key matches the last certificate 
 * chain loaded in ctx, and builds the certificate chain. This function should be 
 * called after a certificate is loaded into the CTX. 
 * @param ctx The context the private key will be loaded into.
 * @param key_path Path to private key file. This file should be PEM or DER (ASN1).
 * @return 1 on success, 0 on error.
 */
int load_private_key(SSL_CTX* ctx, char* key_path);

/**
 * A certificate file or directory is loaded into ctx. The private key should
 * be loaded into ctx after this function is called. 
 * @param ctx The context that certificates will be loaded into.
 * @param path The path to a PEM file or directory containing all certificates
 * in the chain to be loaded into ctx.
 * @returns 1 on success, 0 on error.
 */
int load_certificates(SSL_CTX* ctx, char* path);

/**
 * A directory containing certificate files is loaded into ctx. The private key 
 * should be loaded into ctx after this function is called. 
 * @param ctx The context that certificates will be loaded into.
 * @param path The path to a directory containing all certificates
 * in the chain to be loaded into ctx.
 * @returns 1 on success, 0 on error.
 */
int load_directory_certs(SSL_CTX* ctx, char* path);

#endif
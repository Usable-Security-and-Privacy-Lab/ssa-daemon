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
#ifndef SSA_HASHMAP_STR_H
#define SSA_HASHMAP_STR_H

typedef struct hsmap {
    struct hsnode** buckets;
    int num_buckets;
    int item_count;
} hsmap_t;


/**
 * Creates a new string hashmap that is \p num_buckets in size. Note that 
 * the hashmap will be capable of storing much more than \p num_buckets;
 * it is simply the array size for the hashmap.
 * @param num_buckets the size of the hashmap.
 * @returns A new string hashmap pointer, or NULL on failure.
 */
hsmap_t* str_hashmap_create(int num_buckets);


/**
 * Frees all entries from the given string hashmap \p map, but leaves the 
 * values of each entry alone.
 * @param map The map to be freed.
 */
void str_hashmap_free(hsmap_t* map);


/**
 * Frees all entries from the given string hashmap \p map, and frees
 * the values of each entry using \p free_func.
 * @param map The map to free.
 * @param free_func The function used to free each value from the hashmap.
 */
void str_hashmap_deep_free(hsmap_t* map, void (*free_func)(void*));


/**
 * Adds the given key:value pair to \p map.
 * @param map The map to add a new element to.
 * @param key The null-terminated string used to lookup the value in \p map.
 * @param value A pointer to a data structure to be stored in \p map.
 * @returns 0 on success; 1 if the entry could not be found; or -1 on 
 * malloc failure.
 */
int str_hashmap_add(hsmap_t* map, char* key, void* value);


/**
 * Deletes the entry associated with \p key from \p map.
 * @param map The map to delete an entry from.
 * @param key A null-terminated string that identifies the entry to delete.
 * @returns 0 on success, or 1 if no entry exists for \p key.
 */
int str_hashmap_del(hsmap_t* map, char* key);


/**
 * Retrieves the value associated with \p key from \p map.
 * @param map The string hashmap to retrieve a value from.
 * @param key The key associated with the value to retrieve.
 * @returns A pointer to the value associated with \p key, 
 * or NULL if no entry exists in the hashmap for \p key.
 */
void* str_hashmap_get(hsmap_t* map, char* key);


/**
 * Prints the entire contents of the hashmap to stdout.
 * @param map The map to print.
 */
void str_hashmap_print(hsmap_t* map);


#endif
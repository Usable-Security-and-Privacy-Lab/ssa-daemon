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

#ifndef SSA_HASHQUEUE_H
#define SSA_HASHQUEUE_STR_H

typedef struct hqueue {
    struct hqnode** buckets;
    int num_buckets;
    int item_count;
} hqueue_t;


/**
 * The `hashqueue` data structure is a slight variation on the standard 
 * hashqueue implementation. In traditional maps, each key is associated 
 * with exactly one value, which the queue can then check for, add, or 
 * remove with O(1) complexity. The hashqueue extends the base principle 
 * of hashing the key to achieve quick checks and removals while extending 
 * the implementation to allow for multiple elements of the same key to be 
 * stored. It should be noted that this increases the insertion time to 
 * O(k), where k is the number of elements already in the queue of the given key, 
 * but such performance is considered acceptable for our uses.
 * 
 * This structure is particularly useful for SSL sessions, where:
 * 1. Sessions need to be identified by a "hostname:port" string to be used for 
 * session resumption.
 * 2. Multiple sessions should be able to be stored for one hostname:port combo 
 * to facilitate efficient resumption where multiple clients connect to the 
 * same server.
 * 3. Older sessions should be used before newer sessions, to keep sessions in 
 * the cache fresh.
 * 
 * Each session is simply hashed according to its "hostname:port" string and 
 * then appended to the end of the queue it was hashed in. Accessing or popping 
 * an element of a given key is as simple as the original hashqueue 
 * implementation.
 * 
 * Creates a new hashqueue that is \p num_buckets in size. Note that 
 * the hashqueue will be capable of storing much more than \p num_buckets;
 * it is simply the array size for the hashqueue.
 * @param num_buckets the size of the hashqueue.
 * @returns A new string hashqueue pointer, or NULL on failure.
 */
hqueue_t* hashqueue_create(int num_buckets);


/**
 * Frees all entries from the given string hashqueue \p queue, but leaves the 
 * values of each entry alone.
 * @param queue The queue to be freed.
 */
void hashqueue_free(hqueue_t* queue);


/**
 * Frees all entries from the given string hashqueue \p queue, and frees
 * the values of each entry using \p free_func.
 * @param queue The queue to free.
 * @param free_func The function used to free each value from the hashqueue.
 */
void hashqueue_deep_free(hqueue_t* queue, void (*free_func)(void*));


/**
 * Adds the given key:value pair to \p queue.
 * @param queue The queue to add a new element to.
 * @param key The null-terminated string used to lookup the value in \p queue.
 * @param value A pointer to a data structure to be stored in \p queue.
 * @returns 0 on success; 1 if the entry could not be found; or -1 on 
 * malloc failure.
 */
int hashqueue_push(hqueue_t* queue, char* key, void* value);


/**
 * Deletes the entry associated with \p key from \p queue.
 * @param queue The queue to delete an entry from.
 * @param key A null-terminated string that identifies the entry to delete.
 * @returns 0 on success, or 1 if no entry exists for \p key.
 */
int hashqueue_pop(hqueue_t* queue, char* key);


/**
 * Retrieves the value associated with \p key from \p queue.
 * @param queue The string hashqueue to retrieve a value from.
 * @param key The key associated with the value to retrieve.
 * @returns A pointer to the value associated with \p key, 
 * or NULL if no entry exists in the hashqueue for \p key.
 */
void* hashqueue_front(hqueue_t* queue, char* key);


/**
 * Prints the entire contents of the hashqueue to stdout.
 * @param queue The queue to print.
 */
void hashqueue_print(hqueue_t* queue);


/**
 * In hashqueues where `str_hashqueue_queue_add` has been used, this function 
 * may be used to delete a specific instance of a node when several nodes exist 
 * with the same key. It does so by iterating through each element containing 
 * \p key as its key and checking to see if the pointer \p value matches the 
 * element's value. 
 * @param queue The queue to delete the given key:value pair from. 
 * @param key A *non*-unique null-terminated string to identify the element. 
 * @param value The specific value of the element to be deleted. 
 * @returns 0 on success, or 1 if no element with the given key:value pair 
 * could be found. 
 */
int hashqueue_remove(hqueue_t* queue, char* key, void* value);


#endif
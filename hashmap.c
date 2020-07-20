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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hashmap.h"

typedef struct hnode {
	unsigned long key;  /** The 'key' of the key:value pair for the map */
	void* value;        /** The 'value' of the key:value pair for the map */

	struct hnode* next; /** The next node in the linked list */
} hnode_t;



/**
 * Hashes the given key into one of the hashmap's buckets.
 * @param map The hashmap that the key will be hashed into.
 * @param key The key to be hashed.
 * @returns The hashed valued of the key, suitable for insertion into \p map.
 */
static int hash(hmap_t* map, unsigned long key) {
    return key % map->num_buckets;
}


/**
 * Allocates a new hashmap with the given number of buckets.
 * @param num_buckets The intended size of the hashmap. Note that the 
 * hashamp is implemented with an array/linked-list combo, so it will
 * always be capable of storing an arbitrary number of elements. 
 * \p num_buckets merely allows the user to use less or more buckets 
 * depending on how many elements they intend to store in the hashmap.
 * @returns A pointer to an allocated hmap_t struct, or NULL on failure.
 */
hmap_t* hashmap_create(int num_buckets) {
	hmap_t* map = (hmap_t*)malloc(sizeof(hmap_t));
	if (map == NULL) {
		return NULL;
	}
	map->buckets = (hnode_t**)calloc(num_buckets, sizeof(hnode_t*));
	if (map->buckets == NULL) {
		free(map);
		return NULL;
	}
	map->num_buckets = num_buckets;
	return map;
}


/**
 * Frees up all entries and memory within \p map, and frees the values stored
 * with the \p free_func.
 * @param map The hashmap to free up.
 * @param free_func The function to be used to free each value stored in \p map.
 */
void hashmap_deep_free(hmap_t* map, void (*free_func)(void*)) {
	hnode_t* cur = NULL;
	hnode_t* tmp = NULL;
	int i;
	if (map == NULL) {
		return;
	}
	for (i = 0; i < map->num_buckets; i++) {
		cur = map->buckets[i];
		while (cur != NULL) {
			tmp = cur->next;
			if (free_func != NULL) {
				free_func(cur->value);
			}
			free(cur);
			cur = tmp;
		}
	}
	free(map->buckets);
	free(map);
	return;
}

/**
 * Frees all entries and memory within \p map. This function does not free
 * the values stored; use `hashmap_deep_free` for that functionality.
 * @param map The map to free up.
 */
void hashmap_free(hmap_t* map) {
	hashmap_deep_free(map, NULL);
	return;
}


/**
 * Adds \p key and \p value as a pair to the given hashmap \p map.
 * @param map The map to add the key:value pair to.
 * @param key The positive integer key to use for the pair.
 * @param value A pointer to any value desired to be stored within the hashmap.
 * @returns 0 on success; -1 on malloc failure; and 1 if an entry already
 * exists with \p key as its key.
 */
int hashmap_add(hmap_t* map, unsigned long key, void* value) {
	int index;
	hnode_t* cur;
	hnode_t* next;
	hnode_t* new_node = (hnode_t*)malloc(sizeof(hnode_t));
    if (new_node == NULL)
        return -1;

    new_node->key = key;
	new_node->value = value;
	new_node->next = NULL;
	
	index = hash(map, key);

	cur = map->buckets[index];
	if (cur == NULL) {
		map->buckets[index] = new_node;
		map->item_count++;
		return 0;
	}

	next = cur;
	do {
		cur = next;
		if (cur->key == key) {
			free(new_node);
			return 1; /* Duplicate entry */
		}
		
		next = cur->next;
	} while (next != NULL);

	cur->next = new_node;
	map->item_count++;
	return 0;
}


/**
 * Deletes the entry with the key value equal to \p key from \p map.
 * Note that this function does not free up the value associated with
 * the key.
 * @param map The map to delete the entry from.
 * @param key The key of the entry to be deleted.
 * @returns 0 on success, or 1 if no entry exists for \p key.
 */
int hashmap_del(hmap_t* map, unsigned long key) {
	int index;
	hnode_t* cur;
	hnode_t* tmp;
	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return 1;
	}

	if (cur->key == key) {
		map->buckets[index] = cur->next;
		free(cur);
		map->item_count--;
		return 0;
	}
	while (cur->next != NULL) {
		if (cur->next->key == key) {
			tmp = cur->next;
			cur->next = cur->next->next;
			free(tmp);
			map->item_count--;
			return 0;
		}
		cur = cur->next;
	}
	return 1; /* Not found */
}


/**
 * Retrieves the value pointer associated with \p key from the given hashmap
 * \p map.
 * @param map The map to retrieve a value from.
 * @param key The key of the value desired to be retrieved.
 * @returns A void pointer representing the value associated with \p key, or
 * NULL if the value was not in the hashmap.
 */
void* hashmap_get(hmap_t* map, unsigned long key) {
	int index;
	hnode_t* cur;
	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL)
		return NULL;


	do {
		if (cur->key == key)
			return cur->value;
		
		cur = cur->next;
	} while (cur != NULL);

	return NULL;
}


/**
 * Prints the entire contents of the hashmap to stdout.
 * @param map The map to print.
 */
void hashmap_print(hmap_t* map) {
	int i;
	hnode_t* cur;
	printf("Hash map contents:\n");
	for (i = 0; i < map->num_buckets; i++) {
		printf("\tBucket %d:\n", i);
		cur = map->buckets[i];
		while (cur) {
			printf("\t\tNode [key = %lu, value=%p]\n",
				cur->key, cur->value);
			cur = cur->next;
		}
	}
	return;
}
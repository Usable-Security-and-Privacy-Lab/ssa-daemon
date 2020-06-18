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
	struct hnode* next;
	union {
		unsigned long k_long;
		char* k_str;
		void* k_ptr;
	} key;
	void* value;
} hnode_t;


static int hash(hmap_t* map, unsigned long key);

int hash(hmap_t* map, unsigned long key) {
	return key % map->num_buckets;
}

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

void hashmap_free(hmap_t* map) {
	hashmap_deep_free(map, NULL);
	return;
}

int hashmap_add(hmap_t* map, unsigned long key, void* value) {
	int index;
	hnode_t* cur;
	hnode_t* next;
	hnode_t* new_node = (hnode_t*)malloc(sizeof(hnode_t));
    if (new_node == NULL)
        return -1;

    new_node->key.k_long = key;
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
		if (cur->key.k_long == key) {
			free(new_node);
			return 1; /* Duplicate entry */
		}
		
		next = cur->next;
	} while (next != NULL);

	cur->next = new_node;
	map->item_count++;
	return 0;
}

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

	if (cur->key.k_long == key) {
		map->buckets[index] = cur->next;
		free(cur);
		map->item_count--;
		return 0;
	}
	while (cur->next != NULL) {
		if (cur->next->key.k_long == key) {
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

void* hashmap_get(hmap_t* map, unsigned long key) {
	int index;
	hnode_t* cur;
	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return NULL;
	}

	do {
		if (cur->key.k_long == key)
			return cur->value;
		
		cur = cur->next;
	} while (cur != NULL);
	
	return NULL;
}

void hashmap_print(hmap_t* map) {
	int i;
	hnode_t* cur;
	printf("Hash map contents:\n");
	for (i = 0; i < map->num_buckets; i++) {
		printf("\tBucket %d:\n", i);
		cur = map->buckets[i];
		while (cur) {
			printf("\t\tNode [key = %lu, value=%p]\n",
				cur->key.k_long, cur->value);
			cur = cur->next;
		}
	}
	return;
}
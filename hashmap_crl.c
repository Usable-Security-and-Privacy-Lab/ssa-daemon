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
#include "hashmap_crl.h"

typedef struct hcnode {
	struct hcnode* next;
	char* key;
	int len;
} hcnode_t;

static int hash(hcmap_t* map, char* key, int len);
int crl_match(hcnode_t* check, char* key, int len);

int hash(hcmap_t* map, char* key, int len) {
	int i = 0;
	unsigned int hash_val = 0;

	for (i = 0; i < len; ++i) {
		if (key[i] == 0xFF)
			fprintf(stderr, "this is a test\n");
		hash_val += (i * key[i]);
	}

	hash_val = hash_val % map->num_buckets;		
	return hash_val;
}


hcmap_t* crl_hashmap_create(int num_buckets) {
	fprintf(stderr, "creating hashmap\n");
	hcmap_t* map = (hcmap_t*)calloc(1, sizeof(hcmap_t));
	if (map == NULL) {
		return NULL;
	}
	map->buckets = (hcnode_t**)calloc(num_buckets, sizeof(hcnode_t*));
	if (map->buckets == NULL) {
		free(map);
		return NULL;
	}
	map->num_buckets = num_buckets;
	return map;
}

void crl_hashmap_free(hcmap_t* map) {
	hcnode_t* cur = NULL;
	hcnode_t* tmp = NULL;
	int i;
	if (map == NULL) {
		return;
	}
	for (i = 0; i < map->num_buckets; i++) {
		cur = map->buckets[i];
		while (cur != NULL) {
			tmp = cur->next;
			
            free(cur->key);
			free(cur);
			cur = tmp;
		}
	}
	free(map->buckets);
	free(map);
	return;
}

int crl_hashmap_add(hcmap_t* map, char* key, int len) {
	int index;
	hcnode_t* cur;
	hcnode_t* next;
	hcnode_t* new_node = (hcnode_t*)calloc(1, sizeof(hcnode_t));
	if (new_node == NULL)
		return 0;
	new_node->key = key;
	new_node->len = len;
	new_node->next = NULL;

	if (key == NULL) {
		free(new_node);
		return 0;
	}
	
	index = hash(map, key, len);

	cur = map->buckets[index];
	next = cur;
	if (cur == NULL) {
		map->buckets[index] = new_node;
		map->item_count++;
		return 1;
	}
	int k = 0;
	do {
		cur = next;
		if(crl_match(cur, key, len)) {
			/* Duplicate entry */
			free(new_node);
			return 0;
		}
		k++;
		next = cur->next;
	} while (next != NULL);

	cur->next = new_node;
	map->item_count++;
	return 1;
}

int crl_hashmap_del(hcmap_t* map, char* key, int len) {
	int index;
	hcnode_t* cur;
	hcnode_t* tmp;
	index = hash(map, key, len);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return 0;
	}
	if (crl_match(cur, key, len)) {
		map->buckets[index] = cur->next;
		free(cur);
		map->item_count--;
		return 1;
	}
	while (cur->next != NULL) {
		if (crl_match(cur, key, len)) {
			tmp = cur->next;
			cur->next = cur->next->next;
            free(tmp->key);
			free(tmp);
			map->item_count--;
			return 1;
		}
		cur = cur->next;
	}
	/* Not found */
	return 0;
}

int crl_hashmap_get(hcmap_t* map, char* key, int len) {
	int index;
	hcnode_t* cur;

	if (key == NULL) {
		return 0;
	}

	index = hash(map, key, len);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return 0;
	}
	if (crl_match(cur, key, len)) {
		return 1;
	}
	while (cur->next != NULL) {
		if (crl_match(cur->next, key, len)) {
			return 1;
		}
		cur = cur->next;
	}
	return 0;
}


void crl_hashmap_print(hcmap_t* map) {
	int i;
	hcnode_t* cur;
	printf("Hash map contents:\n");
	for (i = 0; i < map->num_buckets; i++) {
		printf("\tBucket %d:\n", i);
		cur = map->buckets[i];
		while (cur) {
			for (int i = 0; i < cur->len; i++) {
				putchar(cur->key[i]);
			}
			putchar('\n');
			cur = cur->next;
		}
	}
	return;
}

int crl_match(hcnode_t* check, char* key, int len) {
	if (len != check->len) {
		return 0;
	}
	for (int i = 0; i < len; i++) {
		if (check->key[i] != key[i]) {
			return 0;
		}
	}
	return 1;
}

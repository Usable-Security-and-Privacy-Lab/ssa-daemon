#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hashqueue.h"
#define STR_MATCH(s, n) (strcmp(s, n) == 0)

typedef struct hqnode {
	struct hqnode* next;
	char* key;
	void* value;
} hqnode_t;


/**
 * Creates an integer hash of the given string \p key and returns an index
 * suitable for insertion of an element into \p queue.
 * @param queue The queue to hash the given key into.
 * @param key A unique null-terminated string to be used as the identifier.
 */
static int hash(hqueue_t* queue, char* key) {
	int i;
	int hash_val = 0;
	
	for (i = 0; i < strlen(key); ++i)
		hash_val += key[i];

	return hash_val % queue->num_buckets;
}

/**
 * Creates a new string hashqueue that is \p num_buckets in size. Note that 
 * the hashqueue will be capable of storing much more than \p num_buckets;
 * it is simply the array size for the hashqueue.
 * @param num_buckets the size of the hashqueue.
 * @returns A new string hashqueue pointer, or NULL on failure.
 */
hqueue_t* hashqueue_create(int num_buckets) {
	hqueue_t* queue = (hqueue_t*)malloc(sizeof(hqueue_t));
	if (queue == NULL) {
		return NULL;
	}
	queue->buckets = (hqnode_t**)calloc(num_buckets, sizeof(hqnode_t*));
	if (queue->buckets == NULL) {
		free(queue);
		return NULL;
	}
	queue->num_buckets = num_buckets;
	return queue;
}


/**
 * Frees all entries from the given string hashqueue \p queue, and frees
 * the values of each entry using \p free_func.
 * @param queue The queue to free.
 * @param free_func The function used to free each value from the hashqueue.
 */
void hashqueue_deep_free(hqueue_t* queue, void (*free_func)(void*)) {
	hqnode_t* cur = NULL;
	hqnode_t* tmp = NULL;
	int i;
	if (queue == NULL) {
		return;
	}
	for (i = 0; i < queue->num_buckets; i++) {
		cur = queue->buckets[i];
		while (cur != NULL) {
			tmp = cur->next;
			if (free_func != NULL)
				free_func(cur->value);
			
            free(cur->key);
			free(cur);
			cur = tmp;
		}
	}
	free(queue->buckets);
	free(queue);
	return;
}

/**
 * Frees all entries from the given string hashqueue \p queue, but leaves the 
 * values of each entry alone.
 * @param queue The queue to be freed.
 */
void hashqueue_free(hqueue_t* queue) {
	hashqueue_deep_free(queue, NULL);
	return;
}


/**
 * Adds the given key:value pair to \p queue.
 * @param queue The queue to add a new element to.
 * @param key The null-terminated string used to lookup the value in \p queue.
 * @param value A pointer to a data structure to be stored in \p queue.
 * @returns 0 on success; 1 if the entry could not be found; or -1 on 
 * malloc failure.
 */
int hashqueue_push(hqueue_t* queue, char* key, void* value) {

    int index;
	hqnode_t* cur;
	hqnode_t* new_node;
    
    if (key == NULL)
        return 1;

    new_node = (hqnode_t*)malloc(sizeof(hqnode_t));
    if (new_node == NULL)
        return -1;

    new_node->key = key;
    new_node->value = value;
    new_node->next = NULL;

    index = hash(queue, key);

	cur = queue->buckets[index];
	if (cur == NULL) {
		queue->buckets[index] = new_node;
		queue->item_count++;
		return 0;
	}

    while (cur->next != NULL)
        cur = cur->next;

    cur->next = new_node;
	queue->item_count++;
	return 0;
}

/**
 * Deletes the entry associated with \p key from \p queue.
 * @param queue The queue to delete an entry from.
 * @param key A null-terminated string that identifies the entry to delete.
 * @returns 0 on success, or 1 if no entry exists for \p key.
 */
int hashqueue_pop(hqueue_t* queue, char* key) {

	int index;
	hqnode_t* cur;
	hqnode_t* tmp;
	index = hash(queue, key);

	cur = queue->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return 1;
	}

	if (STR_MATCH(cur->key,key)) {
		queue->buckets[index] = cur->next;
        free(cur->key);
		free(cur);
		queue->item_count--;
		return 0;
	}
	while (cur->next != NULL) {
        tmp = cur->next;

		if (STR_MATCH(tmp->key,key)) {
			cur->next = tmp->next;
            free(tmp->key);
			free(tmp);
			queue->item_count--;
			return 0;
		}
		cur = tmp;
	}
	/* Not found */
	return 1;
}


/**
 * Retrieves the value associated with \p key from \p queue.
 * @param queue The string hashqueue to retrieve a value from.
 * @param key The key associated with the value to retrieve.
 * @returns A pointer to the value associated with \p key, 
 * or NULL if no entry exists in the hashqueue for \p key.
 */
void* hashqueue_front(hqueue_t* queue, char* key) {
	int index;
	hqnode_t* cur;

	if (key == NULL) {
		return NULL;
	}

	index = hash(queue, key);
	cur = queue->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return NULL;
	}
	if (STR_MATCH(cur->key,key)) {
		return cur->value;
	}
	while (cur->next != NULL) {
		if (STR_MATCH(cur->next->key, key))
			return cur->next->value;
		
		cur = cur->next;
	}
	return NULL;
}


/**
 * Prints the entire contents of the hashqueue to stdout.
 * @param queue The queue to print.
 */
void hashqueue_print(hqueue_t* queue) {
	int i;
	hqnode_t* cur;
	printf("Hash queue contents:\n");
	for (i = 0; i < queue->num_buckets; i++) {
		printf("\tBucket %d:\n", i);
		cur = queue->buckets[i];
		while (cur) {
			printf("\t\tNode [key = \"%s\", value=%p]\n",
				cur->key, cur->value);
			cur = cur->next;
		}
	}
	return;
}


/**
 * In queues where `str_hashqueue_mult_add` has been used, this function may
 * be used to delete a specific instance of a node when several nodes exist
 * with the same key. It does so by iterating through each element containing 
 * \p key as its key and checking to see if the pointer \p value matches the 
 * element's value.
 * @param queue The queue to delete the given key:value pair from.
 * @param key A *non*-unique null-terminated string to identify the element.
 * @param value The specific value of the element to be deleted.
 * @returns 0 on success, or 1 if no element with the given key:value pair
 * could be found.
 */
int hashqueue_remove(hqueue_t* queue, char* key, void* value) {

	int index;
	hqnode_t* cur;
	hqnode_t* tmp;
	index = hash(queue, key);

	cur = queue->buckets[index];
	if (cur == NULL)
		return 1; /* Not found */

	if (STR_MATCH(cur->key,key) && cur->value == value) {
		queue->buckets[index] = cur->next;
        free(cur->key);
		free(cur);
		queue->item_count--;
		return 0;
	}
	while (cur->next != NULL) {
        tmp = cur->next;

		if (STR_MATCH(tmp->key,key) && cur->value == value) {
			cur->next = tmp->next;
            free(tmp->key);
			free(tmp);
			queue->item_count--;
			return 0;
		}
		cur = tmp;
	}

	/* Not found */
	return 1;
}
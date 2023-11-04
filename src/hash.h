#ifndef __HASH_H__
#define __HASH_H__

struct hash_st;
typedef struct hash_st hash_st;

#define HFLAG_EXTERN_KEY        0x1

typedef void (*hash_data_free_func_t)(void *data);
typedef unsigned int (*hash_key_func_t)(const void *key, int klen);
typedef int (*hash_keycmp_func_t)(const void *key1, int klen1, const void *key2, int klen2);

hash_st *xhash_create(unsigned nslot, hash_data_free_func_t del, hash_key_func_t keyf);
hash_st *xhash_create2(unsigned nslot, hash_data_free_func_t del, hash_key_func_t keyf,
                              hash_keycmp_func_t keycmp, int flag);

void xhash_insert(hash_st *ht, const void *key, int klen, void *val);
int xhash_search(hash_st *ht, const void *key, int klen, void **val);
int xhash_delete(hash_st *ht, const void *key, int len);
void xhash_clear(hash_st *ht);
void xhash_destroy(hash_st *ht);

typedef struct hash_itor_st {
	const void *key;
	void *val;
	unsigned int klen;
	char __private_data[0];
} hash_itor_st;

const hash_itor_st *xhash_first(hash_st *ht);
const hash_itor_st *xhash_next(hash_st *ht, const hash_itor_st *itor);

#define xhash_foreach(hash, iter)\
	for ((iter) = xhash_first(hash); (iter) != NULL; (iter) = xhash_next(hash, iter))

#define xhash_foreach_safe(hash, iter, next)\
	for ((iter) = xhash_first(hash), (next) = ((iter)?xhash_next(hash, iter):NULL);\
		(iter) != NULL; (iter) = (next), (next) = ((next)?xhash_next(hash, next):NULL))

#endif

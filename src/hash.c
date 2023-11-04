#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "memory.h"
#include "list.h"

struct hash_node_st {
	hash_itor_st		d;
	unsigned int        __hval;
	struct hash_node_st *next;
	struct list_head	list;
	char 				__key[0];
};


struct hash_st {
	struct hash_node_st **slots;
	struct list_head	head;
	
	unsigned int        nslot;
	unsigned int        nelement;
	int                 flag;

	hash_data_free_func_t   hdel;
	hash_key_func_t         hkey;
	hash_keycmp_func_t      hkeycmp;
};

static unsigned int hash_default_key_time33(const void *key, int klen)
{
	unsigned int h = 5381;
	const unsigned char *p = (const unsigned char *)key;

	while (klen > 0) {
		h = h * 33 + (*p);
		p++;
		klen--;
	}

	return h;
}

static int hash_default_keycmp(const void *key1, int klen1, const void *key2, int klen2)
{
	return ((klen1 == klen2) && (memcmp(key1, key2, klen1) == 0) ? 0 : 1);
}

unsigned int xhash_count(hash_st *ht)
{
	return ht->nelement;
}

static inline unsigned int round_up_power2(unsigned int v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

hash_st *xhash_create2(unsigned nslot, hash_data_free_func_t del, hash_key_func_t keyf,
                              hash_keycmp_func_t keycmp, int flag)
{
	hash_st *h = zero_alloc(sizeof(hash_st));

	h->nslot = round_up_power2(nslot);
	h->slots = zero_alloc(h->nslot * sizeof(struct hash_node_st *));
	INIT_LIST_HEAD(&h->head);
	
	h->hdel = del;
	h->flag = flag;

	if (keyf) {
		h->hkey = keyf;
	} else {
		h->hkey = hash_default_key_time33;
	}

	if (keycmp) {
		h->hkeycmp = keycmp;
	} else {
		h->hkeycmp = hash_default_keycmp;
	}

	return h;
}

hash_st *xhash_create(unsigned nslot, hash_data_free_func_t del, hash_key_func_t keyf)
{
	return xhash_create2(nslot, del, keyf, hash_default_keycmp, 0);
}

void xhash_insert(hash_st *ht, const void *key, int len, void *val)
{
	unsigned int hval = ht->hkey(key, len);
	unsigned int idx = hval & (ht->nslot - 1);
	struct hash_node_st *tmp;
	struct hash_node_st *p = ht->slots[idx];

	while (p) {
		if (hval == p->__hval && ht->hkeycmp(p->d.key, p->d.klen, key, len) == 0) {
			if ((void *)ht->hdel) {
				ht->hdel(p->d.val);
			}

			p->d.val = val;

			if (ht->flag & HFLAG_EXTERN_KEY) {
				p->d.key = (void *)key;
				p->d.klen = len;
			}

			return;
		}

		p = p->next;
	}

	tmp = zero_alloc(sizeof(struct hash_node_st) + ((!(ht->flag & HFLAG_EXTERN_KEY)) * (len + 1)));

	tmp->d.klen = len;

	if (ht->flag & HFLAG_EXTERN_KEY) {
		tmp->d.key = (void *)key;
	} else {
		memcpy(tmp->__key, key, len);
		tmp->__key[len] = 0;
		tmp->d.key = tmp->__key;
	}

	tmp->d.val = val;
	tmp->__hval = hval;

	tmp->next = ht->slots[idx];
	ht->slots[idx] = tmp;
	list_add_tail(&tmp->list, &ht->head);
	
	ht->nelement++;
}

int xhash_search(hash_st *ht, const void *key, int len, void **val)
{
	unsigned int hval = ht->hkey(key, len);
	unsigned int idx = hval & (ht->nslot - 1);
	struct hash_node_st *p = ht->slots[idx];

	while (p) {
		if (hval == p->__hval && ht->hkeycmp(p->d.key, p->d.klen, key, len) == 0) {
			if (val) {
				*val = p->d.val;
			}

			return 0;
		}

		p = p->next;
	}

	return -1;
}

int xhash_delete(hash_st *ht, const void *key, int len)
{
	unsigned int hval = ht->hkey(key, len);
	unsigned int idx = hval & (ht->nslot - 1);
	struct hash_node_st *p = ht->slots[idx];
	struct hash_node_st *last = NULL;

	while (p) {
		if (hval == p->__hval && ht->hkeycmp(p->d.key, p->d.klen, key, len) == 0) {
			if (last) {
				last->next = p->next;
			} else {
				ht->slots[idx] = p->next;
			}
			
			list_del(&p->list);
			ht->nelement--;

			if ((void *)ht->hdel) {
				ht->hdel(p->d.val);
			}

			free(p);
			return 0;
		}

		last = p;
		p = p->next;
	}

	return -1;
}

void xhash_clear(hash_st *ht)
{
	struct hash_node_st *t, *n;

	if (!ht)
		return;

	list_for_each_entry_safe(t, n, &ht->head, list) {
		if ((void *)ht->hdel) {
			ht->hdel(t->d.val);
		}

		free(t);
	}

	memset(ht->slots, 0, ht->nslot * sizeof(void *));
	ht->nelement = 0;
	INIT_LIST_HEAD(&ht->head);
}

void xhash_destroy(hash_st *ht)
{
	if (!ht)
		return;

	xhash_clear(ht);

	free(ht->slots);
	free(ht);
}

const hash_itor_st *xhash_first(hash_st *ht)
{
	if (list_empty(&ht->head))
		return NULL;
	
	return (const hash_itor_st *)list_first_entry(&ht->head, struct hash_node_st, list);
}

const hash_itor_st *xhash_next(hash_st *ht, const hash_itor_st *itor)
{
	const struct hash_node_st *p = (const struct hash_node_st *)itor;
	if (p->list.next == &ht->head)
		return NULL;
	
	return (const hash_itor_st *)list_entry(p->list.next, struct hash_node_st, list);
}

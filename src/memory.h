#ifndef __MEMORY_H__
#define __MEMORY_H__

#include <stdlib.h>

#define CHECK_PTR_DIE(ptr)		do {			\
	if (!(ptr)) {								\
		fprintf(stderr, "out of memory\n");		\
		abort();								\
	}											\
} while(0)

static inline void *alloc_die(size_t sz)
{
	void *p = malloc(sz);
	CHECK_PTR_DIE(p);
	return p;
}

static inline void *zero_alloc(size_t sz)
{
	void *p = calloc(1, sz);
	CHECK_PTR_DIE(p);
	return p;
}

static inline char *strdup_die(const char *s)
{
	char *p = strdup(s);
	CHECK_PTR_DIE(p);
	return p;
}

static inline void *realloc_die(void *ptr, size_t newsz)
{
	void *p = realloc(ptr, newsz);
	CHECK_PTR_DIE(p);
	return p;
}


#endif

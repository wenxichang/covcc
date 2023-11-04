#ifndef __COV_READER_H__
#define __COV_READER_H__

#include <stdint.h>

struct cov_node {
	char *file;
	unsigned long counter;
	int type;
	int lineno;
	int colno;
};

struct stat_node {
	uint32_t br_total;
	uint32_t br_hit;
	uint32_t ln_total;
	uint32_t ln_hit;
};

#endif

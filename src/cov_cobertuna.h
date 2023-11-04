#ifndef __COV_COVERTUNA_H__
#define __COV_COVERTUNA_H__

#include "hash.h"
#include "cov_reader.h"

int cov_cob_generate(hash_st *h, const char *xml);
hash_st *cov_cob_stat(hash_st *h, struct stat_node *all);

#endif

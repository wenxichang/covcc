#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#include "cov_reader.h"
#include "cov_cobertuna.h"
#include "memory.h"

hash_st *cov_cob_stat(hash_st *h, struct stat_node *all)
{
	hash_st *fh = xhash_create(8192, (hash_data_free_func_t)free, NULL);

	if (all)
		memset(all, 0, sizeof(*all));

	const hash_itor_st *itor;
	for (itor = xhash_first(h); itor; itor = xhash_next(h, itor)) {
		struct cov_node *n = itor->val;

		struct stat_node *sn;
		if (xhash_search(fh, n->file, strlen(n->file), (void **)&sn) != 0) {
			sn = zero_alloc(sizeof(struct stat_node));
			xhash_insert(fh, n->file, strlen(n->file), sn);
		}

		if (n->type == 'B') {
			sn->br_total++;
			sn->br_hit += !!(n->counter);
	
			if (all) {
				all->br_total++;
				all->br_hit += !!(n->counter);
			}
		} else if (n->type == 'L') {
			sn->ln_total++;
			sn->ln_hit += !!(n->counter);

			if (all) {
				all->ln_total++;
				all->ln_hit += !!(n->counter);
			}
		} else {
			assert(0);
		}
	}

	return fh;
}

static int line_cmp(const void *a, const void *b)
{
	const struct cov_node *na = *(const struct cov_node **)a;
	const struct cov_node *nb = *(const struct cov_node **)b;

	if (na->lineno != nb->lineno)
		return na->lineno - nb->lineno;
	
	return na->colno - nb->colno;
}

static int collect_file_cov(hash_st *h, const char *file, int lfile, struct cov_node **nodes, int sz)
{
	const hash_itor_st *itor;
	int cnt = 0;

	for (itor = xhash_first(h); itor; itor = xhash_next(h, itor)) {
		struct cov_node *n = itor->val;

		if (strlen(n->file) == lfile && memcmp(file, n->file, lfile) == 0) {
			if (cnt < sz) {
				nodes[cnt++] = n;
			} else {
				break;
			}
		}
	}

	qsort(nodes, cnt, sizeof(void *), line_cmp);
	return cnt;
}

static const char *escape_class(const char *key, int klen, char *buf, int sz)
{
	int i;
	for (i = 0; i < klen && i < sz - 1; ++i) {
		if (isalnum(key[i])) {
			buf[i] = key[i];
		} else {
			buf[i] = '_';
		}
	}
	buf[i] = 0;
	return buf;
}

int cov_cob_generate(hash_st *h, const char *xml)
{
	FILE *fp = fopen(xml, "w");
	if (!fp) {
		fprintf(stderr, "Can not open %s for output: %s\n", xml, strerror(errno));
		return 1;
	}

	struct stat_node all;
	hash_st *fh = cov_cob_stat(h, &all);

	fprintf(fp, "<?xml version='1.0' encoding='UTF-8'?>\n");
	fprintf(fp, "<!DOCTYPE coverage SYSTEM 'http://cobertura.sourceforge.net/xml/coverage-04.dtd'>\n");
	fprintf(fp, "<coverage line-rate=\"%f\" branch-rate=\"%f\" lines-covered=\"%u\" lines-valid=\"%u\" "
				"branches-covered=\"%u\" branches-valid=\"%u\" complexity=\"0.0\" timestamp=\"%lu\" version=\"covcc 1.0\">",
				(float)all.ln_hit / (float)all.ln_total, (float)all.br_hit / (float)all.br_total, all.ln_hit, all.ln_total,
				all.br_hit, all.br_total, (unsigned long)time(NULL));

	fprintf(fp, "  <packages>\n");

	const hash_itor_st *itor;
	char buf[128];
	for (itor = xhash_first(fh); itor; itor = xhash_next(fh, itor)) {
		struct stat_node *sn = itor->val;

		fprintf(fp, "    <package name=\"%.*s\" line-rate=\"%f\" branch-rate=\"%f\" complexity=\"0.0\">\n",
					itor->klen, (const char *)itor->key, (float)sn->ln_hit / (float)sn->ln_total,
					(float)sn->br_hit / (float)sn->br_total);
		fprintf(fp, "      <classes>\n");
		fprintf(fp, "        <class name=\"%s\" filename=\"%.*s\" line-rate=\"%f\" branch-rate=\"%f\" complexity=\"0.0\">\n",
					escape_class((const char *)itor->key, itor->klen, buf, sizeof(buf)),
					itor->klen, (const char *)itor->key, (float)sn->ln_hit / (float)sn->ln_total,
					(float)sn->br_hit / (float)sn->br_total);

		fprintf(fp, "          <lines>\n");
		struct cov_node *nodes[65536];
		int nnode = collect_file_cov(h, itor->key, itor->klen, nodes, 65536);
		int i;
		for (i = 0; i < nnode; ++i) {
			struct cov_node *n = nodes[i];
			if (n->type == 'L') {
				fprintf(fp, "            <line number=\"%d\" hits=\"%lu\" branch=\"false\"/>\n", n->lineno, n->counter);
			} else if (n->type == 'B') {
				fprintf(fp, "            <line number=\"%d\" hits=\"%lu\" branch=\"true\"/>\n", n->lineno, n->counter);
			}
		}

		fprintf(fp, "          </lines>\n");
		fprintf(fp, "        </class>\n");
		fprintf(fp, "      </classes>\n");
		fprintf(fp, "    </package>\n");
	}
	fprintf(fp, "  </packages>\n");
	fprintf(fp, "</coverage>\n");

	xhash_destroy(fh);
	fclose(fp);
	return 0;
}
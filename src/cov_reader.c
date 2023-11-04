#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>
#include <stdint.h>

#include "hash.h"
#include "memory.h"
#include "cov_kcore.h"
#include "cov_cobertuna.h"
#include "cov_reader.h"

static int usage(void)
{
	printf("Usage: cov_reader [-m module] [-o output] [-h] [-i input ...] [src-files...] [-a]\n"
			"  options:\n"
			"   -m <module>   dump specified module's coverage data, default: all modules\n"
			"   -o <output>   specify output file, default: /dev/null\n"
			"   -i <input>    coverage dump file input, for merging or generating reports\n"
			"   -a            print coverage summary\n"
			"   -l            generate line coverage(default:yes)\n"
			"   -b            generate branch coverage(default:no)\n"
			"   src-files...  generate report for c source\n"
			"   --xml <file>  generate cobertura xml report\n"
			"   -h            show this message\n");
	return 1;
}

#define MAX_DUMP_FILE	100
#define GEN_LINE_COV	0x1
#define GEN_BRANCH_COV	0x2

static int hex_to_num(int x)
{
	if (x >= '0' && x <= '9') return x - '0';
	else if (x >= 'a' && x <= 'f') return x - 'a' + 0xa;
	else if (x >= 'A' && x <= 'F') return x - 'A' + 0xa;
	return 0;
}

static void unescape_name(char *name)
{
	char *in = name;
	char *out = name;

	for (; *in; ++in) {
		if (*in == '_') {
			++in;
			if (*in == '_') {
				*out++ = '_';
			} else if (isxdigit(*in) && isxdigit(*(in + 1))) {
				int c = (hex_to_num(*in) << 4) + (hex_to_num(*(in + 1)));
				*out++ = c;
				in += 1;
			} else {
				*out++ = *in;
			}
		} else {
			*out++ = *in;
		}
	}

	*out = 0;
}

static char *unpack_name(char *name, int *lineno, int *colno)
{
	/* %d_%d__%s */
	char *fname = strstr(name, "__");
	if (!fname)
		return NULL;

	fname += 2;

	unescape_name(fname);

	char *ln = strtok(name, "_");
	if (ln)
		*lineno = atoi(ln);
	
	if (colno) {
		char *cl = strtok(NULL, "_");
		if (cl)
			*colno = atoi(cl);
	}
	
	return fname;
}

static int dump_coverage(const char *mod, const char *output)
{
	int err = 1;
	FILE *out = stdout;
	if (output) {
		out = fopen(output, "w");
		if (!out) {
			fprintf(stderr, "Can not open %s for output: %s\n", output, strerror(errno));
			return 1;
		}
	}

	FILE *kallsyms = fopen("/proc/kallsyms", "r");
	if (!kallsyms) {
		fprintf(stderr, "Can not open /proc/kallsyms: %s\n", strerror(errno));
		goto close_out;
	}

	struct kcore_access *acc = kcore_access_create("/proc/kcore");
	if (!acc)
		goto close_ksyms;

	char line[1024];
	while (fgets(line, sizeof(line), kallsyms)) {
		char *addr = strtok(line, " \t\r\n");
		if (!addr)
			continue;
		
		char *attr = strtok(NULL, " \t\r\n");
		if (!attr)
			continue;
		
		char *name = strtok(NULL, " \t\r\n");
		if (!name)
			continue;

		if (mod) {
			char *module = strtok(NULL, " \t\r\n");
			if (!module || strcmp(mod, module) != 0)
				continue;
		}
	
		unsigned long offset = strtoul(addr, NULL, 16);

		if (strncmp(name, "__cov_cnt_", 10) == 0) {
			unsigned long val;
			int res;
			if ((res = kcore_access_read(acc, offset, &val, sizeof(val)))) {
				fprintf(stderr, "kcore read error: %s\n", strerror(-res));
				goto release_kcore_access;
			}

			int lineno = 0, colno = 0;
			char *fname = unpack_name(name + 10, &lineno, &colno);
			if (fname) {
				fprintf(out, "B:%s:%d:%d:%lu\n", fname, lineno, colno, val);
			}
		} else if (strncmp(name, "__cov_line_", 11) == 0) {
			unsigned long ptr, val;
			int res;
			if ((res = kcore_access_read(acc, offset, &ptr, sizeof(ptr))) ||
				(res = kcore_access_read(acc, ptr, &val, sizeof(val)))) {
				fprintf(stderr, "kcore read error: %s\n", strerror(-res));
				goto release_kcore_access;
			}

			int lineno = 0;
			char *fname = unpack_name(name + 11, &lineno, NULL);
			if (fname) {
				fprintf(out, "L:%s:%d:0:%lu\n", fname, lineno, val);
			}
		}
	}

	err = 0;

release_kcore_access:
	kcore_access_destroy(acc);
close_ksyms:
	fclose(kallsyms);
close_out:
	if (out != stdout) {
		fclose(out);
	}
	return err;
}

static void cov_node_destroy(struct cov_node *n)
{
	if (!n)
		return;
	
	free(n->file);
	free(n);
}

static unsigned int cov_node_key(const void *key, int len__)
{
	const struct cov_node *k = key;
	unsigned int h = ((k->type * 0x2137) ^ (k->lineno * 0x458123) ^ (k->colno * 0x3423421)) + 5381;
	const unsigned char *p = (const unsigned char *)k->file;
	int klen = strlen((const char *)p);

	while (klen > 0) {
		h = h * 33 + (*p);
		p++;
		klen--;
	}

	return h;
}

static int cov_node_cmp(const void *key1, int klen1, const void *key2, int klen2)
{
	const struct cov_node *k1 = key1, *k2 = key2;
	return (k1->type == k2->type && k1->lineno == k2->lineno && 
			k1->colno == k2->colno && strcmp(k1->file, k2->file) == 0) ? 0 : 1;
}

static int load_coverage(hash_st *h, const char *file)
{
	FILE *fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "Can not load coverage file %s: %s\n", file, strerror(errno));
		return 1;
	}

	char line[1024];
	while (fgets(line, sizeof(line), fp)) {
		char *t = strtok(line, ":\r\n");
		char *f = strtok(NULL, ":\r\n");
		char *ln = strtok(NULL, ":\r\n");
		char *cn = strtok(NULL, ":\r\n");
		char *co = strtok(NULL, ":\r\n");
		if (!t || !f || !ln || !cn || !co)
			break;
		
		if (strcmp(t, "L") != 0 && strcmp(t, "B") != 0)
			continue;

		struct cov_node *node = zero_alloc(sizeof(struct cov_node));
		node->file = strdup_die(f);
		node->type = *t;
		node->lineno = strtol(ln, NULL, 10);
		node->colno = strtol(cn, NULL, 10);
		node->counter = strtoull(co, NULL, 10);

		struct cov_node *nd;
		if (xhash_search(h, node, sizeof(struct cov_node), (void **)&nd) == 0) {
			nd->counter += node->counter;
			cov_node_destroy(node);
		} else {
			xhash_insert(h, node, sizeof(struct cov_node), node);
		}
	}

	fclose(fp);
	return 0;
}

static hash_st *create_coverage(void)
{
	return xhash_create2(8192, (hash_data_free_func_t)cov_node_destroy, cov_node_key, cov_node_cmp,
						 HFLAG_EXTERN_KEY);
}

static int merge_coverages(char *files[], int nr, const char *output)
{
	int i;

	hash_st *stat = create_coverage();
	for (i = 0; i < nr; ++i) {
		if (load_coverage(stat, files[i])) {
			xhash_destroy(stat);
			return 1;
		}
	}

	FILE *out = stdout;
	if (output) {
		out = fopen(output, "w");
		if (!out) {
			fprintf(stderr, "Can not merge coverage to %s: %s", output, strerror(errno));
			xhash_destroy(stat);
			return 1;
		}
	}

	const hash_itor_st *itor;
	for (itor = xhash_first(stat); itor; itor = xhash_next(stat, itor)) {
		struct cov_node *n = itor->val;
		fprintf(out, "%c:%s:%d:%d:%lu\n", n->type, n->file, n->lineno, n->colno, n->counter);
	}

	if (out != stdout) {
		fclose(out);
	}

	xhash_destroy(stat);
	return 0;
}

static int get_tab_cnt(const char *line)
{
	int cnt = 0;
	for (; *line && *line == '\t'; ++line)
		cnt++;

	return cnt;
}

static void gen_file_report(hash_st *h, const char *src, int rp_type)
{
	FILE *fp = fopen(src, "r");
	if (!fp) {
		fprintf(stderr, "Can not open source %s: %s\n", src, strerror(errno));
		return;
	}

	const char *fname = strrchr(src, '/');
	if (fname) {
		fname++;
	} else {
		fname = src;
	}

	char covname[PATH_MAX];
	snprintf(covname, sizeof(covname), "%s.cov", src);
	FILE *report = fopen(covname, "w");
	if (!report) {
		fprintf(stderr, "Can not open report %s: %s\n", covname, strerror(errno));
		fclose(fp);
		return;
	}

	char line[1024];
	int lineno = 1;
	while (fgets(line, sizeof(line), fp)) {
		int len = strlen(line);
		int i, j;
		int tab_cnt = get_tab_cnt(line);
		int first = 1;

		if (rp_type & GEN_BRANCH_COV) {
			for (i = 0; i < len + 1; ++i) {
				struct cov_node key = {
					.type = 'B',
					.file = (char *)fname,
					.lineno = lineno,
					.colno = i,
				};

				struct cov_node *val;
				if (xhash_search(h, &key, sizeof(struct cov_node), (void **)&val) == 0) {
					if (first) {
						fprintf(report, "\n");
						first = 0;
					}

					fprintf(report, "%10lu ", val->counter);
					for (j = 0; j < i + tab_cnt * 3 + 8; ++j)
						fputc('-', report);
					fprintf(report, "*\n");
				}
			}
		}

		if (rp_type & GEN_LINE_COV) {
			struct cov_node key = {
				.type = 'L',
				.file = (char *)fname,
				.lineno = lineno,
				.colno = 0,
			};
			struct cov_node *lval;
			if (xhash_search(h, &key, sizeof(struct cov_node), (void **)&lval) == 0) {
				fprintf(report, "%10lu ", lval->counter);
			} else {
				fprintf(report, "%10s ", "-");
			}
		}

		fprintf(report, "%8d: ", lineno);
		char *p = line;
		while (*p && *p == '\t') {
			fprintf(report, "    ");
			++p;
		}
		fprintf(report, "%s", p);

		lineno++;
	}

	fclose(report);
	fclose(fp);
}

static int anal_coverages(const char *file, char *sources[], int nr_src, int rp_type)
{
	hash_st *h = create_coverage();
	if (load_coverage(h, file)) {
		xhash_destroy(h);
		return 1;
	}

	int i;
	for (i = 0; i < nr_src; ++i) {
		gen_file_report(h, sources[i], rp_type);
	}

	xhash_destroy(h);
	return 0;
}

static int generate_xml(const char *file, const char *xml)
{
	hash_st *h = create_coverage();
	int res = 1;

	if (load_coverage(h, file))
		goto end;

	if (cov_cob_generate(h, xml))
		goto end;

	res = 0;
end:
	xhash_destroy(h);
	return res;
}

static int show_summary(const char *file)
{
	hash_st *h = create_coverage();
	if (load_coverage(h, file)) {
		xhash_destroy(h);
		return 1;
	}

	struct stat_node all;
	hash_st *fh = cov_cob_stat(h, &all);
	const hash_itor_st *itor;

	printf("Line\tBranch\tFile\n");
	for (itor = xhash_first(fh); itor; itor = xhash_next(fh, itor)) {
		struct stat_node *n = itor->val;
		float br_rate = (float)(n->br_hit * 100) / (float)n->br_total;
		float ln_rate = (float)(n->ln_hit * 100) / (float)n->ln_total;
		printf("%.2f%%\t%.2f%%\t%.*s\n", ln_rate, br_rate, itor->klen, (const char *)itor->key);
	}

	printf("\nTotal:\n");
	float all_br_rate = (float)(all.br_hit * 100) / (float)all.br_total;
	float all_ln_rate = (float)(all.ln_hit * 100) / (float)all.ln_total;
	printf("%.2f%%\t%.2f%%\n", all_ln_rate, all_br_rate);

	xhash_destroy(fh);
	xhash_destroy(h);
	return 0;
}

int main(int argc, char **argv)
{
	int i;
	char expect_mod[128];
	const char *mod = NULL;
	const char *output = NULL;
	char *dump_files[MAX_DUMP_FILE];
	int nr_dump_file = 0;
	char *anal_files[MAX_DUMP_FILE];
	int nr_anal_file = 0;
	int print_summary = 0;
	char tmp[PATH_MAX];
	int exit_code = 0;
	int rp_type = 0;
	const char *xmlfile = NULL;

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-m") == 0) {
			if (++i >= argc)
				return usage();
			snprintf(expect_mod, sizeof(expect_mod), "[%s]", argv[i]);
			mod = expect_mod;
		} else if (strcmp(argv[i], "-o") == 0) {
			if (++i >= argc)
				return usage();
			output = argv[i];
		} else if (strcmp(argv[i], "-i") == 0) {
			if (++i >= argc)
				return usage();
			if (nr_dump_file >= MAX_DUMP_FILE) {
				fprintf(stderr, "Too many dump file for input\n");
				return 1;
			}
			dump_files[nr_dump_file++] = argv[i];
		} else if (strcmp(argv[i], "-h") == 0) {
			return usage();
		} else if (strcmp(argv[i], "-a") == 0) {
			print_summary = 1;
		} else if (strcmp(argv[i], "-l") == 0) {
			rp_type |= GEN_LINE_COV;
		} else if (strcmp(argv[i], "-b") == 0) {
			rp_type |= GEN_BRANCH_COV;
		} else if (strcmp(argv[i], "--xml") == 0) {
			if (++i >= argc)
				return usage();
			xmlfile = argv[i];
		} else {
			if (nr_anal_file >= MAX_DUMP_FILE) {
				fprintf(stderr, "Too many source file for reporting\n");
				return 1;
			}
			anal_files[nr_anal_file++] = argv[i];
		}
	}

	if (!rp_type)
		rp_type = GEN_LINE_COV;

	if (!output) {
		snprintf(tmp, sizeof(tmp), "/tmp/cov_rd_%d_%ld", getpid(), time(NULL));
		output = tmp;
	}

	/* generate or merge coverage data */
	if (nr_dump_file) {
		exit_code = merge_coverages(dump_files, nr_dump_file, output);
	} else {
		exit_code = dump_coverage(mod, output);
	}

	if (exit_code)
		goto end;

	if (print_summary)
		show_summary(output);

	/* generate xml report */
	if (xmlfile) {
		exit_code = generate_xml(output, xmlfile);
		if (exit_code)
			goto end;
	}

	/* analyze source files */
	if (nr_anal_file)
		exit_code = anal_coverages(output, anal_files, nr_anal_file, rp_type);

end:
	if (output == tmp) {
		unlink(output);
	}

	return exit_code;
}
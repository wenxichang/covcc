#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>

#include "memory.h"

#include "ac_lexer.h"
#include "ac_token.h"

typedef enum {
	LEX_TYPE_FILE,
	LEX_TYPE_MEM,
} lex_type_t;

struct ac_lexer_st {
	lex_type_t type;
	union {
		struct {
			char *file;
			FILE *fp;
		} f;
		struct {
			const char *mem;
			uint32_t size;
			uint32_t curr;
		} m;
	};
	
	int cur_line;
	int cur_char;
	char *cur_file;
	
	char *buffer;
	int nr_buffer;
	int sz_buffer;

	int (*get_char)(struct ac_lexer_st *lex);
	void (*unget_char)(struct ac_lexer_st *lex, int c);
};

lex_str_st *lex_str_create(const char *buf, uint32_t len)
{
	lex_str_st *ret = alloc_die(sizeof(lex_str_st) + len + 1);
	
	memcpy(ret->data, buf, len);
	ret->data[len] = 0;
	ret->len = len;
	
	return ret;
}

static int file_lex_getc(ac_lexer_st *lex)
{
	int c = fgetc(lex->f.fp);
	if (c == '\n') {
		lex->cur_line++;
		lex->cur_char = 1;
	} else {
		lex->cur_char++;
	}
	return c;
}

static void file_lex_ungetc(ac_lexer_st *lex, int c)
{
	if (c == EOF)
		return;
	
	if (ungetc(c, lex->f.fp) != EOF) {
		if (c == '\n')
			lex->cur_line--;
		else
			lex->cur_char--;
	}
}

ac_lexer_st *ac_lexer_create(const char *file)
{
	ac_lexer_st *lex = zero_alloc(sizeof(ac_lexer_st));
	
	lex->type = LEX_TYPE_FILE;
	lex->f.file = realpath(file, NULL);
	if (!lex->f.file) {
		free(lex);
		return NULL;
	}
	
	lex->f.fp = fopen(lex->f.file, "rb");
	if (!lex->f.fp) {
		free(lex);
		return NULL;
	}
	lex->cur_line = 1;
	lex->cur_char = 1;
	lex->cur_file = strdup_die(lex->f.file);

	lex->get_char = file_lex_getc;
	lex->unget_char = file_lex_ungetc;
	return lex;
}

static int mem_lex_getc(ac_lexer_st *lex)
{
	int c;
	if (lex->m.curr >= lex->m.size)
		return EOF;
	
	c = lex->m.mem[lex->m.curr];
	lex->m.curr++;
	
	if (c == '\n') {
		lex->cur_line++;
		lex->cur_char = 1;
	} else {
		lex->cur_char++;
	}
	return c;
}

static void mem_lex_ungetc(ac_lexer_st *lex, int c)
{
	if (c == EOF)
		return;
	
	if (lex->m.curr > 0)
		lex->m.curr--;
	
	if (c == '\n')
		lex->cur_line--;
	else
		lex->cur_char--;
}

ac_lexer_st *ac_lexer_mem_create(const char *txt, uint32_t size)
{
	ac_lexer_st *lex = zero_alloc(sizeof(ac_lexer_st));
	assert(txt);
	
	lex->type = LEX_TYPE_MEM;
	lex->m.mem = txt;
	lex->m.size = size;
	
	lex->cur_line = 1;
	lex->cur_char = 1;
	lex->cur_file = strdup_die("__memory__");
	
	lex->get_char = mem_lex_getc;
	lex->unget_char = mem_lex_ungetc;
	return lex;
}

void ac_lexer_destroy(ac_lexer_st *lex)
{
	if (!lex)
		return;
	
	if (lex->type == LEX_TYPE_FILE) {
		fclose(lex->f.fp);
		free(lex->f.file);
	}
	free(lex->cur_file);
	free(lex);
}

const char *ac_lexer_get_file(ac_lexer_st *lex)
{
	assert(lex->type == LEX_TYPE_FILE);
	return lex->f.file;
}

static inline int lex_getc(ac_lexer_st *lex)
{
	int c = lex->get_char(lex);
	if (c != EOF) {
		while (lex->nr_buffer + 2 >= lex->sz_buffer) {
			lex->sz_buffer = lex->sz_buffer ? lex->sz_buffer * 2 : 16;
			lex->buffer = realloc_die(lex->buffer, lex->sz_buffer);
		}

		lex->buffer[lex->nr_buffer++] = c;
		lex->buffer[lex->nr_buffer] = 0;
	}
	return c;
}

static inline void lex_unget(ac_lexer_st *lex, int c)
{
	if (c && c != EOF && lex->nr_buffer > 0) {
		lex->nr_buffer--;
		lex->buffer[lex->nr_buffer] = 0;
	}
	lex->unget_char(lex, c);
}

const char *ac_lexer_get_last_txt(ac_lexer_st *lex)
{
	return lex->buffer;
}

void ac_lexer_reset_last_txt(ac_lexer_st *lex)
{
	if (lex->nr_buffer) {
		lex->nr_buffer = 0;
		lex->buffer[0] = 0;
	}
}

static void update_line_info(ac_lexer_st *lex, char *line)
{
	char *p = strtok(line, " ");
	if (strcmp(p, "#") != 0)
		return;
	
	char *lineno = strtok(NULL, " ");
	if (!lineno)
		return;
	
	lex->cur_line = atoi(lineno);
	char *file = strtok(NULL, " ");
	if (!file)
		return;
	
	if (file[0] == '\"')
		file++;
	
	size_t sz = strlen(file);
	if (sz && file[sz - 1] == '\"')
		file[sz - 1] = 0;
	
	free(lex->cur_file);
	lex->cur_file = strdup_die(file);
}

struct keyword {
	const char *key;
	int val;
};

struct keyword s_keywords[] = {
	{ "typedef", TYPEDEF },
	{ "sizeof", SIZEOF },
	{ "enum", ENUM },
	{ "struct", STRUCT },
	{ "union", UNION },
	{ "if", IF },
	{ "else", ELSE },
	{ "while", WHILE },
	{ "do", DO },
	{ "for", FOR },
	{ "switch", SWITCH },
	{ "case", CASE },
	{ "default", DEFAULT },
	{ "break", BREAK },
	{ "continue", CONTINUE },
	{ "return", RETURN },
	{ "goto", GOTO },
	{ "asm", ASM_KEYWORD },
	{ "typeof", TYPEOF },
	{ "alignof", ALIGNOF },
	{ "__attribute__", ATTRIBUTE },
	{ "extern", EXTERN },
	{ "static", STATIC },
	{ "auto", AUTO },
	{ "register", REGISTER },
	{ "char", CHAR },
	{ "short", SHORT },
	{ "int", INT },
	{ "long", LONG },
	{ "signed", SIGNED },
	{ "unsigned", UNSIGNED },
	{ "float", FLOAT },
	{ "double", DOUBLE },
	{ "const", CONST },
	{ "volatile", VOLATILE },
	{ "void", VOID },
	{ "restrict", RESTRICT },
};

static int s_keywords_sorted;

const char *ac_lexer_tok_key(int tok)
{
	unsigned i;

	for (i = 0; i < sizeof(s_keywords) / sizeof(s_keywords[0]); ++i) {
		if (s_keywords[i].val == tok)
			return s_keywords[i].key;
	}

	return NULL;
}

static int kw_cmp(const void *a, const void *b)
{
	const struct keyword *ka = a;
	const struct keyword *kb = b;

	return strcmp(ka->key, kb->key);
}

static inline int lex_key(const char *key)
{	
	if (!s_keywords_sorted) {
		qsort(s_keywords, sizeof(s_keywords) / sizeof(struct keyword), sizeof(struct keyword), kw_cmp);
		s_keywords_sorted = 1;
	}
	
	int low = -1, high = sizeof(s_keywords) / sizeof(struct keyword);

	while (high - low > 1) {
		int mid = (int)(((unsigned int)(high + low)) >> 1);

		if (strcmp(s_keywords[mid].key, key) > 0) {
			high = mid;
		} else {
			low = mid;
		}
	}

	if (low >= 0 && strcmp(s_keywords[low].key, key) == 0) {
		return s_keywords[low].val;
	}

	return -1;
}

#define LOCATION_START(loc, lex) do { 		\
	(loc)->first_line = (lex)->cur_line;	\
	(loc)->first_column = (lex)->cur_char;	\
	(loc)->file = (lex)->cur_file;			\
	} while(0)
#define LOCATION_END(loc, lex) do {			\
	(loc)->last_line = (lex)->cur_line;		\
	(loc)->last_column = (lex)->cur_char;	\
	} while(0)

static int lex_getc1(ac_lexer_st *lex)
{
	int c = 0;

	while ((c = lex_getc(lex)) == ' ' || c == '\t' || c == '\n' || c == '\r');
	if (c == EOF)
		return 0;

	return c;
}

static void ac_lexer_error(ac_lexer_st *lex, int lineno, const char *msg)
{
	fprintf(stderr, "[%d]: %s\n", lineno, msg);
}

static int hex_to_num(int x)
{
	if (x >= '0' && x <= '9') return x - '0';
	else if (x >= 'a' && x <= 'f') return x - 'a' + 0xa;
	else if (x >= 'A' && x <= 'F') return x - 'A' + 0xa;
	return 0;
}

#define STR_INIT_SIZE	16

static lex_str_st *do_string(ac_lexer_st *lex)
{
	int c = lex_getc(lex);
	int endchar = c;
	lex_str_st *buf = zero_alloc(sizeof(lex_str_st) + STR_INIT_SIZE);
	uint32_t sz_buf = STR_INIT_SIZE;
	
	while (1) {
		if (buf->len >= sz_buf - 1) {
			sz_buf = sz_buf * 2;
			buf = realloc_die(buf, sizeof(lex_str_st) + sz_buf);
		}
		
		c = lex_getc(lex);

		if (c == EOF || c == 0) {
			ac_lexer_error(lex, lex->cur_line, "Unexpected EOF parsing string.");
			free(buf);
			return NULL;
		}
		if (c == '\\') {
			int n = lex_getc(lex);
			switch (n) {
			case 'b': buf->data[buf->len++] = '\b'; break;
			case 'f': buf->data[buf->len++] = '\f'; break;
			case 'n': buf->data[buf->len++] = '\n'; break;
			case 'r': buf->data[buf->len++] = '\r'; break;
			case 't': buf->data[buf->len++] = '\t'; break;
			case 'x': {
				int a = lex_getc(lex);
				int b = lex_getc(lex);
				if (!isxdigit(a) || !isxdigit(b)) {
					ac_lexer_error(lex, lex->cur_line, "Error parsing string.");
					free(buf);
					return NULL;
				}
				int hex = (hex_to_num(a) << 4) + (hex_to_num(b));
				buf->data[buf->len++] = hex;
				break;
			}
			case EOF: 
			case 0:
				ac_lexer_error(lex, lex->cur_line, "Unexpected EOF parsing string.");
				free(buf);
				return NULL;
			default: 
				buf->data[buf->len++] = n;
			}
		} else {
			buf->data[buf->len++] = c;
		}
		
		if (c == endchar) {
			buf->len--;
			break;
		}
	}

	buf->data[buf->len] = 0;
	return buf;
}

static double *do_number(ac_lexer_st *lex)
{
	char num[256];
	int wi = 0, xflag = 0, epos = -1;
	double *db;
	char *pend = NULL;

	while (wi < 250) {
		int c = lex_getc(lex);
		if (isdigit(c) || c == '.') {
			num[wi++] = c;
		} else if (xflag && isxdigit(c)) {
			num[wi++] = c;
		} else if ((c == 'x' || c == 'X') && wi == 1 && num[0] == '0') {
			xflag = 1;
			num[wi++] = c;
		} else if (!xflag && (c == 'E' || c == 'e')) {
			epos = wi;
			num[wi++] = c;
		} else if ((c == '+' || c == '-') && wi == epos + 1) {
			/* +- is right next to e */
			num[wi++] = c;
		} else {
			lex_unget(lex, c);
			break;
		}
	}
	num[wi] = 0;
	db = malloc(sizeof(double));
	*db = strtod(num, &pend);
	if (pend - num != wi) {
		/* some env not support strtod with hex digit, try strtol */
		*db = (double)strtol(num, &pend, 0);
	}
	return db;
}

#define LOOK_AHEAD(lex, expect, ret)	do {	\
	int d__ = lex_getc(lex);					\
	if (d__ == expect)							\
		return ret;								\
	lex_unget(lex, d__);						\
} while(0)

static int read_token(ac_lexer_st *lex, YYSTYPE *yylvalp, YYLTYPE *yyllocp)
{
	int c = lex_getc1(lex);
	int k;
	char buf[1024];
	uint32_t nbuf = 0;
	
	LOCATION_START(yyllocp, lex);
	switch (c) {
	case '0' ... '9': {
		lex_unget(lex, c);
		*yylvalp = do_number(lex);
		LOCATION_END(yyllocp, lex);
		return CONSTANT;
	}
	case '"':
	case '\'': {
		lex_str_st *str;
		
		lex_unget(lex, c);
		str = do_string(lex);
		if (!str)
			return EOF;
		
		LOCATION_END(yyllocp, lex);
		*yylvalp = str;
		return STRING_LITERAL;
	}
	case 'a' ... 'z':
	case 'A' ... 'Z':
	case '_': {
		lex_str_st *str;
		
		buf[nbuf++] = c;
		while (isalnum((c = lex_getc(lex))) || c == '_') {
			if (nbuf < sizeof(buf) - 1)
				buf[nbuf++] = c;
		}
		
		lex_unget(lex, c);
		buf[nbuf] = 0;
		LOCATION_END(yyllocp, lex);
		
		if ((k = lex_key(buf)) >= 0)
			return k;

		str = lex_str_create(buf, nbuf);
		*yylvalp = str;
		return IDENTIFIER;
	}
	case '#': {
		lex_str_st *str;

		buf[nbuf++] = c;
		while ((c = lex_getc(lex))) {
			if (c == '\r' || c == '\n')
				break;

			if (nbuf < sizeof(buf) - 1)
				buf[nbuf++] = c;
		}

		buf[nbuf] = 0;
		LOCATION_END(yyllocp, lex);

		str = lex_str_create(buf, nbuf);
		*yylvalp = str;

		update_line_info(lex, buf);
		return LINE_UPDATE;
	}
	default:
		break;
	}
	
	return c;
}

int ac_yylex(YYSTYPE *yylvalp, YYLTYPE *yyllocp, ac_lexer_st *lex)
{
	int ret;
	while ((ret = read_token(lex, yylvalp, yyllocp)) == LINE_UPDATE);

/*
	if (ret < 128 && ret > 0) ac_dbg_printf("%c	@ %d\n", ret, yyllocp->first_line);
	else ac_dbg_printf("%d		@ %d\n", ret, yyllocp->first_line);
*/

	return ret;
}

void ac_yyerror(YYLTYPE *yylloc, ac_lexer_st *lex, const char *fmt, ...)
{
	char msg[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	ac_lexer_error(lex, yylloc ? yylloc->first_line : 0, msg);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <assert.h>
#include <ctype.h>

#include "memory.h"
#include "list.h"

#include "ac_lexer.h"
#include "ac_token.h"

#define MAX_STACK	1000
#define MAX_LINE	65536

static jmp_buf par_env;

#define PARSE_EOF	1
#define PARSE_ERR	2

struct var_name {
	struct list_head list;
	char *name;
	char *file;						/* where counter var belong to */
	uint16_t *lines;				/* lines that counter var covered */
	int nr_line;
	int sz_line;
};

struct parser {
	ac_lexer_st *lex;
	YYSTYPE val;
	YYLTYPE loc;
	int last_tok;

	char stack[MAX_STACK];			/* ([{ symbol stack */
	int sp;

	int counter_sp;
	struct var_name *counter_stack[MAX_STACK];		/* current line counter var stack */

	char before_txt[256];
	char after_txt[256];

	FILE *output;
	struct list_head namehead;
};

static struct parser *parser_create(const char *file)
{
	struct parser *p = zero_alloc(sizeof(struct parser));
	p->lex = ac_lexer_create(file);
	assert(p->lex);
	INIT_LIST_HEAD(&p->namehead);
	return p;
}

static void parser_destroy(struct parser *p)
{
	if (!p)
		return;

	ac_lexer_destroy(p->lex);
	free(p->val);
	fclose(p->output);

	struct var_name *pos, *n;
	list_for_each_entry_safe(pos, n, &p->namehead, list) {
		free(pos->name);
		free(pos->file);
		free(pos->lines);
		free(pos);
	}

	free(p);
}

static int check_bra_match(int a, int b)
{
	switch (a) {
	case ')':
		return b != '(';
	case ']':
		return b != '[';
	case '}':
		return b != '{';
	}
	return 1;
}

static int parser_peek_token(struct parser *p)
{
	if (p->last_tok) {
		return p->last_tok;
	}

	free(p->val);
	p->val = NULL;
	p->last_tok = ac_yylex(&p->val, &p->loc, p->lex);
	return p->last_tok;
}

static int parser_read_token(struct parser *p)
{
	if (p->last_tok) {
		int t = p->last_tok;
		p->last_tok = 0;
		return t;
	} else {
		free(p->val);
		p->val = NULL;
		int tok = ac_yylex(&p->val, &p->loc, p->lex);
		if (tok <= 0) {
			longjmp(par_env, PARSE_EOF);
		}
		return tok;
	}
}

#define APPEND(s, l)	do {		\
	size_t __l = (l);				\
	if (cur + __l + 1 < sz) {		\
		memcpy(out + cur, s, __l);	\
		cur += __l;					\
	}								\
} while(0)

static const char *file_name(const char *path)
{
	const char *name = strrchr(path, '/');
	if (name)
		name++;
	else
		name = path;

	return name;
}

static char *name_escape(const char *fname, char *out, size_t sz)
{
	size_t cur = 0;
	const char *name = file_name(fname);

	for (; *name; ++name) {
		if (*name == '_') {
			APPEND("__", 2);
		} else if (isalnum(*name)) {
			APPEND(name, 1);
		} else {
			char tmp[10];
			snprintf(tmp, sizeof(tmp), "_%02x", *(const uint8_t *)name);
			APPEND(tmp, strlen(tmp));
		}
	}

	assert(cur < sz);
	out[cur] = 0;
	return out;
}

static void set_counter_top(struct parser *p, struct var_name *v)
{
	if (p->counter_sp > 0) {
		assert(p->counter_sp < MAX_STACK);
		p->counter_stack[p->counter_sp - 1] = v;
	}
}

static const char *parser_generate_cov_var(struct parser *p)
{
	struct var_name *v = zero_alloc(sizeof(struct var_name));
	char name_tmp[512];
	char buf[256];

	snprintf(name_tmp, sizeof(name_tmp), "__cov_cnt_%d_%d__%s", p->loc.first_line, p->loc.first_column, 
			name_escape(p->loc.file, buf, sizeof(buf)));

	v->name = strdup_die(name_tmp);
	v->file = strdup_die(file_name(p->loc.file));
	list_add_tail(&v->list, &p->namehead);

	set_counter_top(p, v);

	return v->name;
}

static int current_is_c_file(struct parser *p)
{
	size_t sz = strlen(p->loc.file);
	return strcmp(p->loc.file + sz - 2, ".c") == 0;
}

#define INSERT_BEFORE_NEXT(p, fmt, args...)		\
	snprintf((p)->before_txt, sizeof((p)->before_txt), fmt, ##args)

#define INSERT_AFTER_NEXT(p, fmt, args...)		\
	snprintf((p)->after_txt, sizeof((p)->after_txt), fmt, ##args)

#define INSERT_NOW(p, fmt, args...) \
	fprintf(p->output, fmt, ##args)

#define syntax_error(p, fmt, args...)	do {		\
	ac_yyerror(&(p)->loc, p->lex, fmt, ##args);		\
	longjmp(par_env, PARSE_ERR);					\
} while(0)

static int parser_next_token(struct parser *p)
{
	int tok = parser_read_token(p);

	const char *ttxt = ac_lexer_get_last_txt(p->lex);
	fprintf(p->output, "%s%s%s", p->before_txt, ttxt, p->after_txt);
	p->before_txt[0] = p->after_txt[0] = 0;
	ac_lexer_reset_last_txt(p->lex);

	if (tok == '(' || tok == '[' || tok == '{') {
		assert(p->sp < MAX_STACK);
		p->stack[p->sp++] = tok;
	} else if (tok == ')' || tok == ']' || tok == '}') {
		if (p->sp <= 0) {
			syntax_error(p, "Unmatched '%c'", tok);
		}

		p->sp--;
		if (check_bra_match(tok, p->stack[p->sp])) {
			syntax_error(p, "Unmatched '%c' with '%c'", tok, p->stack[p->sp]);
		}
	}

	return tok;
}

static void parse_till(struct parser *p, int tok, int sp_delta)
{
	int old_sp = p->sp;
	while (parser_next_token(p) != tok || p->sp != old_sp + sp_delta);
}

static int parser_do_one_stmt(struct parser *p, int insert_cov);
static void parser_do_block(struct parser *p, int insert_cov);

static void parser_do_if_stmt(struct parser *p)
{
	int tok = parser_next_token(p);
	assert(tok == IF);

	if (parser_next_token(p) != '(')
		syntax_error(p, "No '(' after if");

	parse_till(p, ')', -1);

	parser_do_one_stmt(p, 1);

	if (parser_peek_token(p) == ELSE) {
		parser_next_token(p);
		parser_do_one_stmt(p, 1);
	}
}

static void parser_do_for_stmt(struct parser *p)
{
	int tok = parser_next_token(p);
	assert(tok == FOR);

	if (parser_next_token(p) != '(')
		syntax_error(p, "No '(' after for");
	
	parse_till(p, ')', -1);

	parser_do_one_stmt(p, 1);
}

static void parser_do_switch_stmt(struct parser *p)
{
	int tok = parser_next_token(p);
	assert(tok == SWITCH);

	if (parser_next_token(p) != '(')
		syntax_error(p, "No '(' after for");
	
	parse_till(p, ')', -1);

	if (parser_next_token(p) != '{')
		syntax_error(p, "No '{' parsing switch block");

	while (1) {
		int tok = parser_peek_token(p);
		if (tok == '}') {
			parser_next_token(p);
			break;
		}

		if (tok == CASE || tok == DEFAULT) {
			parse_till(p, ':', 0);

			if (current_is_c_file(p))
				INSERT_NOW(p, "%s++;", parser_generate_cov_var(p));
		}

		parser_do_one_stmt(p, 0);
	}
}

static void parser_do_do_stmt(struct parser *p)
{
	int tok = parser_next_token(p);
	assert(tok == DO);

	parser_do_block(p, 1);

	if (parser_next_token(p) != WHILE)
		syntax_error(p, "No 'while' after block of do");
	
	parse_till(p, ';', 0);
}

static void parser_do_while_stmt(struct parser *p)
{
	int tok = parser_next_token(p);
	assert(tok == WHILE);

	if (parser_next_token(p) != '(')
		syntax_error(p, "No '(' after while");
	
	parse_till(p, ')', -1);

	parser_do_one_stmt(p, 1);
}

static int push_counter(struct parser *p)
{
	assert(p->counter_sp < MAX_STACK);

	p->counter_stack[p->counter_sp++] = NULL;
	return 1;
}

static void pop_counter(struct parser *p)
{
	assert(p->counter_sp > 0);
	p->counter_sp--;
	p->counter_stack[p->counter_sp] = NULL;
}

static int parser_do_one_stmt(struct parser *p, int insert_cov)
{
	int t = 0;
	int has_ins_brace = 0;
	int tok = parser_peek_token(p);
	int tok_line = p->loc.first_line;
	int pushed = 0;

	if (insert_cov && current_is_c_file(p)) {
		pushed = push_counter(p);
		if (tok == '{') {
			INSERT_AFTER_NEXT(p, "%s++;", parser_generate_cov_var(p));
		} else {
			has_ins_brace = 1;
			INSERT_BEFORE_NEXT(p, "{ %s++;", parser_generate_cov_var(p));
		}
	}

	if (tok != '{' && tok_line > 0 && tok_line < MAX_LINE && 
			p->counter_sp > 0 && p->counter_stack[p->counter_sp - 1]) {
		struct var_name *vn = p->counter_stack[p->counter_sp - 1];
		if (vn->nr_line >= vn->sz_line) {
			vn->sz_line = vn->sz_line ? vn->sz_line * 2 : 8;
			vn->lines = realloc_die(vn->lines, vn->sz_line * sizeof(uint16_t));
		}

		vn->lines[vn->nr_line++] = tok_line;
	}

	switch (tok) {
	case '{':
		parser_do_block(p, 0);
		break;
	case IF:
		t = 1;
		parser_do_if_stmt(p);
		break;
	case FOR:
		t = 1;
		parser_do_for_stmt(p);
		break;
	case SWITCH:
		t = 1;
		parser_do_switch_stmt(p);
		break;
	case DO:
		t = 1;
		parser_do_do_stmt(p);
		break;
	case WHILE:
		t = 1;
		parser_do_while_stmt(p);
		break;
	case IDENTIFIER:
		/* label: counter++; forced */
		parser_next_token(p);
		if (parser_peek_token(p) == ':') {
			parser_next_token(p);

			if (current_is_c_file(p)) {
				INSERT_NOW(p, "%s++;", parser_generate_cov_var(p));
			}

			parser_do_one_stmt(p, 0);
		} else {
			parse_till(p, ';', 0);
		}
		break;
	case RETURN:
	case BREAK:
	case CONTINUE:
	case GOTO:
		set_counter_top(p, NULL);		/* fall through */
	default:
		parse_till(p, ';', 0);
		break;
	}

	if (pushed) {
		pop_counter(p);
	}

	if (has_ins_brace) {
		INSERT_NOW(p, "}");
	}

	return t;
}

static void parser_do_block(struct parser *p, int insert_cov)
{
	int pushed = 0;

	if (parser_next_token(p) != '{')
		syntax_error(p, "No '{' parsing block");

	if (insert_cov && current_is_c_file(p)) {
		pushed = push_counter(p);
		INSERT_NOW(p, "%s++;", parser_generate_cov_var(p));
	}

	while (1) {
		int tok = parser_peek_token(p);
		if (tok == '}') {
			parser_next_token(p);

			if (pushed) {
				pop_counter(p);
			}

			break;
		}

		if (parser_do_one_stmt(p, 0) && current_is_c_file(p))
			INSERT_NOW(p, "%s++;", parser_generate_cov_var(p));
	}
}

static int parser_do_function(struct parser *p)
{
	if (parser_next_token(p) != IDENTIFIER)
		return 0;

	char function_name[256];
	lex_str_st *id = p->val;
	snprintf(function_name, sizeof(function_name), "%.*s", id->len, id->data);

	if (parser_peek_token(p) != '(')
		return 0;

	parse_till(p, ')', 0);

	if (parser_peek_token(p) != '{')
		return 0;

	/* dbg_print("found function %s\n", function_name); */
	parser_do_block(p, 1);
	return 0;
}

static void parse_file(struct parser *p)
{	
	while (1) {
		if (parser_do_function(p))
			break;
	}
}

int cov_inject(const char *file)
{
	FILE *output = tmpfile();
	if (!output) {
		perror("create tmp file");
		return 1;
	}

	struct parser *par = parser_create(file);
	if (!par) {
		perror("open file");
		fclose(output);
		return 1;
	}

	par->output = output;

	int err = 0;

	switch (setjmp(par_env)) {
	case 0:
		parse_file(par);
		break;
	case PARSE_EOF:
		break;
	case PARSE_ERR:
		err = 1;
		break;
	default:
		assert(0);
	}

	if (!err && par->lex) {
		ac_lexer_destroy(par->lex);
		par->lex = NULL;

		FILE *orig = fopen(file, "w");
		if (!orig) {
			perror("open origin");
			return 1;
		}

		/* make gcc ignore warning */
		fprintf(orig, "#pragma GCC diagnostic ignored \"-Wdeclaration-after-statement\"\n");

		/* write all definitions of vars */
		struct var_name *pos;
		char line_set[MAX_LINE] = { 0 };
		list_for_each_entry(pos, &par->namehead, list) {
			fprintf(orig, "unsigned long %s;\n", pos->name);
			int i;
			for (i = 0; i < pos->nr_line; ++i) {
				uint16_t lineno = pos->lines[i];
				if (line_set[lineno])
					continue;

				line_set[lineno] = 1;
				
				char tmp[128];
				fprintf(orig, "unsigned long *__cov_line_%u__%s = &%s;\n", lineno, 
					name_escape(pos->file, tmp, sizeof(tmp)), pos->name);
			}
		}

		rewind(output);
		char buf[4096];
		size_t n;
		while ((n = fread(buf, 1, sizeof(buf), output)) > 0)
			fwrite(buf, 1, n, orig);
		
		fclose(orig);
	}

	parser_destroy(par);
	return err;
}

#ifdef COV_INJECT_TOOL
int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		return 1;
	}

	return cov_inject(argv[1]);
}
#endif

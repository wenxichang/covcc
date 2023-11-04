#ifndef __AC_LEXER_H__
#define __AC_LEXER_H__

#include <stdint.h>

#include "ac_token.h"

struct ac_lexer_st;
typedef struct ac_lexer_st ac_lexer_st;

ac_lexer_st *ac_lexer_create(const char *file);
ac_lexer_st *ac_lexer_mem_create(const char *txt, uint32_t size);
void ac_lexer_destroy(ac_lexer_st *lex);
const char *ac_lexer_get_file(ac_lexer_st *lex);

const char *ac_lexer_tok_key(int tok);

const char *ac_lexer_get_last_txt(ac_lexer_st *lex);
void ac_lexer_reset_last_txt(ac_lexer_st *lex);

/* for ac_parser.y */

int ac_yylex(YYSTYPE *yylvalp, YYLTYPE *yyllocp, ac_lexer_st *lex);
void ac_yyerror(YYLTYPE *yylloc, ac_lexer_st *lex, const char *msg, ...);

typedef struct lex_str_st {
	uint32_t len;
	char data[0];
} lex_str_st;

lex_str_st *lex_str_create(const char *buf, uint32_t len);

#endif

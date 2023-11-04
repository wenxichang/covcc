#ifndef __AC_TOKEN_H__
#define __AC_TOKEN_H__

#include <stdint.h>

enum {
	IDENTIFIER = 256,
	CONSTANT,
	STRING_LITERAL,
	LINE_UPDATE,

	TYPEDEF,
	SIZEOF,

	ENUM,
	STRUCT,
	UNION,

	IF,
	ELSE,
	WHILE,
	DO,
	FOR,
	SWITCH,
	CASE,
	DEFAULT,
	BREAK,
	CONTINUE,
	RETURN,
	GOTO,

	ASM_KEYWORD,
	TYPEOF,
	ALIGNOF,
	ATTRIBUTE,

	EXTERN,
	STATIC,
	AUTO,
	REGISTER,

	CHAR,
	SHORT,
	INT,
	LONG,
	SIGNED,
	UNSIGNED,
	FLOAT,
	DOUBLE,
	CONST,
	VOLATILE,
	VOID,
	RESTRICT,
};

typedef void *YYSTYPE;
typedef struct {
	int first_line;
	int first_column;
	int last_line;
	int last_column;
	const char *file;
} YYLTYPE;

#endif

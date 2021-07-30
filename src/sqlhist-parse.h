#ifndef __SQLHIST_PARSE_H
#define __SQLHIST_PARSE_H

#include <stdarg.h>
#include <tracefs.h>

struct str_hash;
#define HASH_BITS 10

struct sql_table;

struct sqlhist_bison {
	const char		*buffer;
	size_t			buffer_size;
	size_t			buffer_idx;
	int			line_no;
	int			line_idx;
	struct sql_table	*table;
	char			*parse_error_str;
	struct str_hash         *str_hash[1 << HASH_BITS];
};

extern struct sqlhist_bison *sb;

#include "sqlhist.tab.h"

enum filter_type {
	FILTER_GROUP,
	FILTER_NOT_GROUP,
	FILTER_EQ,
	FILTER_NE,
	FILTER_LE,
	FILTER_LT,
	FILTER_GE,
	FILTER_GT,
	FILTER_BIN_AND,
	FILTER_STR_CMP,
	FILTER_AND,
	FILTER_OR,
};

enum compare_type {
	COMPARE_GROUP,
	COMPARE_ADD,
	COMPARE_SUB,
	COMPARE_MUL,
	COMPARE_DIV,
	COMPARE_BIN_AND,
	COMPARE_BIN_OR,
	COMPARE_AND,
	COMPARE_OR,
};

char * store_str(struct sqlhist_bison *sb, const char *str);

int table_start(struct sqlhist_bison *sb);

void *add_field(struct sqlhist_bison *sb, const char *field, const char *label);

int add_match(struct sqlhist_bison *sb, void *A, void *B);

int add_selection(struct sqlhist_bison *sb, void *item, const char *label);
int add_from(struct sqlhist_bison *sb, void *item);
int add_to(struct sqlhist_bison *sb, void *item);

extern void sql_parse_error(struct sqlhist_bison *sb, const char *text,
			    const char *fmt, va_list ap);

#endif

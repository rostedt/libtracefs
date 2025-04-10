#ifndef __SQLHIST_PARSE_H
#define __SQLHIST_PARSE_H

#include <stdarg.h>
#include <tracefs.h>

#include <tracefs-local.h>

struct str_hash;

struct sql_table;

struct sqlhist_bison {
	void			*scanner;
	const char		*buffer;
	size_t			buffer_size;
	size_t			buffer_idx;
	int			line_no;
	int			line_idx;
	struct sql_table	*table;
	char			*parse_error_str;
	struct str_hash         *str_hash[1 << HASH_BITS];
};

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

char *tfs_store_str(struct sqlhist_bison *sb, const char *str);

int tfs_table_start(struct sqlhist_bison *sb);

void *tfs_add_field(struct sqlhist_bison *sb, const char *field, const char *label);

void *tfs_add_filter(struct sqlhist_bison *sb, void *A, void *B, enum filter_type op);

int tfs_add_match(struct sqlhist_bison *sb, void *A, void *B);
void *tfs_add_compare(struct sqlhist_bison *sb, void *A, void *B, enum compare_type type);
int tfs_add_where(struct sqlhist_bison *sb, void *expr);

int tfs_add_selection(struct sqlhist_bison *sb, void *item, const char *label);
int tfs_add_from(struct sqlhist_bison *sb, void *item);
int tfs_add_to(struct sqlhist_bison *sb, void *item);
void *tfs_add_cast(struct sqlhist_bison *sb, void *field, const char *type);
void *tfs_add_cast_buckets(struct sqlhist_bison *sb, void *field, const char *type, int num);

void *tfs_add_string(struct sqlhist_bison *sb, const char *str);
void *tfs_add_number(struct sqlhist_bison *sb, long val);

extern void tfs_sql_parse_error(struct sqlhist_bison *sb, const char *text,
				const char *fmt, va_list ap);

#endif

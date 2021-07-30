// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2021 VMware Inc, Steven Rostedt <rostedt@goodmis.org>
 *
 * Updates:
 * Copyright (C) 2021, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <trace-seq.h>
#include <stdlib.h>
#include <errno.h>

#include "tracefs.h"
#include "tracefs-local.h"
#include "sqlhist-parse.h"

struct sqlhist_bison *sb;

extern int yylex_init(void* ptr_yy_globals);
extern int yylex_init_extra(struct sqlhist_bison *sb, void* ptr_yy_globals);
extern int yylex_destroy (void * yyscanner );

struct str_hash {
	struct str_hash		*next;
	char			*str;
};

enum alias_type {
	ALIAS_EVENT,
	ALIAS_FIELD,
};

#define for_each_field(expr, field, table) \
	for (expr = (table)->fields; expr; expr = (field)->next)

struct field {
	struct expr		*next;	/* private link list */
	const char		*system;
	const char		*event_name;
	struct tep_event	*event;
	const char		*raw;
	const char		*label;
	const char		*field;
};

struct filter {
	enum filter_type	type;
	struct expr		*lval;
	struct expr		*rval;
};

struct match {
	struct match		*next;
	struct expr		*lval;
	struct expr		*rval;
};

struct compare {
	enum compare_type	type;
	struct expr		*lval;
	struct expr		*rval;
	const char		*name;
};

enum expr_type
{
	EXPR_NUMBER,
	EXPR_STRING,
	EXPR_FIELD,
	EXPR_FILTER,
	EXPR_COMPARE,
};

struct expr {
	struct expr		*free_list;
	struct expr		*next;
	enum expr_type		type;
	union {
		struct field	field;
		struct filter	filter;
		struct compare	compare;
		const char	*string;
		long		number;
	};
};

struct sql_table {
	struct sqlhist_bison	*sb;
	const char		*name;
	struct expr		*exprs;
	struct expr		*fields;
	struct expr		*from;
	struct expr		*to;
	struct match		*matches;
	struct match		**next_match;
	struct expr		*selections;
	struct expr		**next_selection;
};

__hidden int my_yyinput(char *buf, int max)
{
	if (!sb || !sb->buffer)
		return -1;

	if (sb->buffer_idx + max > sb->buffer_size)
		max = sb->buffer_size - sb->buffer_idx;

	if (max)
		memcpy(buf, sb->buffer + sb->buffer_idx, max);

	sb->buffer_idx += max;

	return max;
}

__hidden void sql_parse_error(struct sqlhist_bison *sb, const char *text,
			      const char *fmt, va_list ap)
{
	const char *buffer = sb->buffer;
	struct trace_seq s;
	int line = sb->line_no;
	int idx = sb->line_idx - strlen(text);
	int i;

	if (!buffer)
		return;

	trace_seq_init(&s);
	if (!s.buffer) {
		fprintf(stderr, "Error allocating internal buffer\n");
		return;
	}

	for (i = 0; line && buffer[i]; i++) {
		if (buffer[i] == '\n')
			line--;
	}
	for (; buffer[i] && buffer[i] != '\n'; i++)
		trace_seq_putc(&s, buffer[i]);
	trace_seq_putc(&s, '\n');
	for (i = idx; i > 0; i--)
		trace_seq_putc(&s, ' ');
	trace_seq_puts(&s, "^\n");
	trace_seq_printf(&s, "ERROR: '%s'\n", text);
	trace_seq_vprintf(&s, fmt, ap);

	trace_seq_terminate(&s);

	sb->parse_error_str = strdup(s.buffer);
	trace_seq_destroy(&s);
}

static inline unsigned int quick_hash(const char *str)
{
	unsigned int val = 0;
	int len = strlen(str);

	for (; len >= 4; str += 4, len -= 4) {
		val += str[0];
		val += str[1] << 8;
		val += str[2] << 16;
		val += str[3] << 24;
	}
	for (; len > 0; str++, len--)
		val += str[0] << (len * 8);

        val *= 2654435761;

        return val & ((1 << HASH_BITS) - 1);
}


static struct str_hash *find_string(struct sqlhist_bison *sb, const char *str)
{
	unsigned int key = quick_hash(str);
	struct str_hash *hash = sb->str_hash[key];

	for (; hash; hash = hash->next) {
		if (!strcmp(hash->str, str))
			return hash;
	}
	return NULL;
}

/*
 * If @str is found, then return the hash string.
 * This lets store_str() know to free str.
 */
static char **add_hash(struct sqlhist_bison *sb, const char *str)
{
	struct str_hash *hash;
	unsigned int key;

	if ((hash = find_string(sb, str))) {
		return &hash->str;
	}

	hash = malloc(sizeof(*hash));
	if (!hash)
		return NULL;
	key = quick_hash(str);
	hash->next = sb->str_hash[key];
	sb->str_hash[key] = hash;
	hash->str = NULL;
	return &hash->str;
}

__hidden char *store_str(struct sqlhist_bison *sb, const char *str)
{
	char **pstr = add_hash(sb, str);

	if (!pstr)
		return NULL;

	if (!(*pstr))
		*pstr = strdup(str);

	return *pstr;
}

__hidden int add_selection(struct sqlhist_bison *sb, void *select,
			   const char *name)
{
	struct sql_table *table = sb->table;
	struct expr *expr = select;

	switch (expr->type) {
	case EXPR_FIELD:
		break;
	case EXPR_COMPARE:
		if (!name)
			return -1;
		expr->compare.name = name;
		break;
	case EXPR_NUMBER:
	case EXPR_STRING:
	case EXPR_FILTER:
	default:
		return -1;
	}

	if (expr->next)
		return -1;

	*table->next_selection = expr;
	table->next_selection = &expr->next;

	return 0;
}

static struct expr *find_field(struct sqlhist_bison *sb,
				const char *raw, const char *label)
{
	struct field *field;
	struct expr *expr;

	for_each_field(expr, field, sb->table) {
		field = &expr->field;

		if (!strcmp(field->raw, raw)) {
			if (label && !field->label)
				field->label = label;
			return expr;
		}

		if (label && !strcmp(field->raw, label)) {
			if (!field->label) {
				field->label = label;
				field->raw = raw;
			}
			return expr;
		}

		if (!field->label)
			continue;

		if (!strcmp(field->label, raw))
			return expr;

		if (label && !strcmp(field->label, label))
			return expr;
	}
	return NULL;
}

static void *create_expr(enum expr_type type, struct expr **expr_p)
{
	struct expr *expr;

	expr = calloc(1, sizeof(*expr));
	if (!expr)
		return NULL;

	if (expr_p)
		*expr_p = expr;

	expr->free_list = sb->table->exprs;
	sb->table->exprs = expr;

	expr->type = type;

	switch (type) {
	case EXPR_FIELD:	return &expr->field;
	case EXPR_COMPARE:	return &expr->compare;
	case EXPR_NUMBER:	return &expr->number;
	case EXPR_STRING:	return &expr->string;
	case EXPR_FILTER:	return &expr->filter;
	}

	return NULL;
}

#define __create_expr(var, type, ENUM, expr)			\
	do {							\
		var = (type *)create_expr(EXPR_##ENUM, expr);	\
	} while(0)

#define create_field(var, expr)				\
	__create_expr(var, struct field, FIELD, expr)

#define create_compare(var, expr)				\
	__create_expr(var, struct compare, COMPARE, expr)

__hidden void *add_field(struct sqlhist_bison *sb,
			 const char *field_name, const char *label)
{
	struct sql_table *table = sb->table;
	struct expr *expr;
	struct field *field;

	expr = find_field(sb, field_name, label);
	if (expr)
		return expr;

	create_field(field, &expr);

	field->next = table->fields;
	table->fields = expr;

	field->raw = field_name;
	field->label = label;

	return expr;
}

__hidden int add_match(struct sqlhist_bison *sb, void *A, void *B)
{
	struct sql_table *table = sb->table;
	struct match *match;

	match = calloc(1, sizeof(*match));
	if (!match)
		return -1;

	match->lval = A;
	match->rval = B;

	*table->next_match = match;
	table->next_match = &match->next;

	return 0;
}
__hidden void *add_compare(struct sqlhist_bison *sb,
			   void *A, void *B, enum compare_type type)
{
	struct compare *compare;
	struct expr *expr;

	create_compare(compare, &expr);

	compare = &expr->compare;
	compare->lval = A;
	compare->rval = B;
	compare->type = type;

	return expr;
}

__hidden int add_from(struct sqlhist_bison *sb, void *item)
{
	struct expr *expr = item;

	if (expr->type != EXPR_FIELD)
		return -1;

	sb->table->from = expr;

	return 0;
}

__hidden int add_to(struct sqlhist_bison *sb, void *item)
{
	struct expr *expr = item;

	if (expr->type != EXPR_FIELD)
		return -1;

	sb->table->to = expr;

	return 0;
}

__hidden int table_start(struct sqlhist_bison *sb)
{
	struct sql_table *table;

	table = calloc(1, sizeof(*table));
	if (!table)
		return -ENOMEM;

	table->sb = sb;
	sb->table = table;

	table->next_match = &table->matches;
	table->next_selection = &table->selections;

	return 0;
}

static int test_event_exists(struct tep_handle *tep,
			     struct expr *expr, struct tep_event **pevent)
{
	struct field *field = &expr->field;
	const char *system = field->system;
	const char *event = field->event_name;

	if (!field->event)
		field->event = tep_find_event_by_name(tep, system, event);
	if (pevent)
		*pevent = field->event;
	return field->event != NULL ? 0 : -1;
}

static int test_field_exists(struct expr *expr)
{
	struct field *field = &expr->field;
	struct tep_format_field *tfield;
	char *field_name;
	const char *p;

	if (!field->event)
		return -1;

	/* The field could have a conversion */
	p = strchr(field->field, '.');
	if (p)
		field_name = strndup(field->field, p - field->field);
	else
		field_name = strdup(field->field);

	if (!field_name)
		return -1;

	if (!strcmp(field_name, TRACEFS_TIMESTAMP) ||
	    !strcmp(field->field, TRACEFS_TIMESTAMP_USECS))
		tfield = (void *)1L;
	else
		tfield = tep_find_any_field(field->event, field_name);
	free(field_name);

	return tfield != NULL ? 0 : -1;
}

static int update_vars(struct tep_handle *tep,
		       struct sql_table *table,
		       struct expr *expr)
{
	struct sqlhist_bison *sb = table->sb;
	struct field *event_field = &expr->field;
	struct tep_event *event;
	struct field *field;
	const char *label;
	const char *raw = event_field->raw;
	const char *event_name;
	const char *system;
	const char *p;
	int label_len = 0, event_len, system_len;

	p = strchr(raw, '.');
	if (p) {
		char *str;

		str = strndup(raw, p - raw);
		if (!str)
			return -1;
		event_field->system = store_str(sb, str);
		free(str);
		if (!event_field->system)
			return -1;
		p++;
	} else {
		p = raw;
	}

	event_field->event_name = store_str(sb, p);
	if (!event_field->event_name)
		return -1;

	if (test_event_exists(tep, expr, &event))
		return -1;

	if (!event_field->system)
		event_field->system = store_str(sb, event->system);

	if (!event_field->system)
		return -1;

	label = event_field->label;
	if (label)
		label_len = strlen(label);

	system = event_field->system;
	system_len = strlen(system);

	event_name = event_field->event_name;
	event_len = strlen(event_name);

	for_each_field(expr, field, table) {
		int len;

		field = &expr->field;

		if (field->event)
			continue;

		raw = field->raw;

		/*
		 * The field could be:
		 *     system.event.field...
		 *     event.field...
		 *     label.field...
		 * We check label first.
		 */

		len = label_len;
		if (label && !strncmp(raw, label, len) &&
		    raw[len] == '.') {
			/* Label matches and takes precedence */
			goto found;
		}

		if (!strncmp(raw, system, system_len) &&
		    raw[system_len] == '.') {
			raw += system_len + 1;
			/* Check the event portion next */
		}

		len = event_len;
		if (strncmp(raw, event_name, len) ||
		    raw[len] != '.') {
			/* Does not match */
			continue;
		}
 found:
		field->system = system;
		field->event_name = event_name;
		field->event = event;
		field->field = raw + len + 1;

		if (!strcmp(field->field, "TIMESTAMP"))
			field->field = store_str(sb, TRACEFS_TIMESTAMP);
		if (!strcmp(field->field, "TIMESTAMP_USECS"))
			field->field = store_str(sb, TRACEFS_TIMESTAMP_USECS);
		if (test_field_exists(expr))
			return -1;
	}

	return 0;
}

static int test_match(struct sql_table *table, struct match *match)
{
	struct field *lval, *rval;
	struct field *to, *from;

	if (!match->lval || !match->rval)
		return -1;

	if (match->lval->type != EXPR_FIELD || match->rval->type != EXPR_FIELD)
		return -1;

	to = &table->to->field;
	from = &table->from->field;

	lval = &match->lval->field;
	rval = &match->rval->field;

	/*
	 * Note, strings are stored in the string store, so all
	 * duplicate strings are the same value, and we can use
	 * normal "==" and "!=" instead of strcmp().
	 *
	 * Either lval == to and rval == from
	 * or lval == from and rval == to.
	 */
	if ((lval->system != to->system) ||
	    (lval->event != to->event)) {
		if ((rval->system != to->system) ||
		    (rval->event != to->event) ||
		    (lval->system != from->system) ||
		    (lval->event != from->event))
			return -1;
	} else {
		if ((rval->system != from->system) ||
		    (rval->event != from->event) ||
		    (lval->system != to->system) ||
		    (lval->event != to->event))
			return -1;
	}
	return 0;
}

static void assign_match(const char *system, const char *event,
			 struct match *match,
			 const char **start_match, const char **end_match)
{
	struct field *lval, *rval;

	lval = &match->lval->field;
	rval = &match->rval->field;

	if (lval->system == system &&
	    lval->event_name == event) {
		*start_match = lval->field;
		*end_match = rval->field;
	} else {
		*start_match = rval->field;
		*end_match = lval->field;
	}
}

static int build_compare(struct tracefs_synth *synth,
			 const char *system, const char *event,
			 struct compare *compare)
{
	const char *start_field;
	const char *end_field;
	struct field *lval, *rval;
	enum tracefs_synth_calc calc;
	int ret;

	lval = &compare->lval->field;
	rval = &compare->rval->field;

	if (lval->system == system &&
	    lval->event_name == event) {
		start_field = lval->field;
		end_field = rval->field;
		calc = TRACEFS_SYNTH_DELTA_START;
	} else {
		start_field = rval->field;
		end_field = lval->field;
		calc = TRACEFS_SYNTH_DELTA_END;
	}

	if (compare->type == COMPARE_ADD)
		calc = TRACEFS_SYNTH_ADD;

	ret = tracefs_synth_add_compare_field(synth, start_field,
					      end_field, calc,
					      compare->name);
	return ret;
}

static struct tracefs_synth *build_synth(struct tep_handle *tep,
					 const char *name,
					 struct sql_table *table)
{
	struct tracefs_synth *synth;
	struct field *field;
	struct match *match;
	struct expr *expr;
	const char *start_system;
	const char *start_event;
	const char *end_system;
	const char *end_event;
	const char *start_match;
	const char *end_match;
	int ret;

	if (!table->to || !table->from)
		return NULL;

	ret = update_vars(tep, table, table->to);
	if (ret < 0)
		return NULL;

	ret = update_vars(tep, table, table->from);
	if (ret < 0)
		return NULL;

	match = table->matches;
	if (!match)
		return NULL;

	ret = test_match(table, match);
	if (ret < 0)
		return NULL;

	start_system = table->from->field.system;
	start_event = table->from->field.event_name;

	end_system = table->to->field.system;
	end_event = table->to->field.event_name;

	assign_match(start_system, start_event, match,
		     &start_match, &end_match);

	synth = tracefs_synth_init(tep, name, start_system,
				   start_event, end_system, end_event,
				   start_match, end_match, NULL);
	if (!synth)
		return NULL;

	for (match = match->next; match; match = match->next) {
		ret = test_match(table, match);
		if (ret < 0)
			goto free;

		assign_match(start_system, start_event, match,
			     &start_match, &end_match);

		ret = tracefs_synth_add_match_field(synth,
						    start_match,
						    end_match, NULL);
		if (ret < 0)
			goto free;
	}

	for (expr = table->selections; expr; expr = expr->next) {
		if (expr->type == EXPR_FIELD) {
			field = &expr->field;
			if (field->system == start_system &&
			    field->event_name == start_event) {
				ret = tracefs_synth_add_start_field(synth,
						field->field, field->label);
			} else {
				ret = tracefs_synth_add_end_field(synth,
						field->field, field->label);
			}
			if (ret < 0)
				goto free;
			continue;
		}

		if (expr->type != EXPR_COMPARE)
			goto free;

		ret = build_compare(synth, start_system, end_system,
				    &expr->compare);
		if (ret < 0)
			goto free;
	}

	return synth;
 free:
	tracefs_synth_free(synth);
	return NULL;
}

static void free_sql_table(struct sql_table *table)
{
	struct match *match;
	struct expr *expr;

	if (!table)
		return;

	while ((expr = table->exprs)) {
		table->exprs = expr->next;
		free(expr);
	}

	while ((match = table->matches)) {
		table->matches = match->next;
		free(match);
	}

	free(table);
}

static void free_str_hash(struct str_hash **hash)
{
	struct str_hash *item;
	int i;

	for (i = 0; i < 1 << HASH_BITS; i++) {
		while ((item = hash[i])) {
			hash[i] = item->next;
			free(item->str);
			free(item);
		}
	}
}

static void free_sb(struct sqlhist_bison *sb)
{
	free_sql_table(sb->table);
	free_str_hash(sb->str_hash);
	free(sb->parse_error_str);
}

struct tracefs_synth *tracefs_sql(struct tep_handle *tep, const char *name,
				  const char *sql_buffer, char **err)
{
	struct sqlhist_bison local_sb;
	struct tracefs_synth *synth = NULL;
	int ret;

	if (!tep || !sql_buffer) {
		errno = EINVAL;
		return NULL;
	}

	memset(&local_sb, 0, sizeof(local_sb));

	local_sb.buffer = sql_buffer;
	local_sb.buffer_size = strlen(sql_buffer);
	local_sb.buffer_idx = 0;

	sb = &local_sb;
	ret = yyparse();

	if (ret)
		goto free;

	synth = build_synth(tep, name, sb->table);

 free:
	if (!synth) {
		if (sb->parse_error_str && err) {
			*err = sb->parse_error_str;
			sb->parse_error_str = NULL;
		}
	}
	free_sb(sb);
	return synth;
}

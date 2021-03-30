// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * Updates:
 * Copyright (C) 2021, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <regex.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include "tracefs.h"
#include "tracefs-local.h"

#define TRACE_CTRL	"tracing_on"
#define TRACE_FILTER	"set_ftrace_filter"

static const char * const options_map[] = {
	"unknown",
	"annotate",
	"bin",
	"blk_cgname",
	"blk_cgroup",
	"blk_classic",
	"block",
	"context-info",
	"disable_on_free",
	"display-graph",
	"event-fork",
	"funcgraph-abstime",
	"funcgraph-cpu",
	"funcgraph-duration",
	"funcgraph-irqs",
	"funcgraph-overhead",
	"funcgraph-overrun",
	"funcgraph-proc",
	"funcgraph-tail",
	"func_stack_trace",
	"function-fork",
	"function-trace",
	"graph-time",
	"hex",
	"irq-info",
	"latency-format",
	"markers",
	"overwrite",
	"pause-on-trace",
	"printk-msg-only",
	"print-parent",
	"raw",
	"record-cmd",
	"record-tgid",
	"sleep-time",
	"stacktrace",
	"sym-addr",
	"sym-offset",
	"sym-userobj",
	"trace_printk",
	"userstacktrace",
	"verbose" };

static int trace_on_off(int fd, bool on)
{
	const char *val = on ? "1" : "0";
	int ret;

	ret = write(fd, val, 1);
	if (ret == 1)
		return 0;

	return -1;
}

static int trace_on_off_file(struct tracefs_instance *instance, bool on)
{
	int ret;
	int fd;

	fd = tracefs_instance_file_open(instance, TRACE_CTRL, O_WRONLY);
	if (fd < 0)
		return -1;
	ret = trace_on_off(fd, on);
	close(fd);

	return ret;
}

/**
 * tracefs_trace_is_on - Check if writing traces to the ring buffer is enabled
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns -1 in case of an error, 0 if tracing is disable or 1 if tracing
 * is enabled.
 */
int tracefs_trace_is_on(struct tracefs_instance *instance)
{
	long long res;

	if (tracefs_instance_file_read_number(instance, TRACE_CTRL, &res) == 0)
		return (int)res;

	return -1;
}

/**
 * tracefs_trace_on - Enable writing traces to the ring buffer of the given instance
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns -1 in case of an error or 0 otherwise
 */
int tracefs_trace_on(struct tracefs_instance *instance)
{
	return trace_on_off_file(instance, true);
}

/**
 * tracefs_trace_off - Disable writing traces to the ring buffer of the given instance
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns -1 in case of an error or 0 otherwise
 */
int tracefs_trace_off(struct tracefs_instance *instance)
{
	return trace_on_off_file(instance, false);
}

/**
 * tracefs_trace_on_fd - Enable writing traces to the ring buffer
 * @fd: File descriptor to ftrace tracing_on file, previously opened
 *	with tracefs_trace_on_get_fd()
 *
 * Returns -1 in case of an error or 0 otherwise
 */
int tracefs_trace_on_fd(int fd)
{
	if (fd < 0)
		return -1;
	return trace_on_off(fd, true);
}

/**
 * tracefs_trace_off_fd - Disable writing traces to the ring buffer
 * @fd: File descriptor to ftrace tracing_on file, previously opened
 *	with tracefs_trace_on_get_fd()
 *
 * Returns -1 in case of an error or 0 otherwise
 */
int tracefs_trace_off_fd(int fd)
{
	if (fd < 0)
		return -1;
	return trace_on_off(fd, false);
}

/**
 * tracefs_option_name - Get trace option name from id
 * @id: trace option id
 *
 * Returns string with option name, or "unknown" in case of not known option id.
 * The returned string must *not* be freed.
 */
const char *tracefs_option_name(enum tracefs_option_id id)
{
	/* Make sure options map contains all the options */
	BUILD_BUG_ON(ARRAY_SIZE(options_map) != TRACEFS_OPTION_MAX);

	if (id < TRACEFS_OPTION_MAX)
		return options_map[id];

	return options_map[0];
}

/**
 * tracefs_option_id - Get trace option ID from name
 * @name: trace option name
 *
 * Returns trace option ID or TRACEFS_OPTION_INVALID in case of an error or
 * unknown option name.
 */
enum tracefs_option_id tracefs_option_id(char *name)
{
	int i;

	if (!name)
		return TRACEFS_OPTION_INVALID;

	for (i = 0; i < TRACEFS_OPTION_MAX; i++) {
		if (strlen(name) == strlen(options_map[i]) &&
		    !strcmp(options_map[i], name))
			return i;
	}

	return TRACEFS_OPTION_INVALID;
}

static struct tracefs_options_mask *trace_get_options(struct tracefs_instance *instance,
						      bool enabled)
{
	struct tracefs_options_mask *bitmask;
	enum tracefs_option_id id;
	char file[PATH_MAX];
	struct dirent *dent;
	char *dname = NULL;
	DIR *dir = NULL;
	long long val;

	bitmask = calloc(1, sizeof(struct tracefs_options_mask));
	if (!bitmask)
		return NULL;
	dname = tracefs_instance_get_file(instance, "options");
	if (!dname)
		goto error;
	dir = opendir(dname);
	if (!dir)
		goto error;

	while ((dent = readdir(dir))) {
		if (*dent->d_name == '.')
			continue;
		if (enabled) {
			snprintf(file, PATH_MAX, "options/%s", dent->d_name);
			if (tracefs_instance_file_read_number(instance, file, &val) != 0 ||
			    val != 1)
				continue;
		}
		id = tracefs_option_id(dent->d_name);
		if (id != TRACEFS_OPTION_INVALID)
			tracefs_option_set(bitmask, id);
	}
	closedir(dir);
	tracefs_put_tracing_file(dname);

	return bitmask;

error:
	if (dir)
		closedir(dir);
	tracefs_put_tracing_file(dname);
	free(bitmask);
	return NULL;
}

/**
 * tracefs_options_get_supported - Get all supported trace options in given instance
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns allocated bitmask structure with all trace options, supported in given
 * instance, or NULL in case of an error. The returned structure must be freed with free()
 */
struct tracefs_options_mask *tracefs_options_get_supported(struct tracefs_instance *instance)
{
	return trace_get_options(instance, false);
}

/**
 * tracefs_options_get_enabled - Get all currently enabled trace options in given instance
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns allocated bitmask structure with all trace options, enabled in given
 * instance, or NULL in case of an error. The returned structure must be freed with free()
 */
struct tracefs_options_mask *tracefs_options_get_enabled(struct tracefs_instance *instance)
{
	return trace_get_options(instance, true);
}

static int trace_config_option(struct tracefs_instance *instance,
			       enum tracefs_option_id id, bool set)
{
	char *set_str = set ? "1" : "0";
	char file[PATH_MAX];
	const char *name;

	name = tracefs_option_name(id);
	if (!name)
		return -1;

	snprintf(file, PATH_MAX, "options/%s", name);
	if (strlen(set_str) != tracefs_instance_file_write(instance, file, set_str))
		return -1;
	return 0;
}

/**
 * tracefs_option_enable - Enable trace option
 * @instance: ftrace instance, can be NULL for the top instance
 * @id: trace option id
 *
 * Returns -1 in case of an error or 0 otherwise
 */
int tracefs_option_enable(struct tracefs_instance *instance, enum tracefs_option_id id)
{
	return trace_config_option(instance, id, true);
}

/**
 * tracefs_option_diasble - Disable trace option
 * @instance: ftrace instance, can be NULL for the top instance
 * @id: trace option id
 *
 * Returns -1 in case of an error or 0 otherwise
 */
int tracefs_option_diasble(struct tracefs_instance *instance, enum tracefs_option_id id)
{
	return trace_config_option(instance, id, false);
}

/**
 * tracefs_option_is_supported - Check if an option is supported
 * @instance: ftrace instance, can be NULL for the top instance
 * @id: trace option id
 *
 * Returns true if an option with given id is supported by the system, false if
 * it is not supported.
 */
bool tracefs_option_is_supported(struct tracefs_instance *instance, enum tracefs_option_id id)
{
	const char *name = tracefs_option_name(id);
	char file[PATH_MAX];

	if (!name)
		return false;
	snprintf(file, PATH_MAX, "options/%s", name);
	return tracefs_file_exists(instance, file);
}

/**
 * tracefs_option_is_enabled - Check if an option is enabled in given instance
 * @instance: ftrace instance, can be NULL for the top instance
 * @id: trace option id
 *
 * Returns true if an option with given id is enabled in the given instance,
 * false if it is not enabled.
 */
bool tracefs_option_is_enabled(struct tracefs_instance *instance, enum tracefs_option_id id)
{
	const char *name = tracefs_option_name(id);
	char file[PATH_MAX];
	long long res;

	if (!name)
		return false;
	snprintf(file, PATH_MAX, "options/%s", name);
	if (!tracefs_instance_file_read_number(instance, file, &res) && res)
		return true;

	return false;
}

/**
 * tracefs_option_is_set - Check if given option is set in the bitmask
 * @options: Options bitmask
 * @id: trace option id
 *
 * Returns true if an option with given id is set in the bitmask,
 * false if it is not set.
 */
bool tracefs_option_is_set(struct tracefs_options_mask options, enum tracefs_option_id id)
{
	if (id > TRACEFS_OPTION_INVALID)
		return options.mask & (1ULL << (id - 1));
	return false;
}

/**
 * tracefs_option_set - Set option in options bitmask
 * @options: Pointer to a bitmask with options
 * @id: trace option id
 */
void tracefs_option_set(struct tracefs_options_mask *options, enum tracefs_option_id id)
{
	if (options && id > TRACEFS_OPTION_INVALID)
		options->mask |= (1ULL << (id - 1));
}

/**
 * tracefs_option_clear - Clear option from options bitmask
 * @options: Pointer to a bitmask with options
 * @id: trace option id
 */
void tracefs_option_clear(struct tracefs_options_mask *options, enum tracefs_option_id id)
{
	if (options && id > TRACEFS_OPTION_INVALID)
		options->mask &= ~(1ULL << (id - 1));
}

static void add_errors(const char ***errs, const char *filter, int ret)
{
	const char **e;

	if (!errs)
		return;

	/* Negative is passed in */
	ret = -ret;
	e = *errs;

	/* If this previously failed to allocate stop processing */
	if (!e && ret)
		return;

	/* Add 2, one for the new entry, and one for NULL */
	e = realloc(e, sizeof(*e) * (ret + 2));
	if (!e) {
		free(*errs);
		*errs = NULL;
		return;
	}
	e[ret] = filter;
	e[ret + 1] = NULL;
	*errs = e;
}

struct func_filter {
	const char		*filter;
	regex_t			re;
	bool			set;
};

/*
 * Convert a glob into a regular expression.
 */
static char *make_regex(const char *glob)
{
	char *str;
	int cnt = 0;
	int i, j;

	for (i = 0; glob[i]; i++) {
		if (glob[i] == '*'|| glob[i] == '.')
			cnt++;
	}

	/* '^' + ('*'->'.*' or '.' -> '\.') + '$' + '\0' */
	str = malloc(i + cnt + 3);
	if (!str)
		return NULL;

	str[0] = '^';
	for (i = 0, j = 1; glob[i]; i++, j++) {
		if (glob[i] == '*')
			str[j++] = '.';
		/* Dots can be part of a function name */
		if (glob[i] == '.')
			str[j++] = '\\';
		str[j] = glob[i];
	}
	str[j++] = '$';
	str[j] = '\0';
	return str;
}

static bool match(const char *str, struct func_filter *func_filter)
{
	return regexec(&func_filter->re, str, 0, NULL, 0) == 0;
}

/*
 * Return 0 on success, -1 error writing, 1 on other errors.
 */
static int write_filter(int fd, const char *filter, const char *module)
{
	char *each_str = NULL;
	int write_size;
	int size;

	if (module)
		write_size = asprintf(&each_str, "%s:mod:%s ", filter, module);
	else
		write_size = asprintf(&each_str, "%s ", filter);

	if (write_size < 0)
		return 1;

	size = write(fd, each_str, write_size);
	free(each_str);

	/* compare written bytes*/
	if (size < write_size)
		return -1;

	return 0;
}

static int check_available_filters(struct func_filter *func_filters,
				   const char *module, const char ***errs)
{
	char *line = NULL;
	size_t size = 0;
	char *path;
	FILE *fp;
	int ret = 1;
	int mlen;
	int i;

	path = tracefs_get_tracing_file("available_filter_functions");
	if (!path)
		return 1;

	fp = fopen(path, "r");
	tracefs_put_tracing_file(path);

	if (!fp)
		return 1;

	if (module)
		mlen = strlen(module);

	while (getline(&line, &size, fp) >= 0) {
		char *saveptr = NULL;
		char *tok, *mtok;
		int len = strlen(line);

		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		tok = strtok_r(line, " ", &saveptr);
		if (!tok)
			goto next;
		if (module) {
			mtok = strtok_r(NULL, " ", &saveptr);
			if (!mtok)
				goto next;
			if ((strncmp(mtok + 1, module, mlen) != 0) ||
			    (mtok[mlen + 1] != ']'))
				goto next;
		}
		for (i = 0; func_filters[i].filter; i++) {
			if (match(tok, &func_filters[i]))
				func_filters[i].set = true;
		}
	next:
		free(line);
		line = NULL;
		len = 0;
	}
	fclose(fp);

	ret = 0;
	for (i = 0; func_filters[i].filter; i++) {
		if (!func_filters[i].set)
			add_errors(errs, func_filters[i].filter, ret--);
	}

	return ret;
}

static int controlled_write(int fd, const char **filters,
			    const char *module, const char ***errs)
{
	int ret = 0;
	int i;

	for (i = 0; filters[i]; i++) {
		int r;

		r = write_filter(fd, filters[i], module);
		if (r < 0) {
			add_errors(errs, filters[i], ret--);
		} else if (r > 0) {
			/* Not filter error */
			if (errs) {
				free(*errs);
				*errs = NULL;
			}
			return 1;
		}
	}
	return ret;
}

static int init_func_filter(struct func_filter *func_filter, const char *filter)
{
	char *str;
	int ret;

	str = make_regex(filter);
	if (!str)
		return -1;

	ret = regcomp(&func_filter->re, str, REG_ICASE|REG_NOSUB);
	free(str);

	if (ret < 0)
		return -1;

	func_filter->filter = filter;
	return 0;
}

static void free_func_filters(struct func_filter *func_filters)
{
	int i;

	if (!func_filters)
		return;

	for (i = 0; func_filters[i].filter; i++) {
		regfree(&func_filters[i].re);
	}
}

static struct func_filter *make_func_filters(const char **filters)
{
	struct func_filter *func_filters = NULL;
	int i;

	for (i = 0; filters[i]; i++)
		;

	if (!i)
		return NULL;

	func_filters = calloc(i + 1, sizeof(*func_filters));
	if (!func_filters)
		return NULL;

	for (i = 0; filters[i]; i++) {
		if (init_func_filter(&func_filters[i], filters[i]) < 0)
			goto out_err;
	}
	return func_filters;
 out_err:
	free_func_filters(func_filters);
	return NULL;
}

/**
 * tracefs_function_filter - write to set_ftrace_filter file to trace
 * particular functions
 * @instance: ftrace instance, can be NULL for top tracing instance
 * @filters: An array of function names ending with a NULL pointer
 * @module: Module to be traced
 * @reset: set to true to reset the file before applying the filter
 * @errs: A pointer to array of constant strings that will be allocated
 * on negative return of this function, pointing to the filters that
 * failed.May be NULL, in which case this field will be ignored.
 *
 * The @filters is an array of strings, where each string will be used
 * to set a function or functions to be traced.
 *
 * If @reset is true, then all functions in the filter are cleared
 * before adding functions from @filters. Otherwise, the functions set
 * by @filters will be appended to the filter file
 *
 * returns -x on filter errors (where x is number of failed filter
 * srtings) and if @errs is not NULL will be an allocated string array
 * pointing to the strings in @filters that failed and must be freed
 * with free().
 *
 * returns 1 on general errors not realted to setting the filter.
 * @errs is not set even if supplied.
 *
 * return 0 on success and @errs is not set.
 */
int tracefs_function_filter(struct tracefs_instance *instance, const char **filters,
			    const char *module, bool reset, const char ***errs)
{
	struct func_filter *func_filters;
	char *ftrace_filter_path;
	int flags;
	int ret;
	int fd;

	if (!filters)
		return 1;

	func_filters = make_func_filters(filters);
	if (!func_filters)
		return 1;

	/* Make sure errs is NULL to start with, realloc() depends on it. */
	if (errs)
		*errs = NULL;

	ret = check_available_filters(func_filters, module, errs);
	free_func_filters(func_filters);
	if (ret)
		return ret;

	ftrace_filter_path = tracefs_instance_get_file(instance, TRACE_FILTER);
	if (!ftrace_filter_path)
		return 1;

	flags = reset ? O_TRUNC : O_APPEND;

	fd = open(ftrace_filter_path, O_WRONLY | flags);
	tracefs_put_tracing_file(ftrace_filter_path);
	if (fd < 0)
		return 1;

	ret = controlled_write(fd, filters, module, errs);

	close(fd);

	return ret;
}

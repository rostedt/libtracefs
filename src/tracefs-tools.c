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
#include <pthread.h>
#include <errno.h>

#include "tracefs.h"
#include "tracefs-local.h"

#define TRACE_CTRL		"tracing_on"
#define TRACE_FILTER		"set_ftrace_filter"
#define TRACE_FILTER_LIST	"available_filter_functions"

/* File descriptor for Top level set_ftrace_filter  */
static int ftrace_filter_fd = -1;
static pthread_mutex_t filter_lock = PTHREAD_MUTEX_INITIALIZER;

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

struct func_list {
	struct func_list	*next;
	unsigned int		start;
	unsigned int		end;
};

struct func_filter {
	const char		*filter;
	regex_t			re;
	bool			set;
	bool			is_regex;
};

static bool is_regex(const char *str)
{
	int i;

	for (i = 0; str[i]; i++) {
		switch (str[i]) {
		case 'a' ... 'z':
		case 'A'...'Z':
		case '_':
		case '0'...'9':
		case '*':
		case '.':
			/* Dots can be part of a function name */
		case '?':
			continue;
		default:
			return true;
		}
	}
	return false;
}

static char *update_regex(const char *reg)
{
	int len = strlen(reg);
	char *str;

	if (reg[0] == '^' && reg[len - 1] == '$')
		return strdup(reg);

	str = malloc(len + 3);
	if (reg[0] == '^') {
		strcpy(str, reg);
	} else {
		str[0] = '^';
		strcpy(str + 1, reg);
		len++; /* add ^ */
	}
	if (str[len - 1] != '$')
		str[len++]= '$';
	str[len] = '\0';
	return str;
}

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

static int add_func(struct func_list ***next_func_ptr, unsigned int index)
{
	struct func_list **next_func = *next_func_ptr;
	struct func_list *func_list = *next_func;

	if (!func_list) {
		func_list = calloc(1, sizeof(*func_list));
		if (!func_list)
			return -1;
		func_list->start = index;
		func_list->end = index;
		*next_func = func_list;
		return 0;
	}

	if (index == func_list->end + 1) {
		func_list->end = index;
		return 0;
	}
	*next_func_ptr = &func_list->next;
	return add_func(next_func_ptr, index);
}

static void free_func_list(struct func_list *func_list)
{
	struct func_list *f;

	while (func_list) {
		f = func_list;
		func_list = f->next;
		free(f);
	}
}

enum match_type {
	FILTER_CHECK	= (1 << 0),
	FILTER_WRITE	= (1 << 1),
	FILTER_FUTURE	= (1 << 2),
};

static int match_filters(int fd, struct func_filter *func_filter,
			 const char *module, struct func_list **func_list,
			 int flags)
{
	enum match_type type = flags & (FILTER_CHECK | FILTER_WRITE);
	bool future = flags & FILTER_FUTURE;
	bool mod_match = false;
	char *line = NULL;
	size_t size = 0;
	char *path;
	FILE *fp;
	int index = 0;
	int ret = 1;
	int mlen;

	path = tracefs_get_tracing_file(TRACE_FILTER_LIST);
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

		index++;

		if (module) {
			mtok = strtok_r(NULL, " ", &saveptr);
			if (!mtok)
				goto next;
			if ((strncmp(mtok + 1, module, mlen) != 0) ||
			    (mtok[mlen + 1] != ']'))
				goto next;
			if (future)
				mod_match = true;
		}
		switch (type) {
		case FILTER_CHECK:
			if (match(tok, func_filter)) {
				func_filter->set = true;
				ret = add_func(&func_list, index);
				if (ret)
					goto out;
			}
			break;
		case FILTER_WRITE:
			/* Writes only have one filter */
			if (match(tok, func_filter)) {
				ret = write_filter(fd, tok, module);
				if (ret)
					goto out;
			}
			break;
		default:
			/* Should never happen */
			ret = -1;
			goto out;

		}
	next:
		free(line);
		line = NULL;
		len = 0;
	}
 out:
	free(line);
	fclose(fp);

	/* If there was no matches and future was set, this is a success */
	if (future && !mod_match)
		ret = 0;

	return ret;
}

static int check_available_filters(struct func_filter *func_filter,
				   const char *module,
				   struct func_list **func_list,
				   bool future)
{
	int flags = FILTER_CHECK | (future ? FILTER_FUTURE : 0);

	return match_filters(-1, func_filter, module, func_list, flags);
}

static int set_regex_filter(int fd, struct func_filter *func_filter,
			    const char *module)
{
	return match_filters(fd, func_filter, module, NULL, FILTER_WRITE);
}

static int controlled_write(int fd, struct func_filter *func_filter,
			    const char *module)
{
	const char *filter = func_filter->filter;
	int ret;

	if (func_filter->is_regex)
		ret = set_regex_filter(fd, func_filter, module);
	else
		ret = write_filter(fd, filter, module);

	return ret;
}

static int init_func_filter(struct func_filter *func_filter, const char *filter)
{
	char *str;
	int ret;

	if (!(func_filter->is_regex = is_regex(filter)))
		str = make_regex(filter);
	else
		str = update_regex(filter);

	if (!str)
		return -1;

	ret = regcomp(&func_filter->re, str, REG_ICASE|REG_NOSUB);
	free(str);

	if (ret < 0)
		return -1;

	func_filter->filter = filter;
	return 0;
}

static int write_number(int fd, unsigned int start, unsigned int end)
{
	char buf[64];
	unsigned int i;
	int n, ret;

	for (i = start; i <= end; i++) {
		n = snprintf(buf, 64, "%d ", i);
		ret = write(fd, buf, n);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 * This will try to write the first number, if that fails, it
 * will assume that it is not supported and return 1.
 * If the first write succeeds, but a following write fails, then
 * the kernel does support this, but something else went wrong,
 * in this case, return -1.
 */
static int write_func_list(int fd, struct func_list *list)
{
	int ret;

	if (!list)
		return 0;

	ret = write_number(fd, list->start, list->end);
	if (ret)
		return 1; // try a different way
	list = list->next;
	while (list) {
		ret = write_number(fd, list->start, list->end);
		if (ret)
			return -1;
		list = list->next;
	}
	return 0;
}

/**
 * tracefs_function_filter - filter the functions that are traced
 * @instance: ftrace instance, can be NULL for top tracing instance.
 * @filter: The filter to filter what functions are to be traced
 * @module: Module to be traced or NULL if all functions are to be examined.
 * @flags: flags on modifying the filter file
 *
 * @filter may be a full function name, a glob, or a regex. It will be
 * considered a regex, if there's any characters that are not normally in
 * function names or "*" or "?" for a glob.
 *
 * @flags:
 *   TRACEFS_FL_RESET - will clear the functions in the filter file
 *          before applying the @filter. This will error with -1
 *          and errno of EBUSY if this flag is set and a previous
 *          call had the same instance and TRACEFS_FL_CONTINUE set.
 *   TRACEFS_FL_CONTINUE - will keep the filter file open on return.
 *          The filter is updated on closing of the filter file.
 *          With this flag set, the file is not closed, and more filters
 *          may be added before they take effect. The last call of this
 *          function must be called without this flag for the filter
 *          to take effect.
 *   TRACEFS_FL_FUTURE - only applicable if "module" is set. If no match
 *          is made, and the module is not yet loaded, it will still attempt
 *          to write the filter plus the module; "<filter>:mod:<module>"
 *          to the filter file. Starting with Linux kernels 4.13, it is possible
 *          to load the filter file with module functions for a module that
 *          is not yet loaded, and when the module is loaded, it will then
 *          activate the module.
 *
 * Returns 0 on success, 1 if there was an error but the filtering has not
 *  yet started, -1 if there was an error but the filtering has started.
 *  If -1 is returned and TRACEFS_FL_CONTINUE was set, then this function
 *  needs to be called again without the TRACEFS_FL_CONTINUE flag to commit
 *  the changes and close the filter file.
 */
int tracefs_function_filter(struct tracefs_instance *instance, const char *filter,
			    const char *module, unsigned int flags)
{
	struct func_filter func_filter;
	struct func_list *func_list = NULL;
	char *ftrace_filter_path;
	bool reset = flags & TRACEFS_FL_RESET;
	bool cont = flags & TRACEFS_FL_CONTINUE;
	bool future = flags & TRACEFS_FL_FUTURE;
	int open_flags;
	int ret = 1;
	int *fd;

	/* future flag is only applicable to modules */
	if (future && !module) {
		errno = EINVAL;
		return 1;
	}

	pthread_mutex_lock(&filter_lock);
	if (instance)
		fd = &instance->ftrace_filter_fd;
	else
		fd = &ftrace_filter_fd;

	/* RESET is only allowed if the file is not opened yet */
	if (reset && *fd >= 0) {
		errno = EBUSY;
		ret = -1;
		goto out;
	}

	/*
	 * Set EINVAL on no matching filter. But errno may still be modified
	 * on another type of failure (allocation or opening a file).
	 */
	errno = EINVAL;

	/* module set with NULL filter means to enable all functions in a module */
	if (module && !filter)
		filter = "*";

	if (!filter) {
		/* OK to call without filters if this is closing the opened file */
		if (!cont && *fd >= 0) {
			errno = 0;
			ret = 0;
			close(*fd);
			*fd = -1;
		}
		/* Also OK to call if reset flag is set */
		if (reset)
			goto open_file;

		goto out;
	}

	if (init_func_filter(&func_filter, filter) < 0)
		goto out;

	ret = check_available_filters(&func_filter, module, &func_list, future);
	if (ret)
		goto out_free;

 open_file:
	ret = 1;
	ftrace_filter_path = tracefs_instance_get_file(instance, TRACE_FILTER);
	if (!ftrace_filter_path)
		goto out_free;

	open_flags = reset ? O_TRUNC : O_APPEND;

	if (*fd < 0)
		*fd = open(ftrace_filter_path, O_WRONLY | O_CLOEXEC | open_flags);
	tracefs_put_tracing_file(ftrace_filter_path);
	if (*fd < 0)
		goto out_free;

	errno = 0;

	ret = 0;

	if (filter) {
		/*
		 * If future is set, and no functions were found, then
		 * set it directly.
		 */
		if (func_list)
			ret = write_func_list(*fd, func_list);
		else
			ret = 1;
		if (ret > 0)
			ret = controlled_write(*fd, &func_filter, module);
	}

	if (!cont) {
		close(*fd);
		*fd = -1;
	}

 out_free:
	free_func_list(func_list);
 out:
	pthread_mutex_unlock(&filter_lock);

	return ret;
}

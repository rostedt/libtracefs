// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2021 VMware Inc, Steven Rostedt <rostedt@goodmis.org>
 *
 * Updates:
 * Copyright (C) 2021, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include "tracefs.h"
#include "tracefs-local.h"

#define HIST_FILE "hist"

#define ASCENDING ".ascending"
#define DESCENDING ".descending"

struct tracefs_hist {
	struct tracefs_instance *instance;
	char			*system;
	char			*event;
	char			*name;
	char			**keys;
	char			**values;
	char			**sort;
	char			*filter;
	int			size;
};

enum tracefs_hist_command {
	HIST_CMD_NONE = 0,
	HIST_CMD_PAUSE,
	HIST_CMD_CONT,
	HIST_CMD_CLEAR,
	HIST_CMD_DESTROY,
};

static void add_list(struct trace_seq *seq, const char *start,
		     char **list)
{
	int i;

	trace_seq_puts(seq, start);
	for (i = 0; list[i]; i++) {
		if (i)
			trace_seq_putc(seq, ',');
		trace_seq_puts(seq, list[i]);
	}
}

/*
 * trace_hist_start - Create and start a histogram for an event
 * @hist: The histogram to write into the trigger file
 * @command: If not zero, can pause, continue or clear the histogram
 *
 * This creates a histogram for an event with the given fields.
 *
 * Returns 0 on succes -1 on error.
 */
static int
trace_hist_start(struct tracefs_hist *hist,
		 enum tracefs_hist_command command)
{
	struct tracefs_instance *instance = hist->instance;
	const char *system = hist->system;
	const char *event = hist->event;
	struct trace_seq seq;
	int ret;

	errno = -EINVAL;
	if (!hist->keys)
		return -1;

	trace_seq_init(&seq);

	if (command == HIST_CMD_DESTROY)
		trace_seq_putc(&seq, '!');

	add_list(&seq, "hist:keys=", hist->keys);

	if (hist->values)
		add_list(&seq, ":vals=", hist->values);

	if (hist->sort)
		add_list(&seq, ":sort=", hist->sort);

	if (hist->size)
		trace_seq_printf(&seq, ":size=%d", hist->size);

	switch(command) {
	case HIST_CMD_NONE: break;
	case HIST_CMD_PAUSE: trace_seq_puts(&seq, ":pause"); break;
	case HIST_CMD_CONT: trace_seq_puts(&seq, ":cont"); break;
	case HIST_CMD_CLEAR: trace_seq_puts(&seq, ":clear"); break;
	default: break;
	}

	if (hist->name)
		trace_seq_printf(&seq, ":name=%s", hist->name);

	if (hist->filter)
		trace_seq_printf(&seq, " if %s\n", hist->filter);

	trace_seq_terminate(&seq);

	ret = -1;
	if (seq.state == TRACE_SEQ__GOOD)
		ret = tracefs_event_file_append(instance, system, event,
						"trigger", seq.buffer);

	trace_seq_destroy(&seq);

	return ret < 0 ? -1 : 0;
}

/**
 * tracefs_hist_free - free a tracefs_hist element
 * @hist: The histogram to free
 */
void tracefs_hist_free(struct tracefs_hist *hist)
{
	if (!hist)
		return;

	trace_put_instance(hist->instance);
	free(hist->system);
	free(hist->event);
	free(hist->name);
	free(hist->filter);
	tracefs_list_free(hist->keys);
	tracefs_list_free(hist->values);
	tracefs_list_free(hist->sort);
	free(hist);
}

/**
 * tracefs_hist_alloc - Initialize a histogram
 * @instance: The instance the histogram will be in (NULL for toplevel)
 * @system: The system the histogram event is in.
 * @event: The event that the histogram will be attached to.
 * @key: The primary key the histogram will use
 * @type: The format type of the key.
 *
 * Will initialize a histogram descriptor that will be attached to
 * the @system/@event with the given @key as the primary. This only
 * initializes the descriptor, it does not start the histogram
 * in the kernel.
 *
 * Returns an initialized histogram on success.
 * NULL on failure.
 */
struct tracefs_hist *
tracefs_hist_alloc(struct tracefs_instance * instance,
			const char *system, const char *event,
			const char *key, enum tracefs_hist_key_type type)
{
	struct tracefs_hist *hist;
	int ret;

	if (!system || !event || !key)
		return NULL;

	if (!tracefs_event_file_exists(instance, system, event, HIST_FILE))
		return NULL;

	hist = calloc(1, sizeof(*hist));
	if (!hist)
		return NULL;

	ret = trace_get_instance(instance);
	if (ret < 0) {
		free(hist);
		return NULL;
	}

	hist->instance = instance;

	hist->system = strdup(system);
	hist->event = strdup(event);

	ret = tracefs_hist_add_key(hist, key, type);

	if (!hist->system || !hist->event || ret < 0) {
		tracefs_hist_free(hist);
		return NULL;
	}


	return hist;
}

/**
 * tracefs_hist_add_key - add to a key to a histogram
 * @hist: The histogram to add the key to.
 * @key: The name of the key field.
 * @type: The type of the key format.
 *
 * This adds a secondary or tertiary key to the histogram.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_add_key(struct tracefs_hist *hist, const char *key,
			 enum tracefs_hist_key_type type)
{
	bool use_key = false;
	char *key_type = NULL;
	char **new_list;
	int ret;

	switch (type) {
	case TRACEFS_HIST_KEY_NORMAL:
		use_key = true;
		ret = 0;
		break;
	case TRACEFS_HIST_KEY_HEX:
		ret = asprintf(&key_type, "%s.hex", key);
		break;
	case TRACEFS_HIST_KEY_SYM:
		ret = asprintf(&key_type, "%s.sym", key);
		break;
	case TRACEFS_HIST_KEY_SYM_OFFSET:
		ret = asprintf(&key_type, "%s.sym-offset", key);
		break;
	case TRACEFS_HIST_KEY_SYSCALL:
		ret = asprintf(&key_type, "%s.syscall", key);
		break;
	case TRACEFS_HIST_KEY_EXECNAME:
		ret = asprintf(&key_type, "%s.execname", key);
		break;
	case TRACEFS_HIST_KEY_LOG:
		ret = asprintf(&key_type, "%s.log2", key);
		break;
	case TRACEFS_HIST_KEY_USECS:
		ret = asprintf(&key_type, "%s.usecs", key);
		break;
	}

	if (ret < 0)
		return -1;

	new_list = tracefs_list_add(hist->keys, use_key ? key : key_type);
	free(key_type);
	if (!new_list)
		return -1;

	hist->keys = new_list;

	return 0;
}

/**
 * tracefs_hist_add_value - add to a value to a histogram
 * @hist: The histogram to add the value to.
 * @key: The name of the value field.
 *
 * This adds a value field to the histogram.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_add_value(struct tracefs_hist *hist, const char *value)
{
	char **new_list;

	new_list = tracefs_list_add(hist->values, value);
	if (!new_list)
		return -1;

	hist->values = new_list;

	return 0;
}

/**
 * tracefs_hist_add_name - name a histogram
 * @hist: The histogram to name.
 * @name: The name of the histogram.
 *
 * Adds a name to the histogram. Named histograms will share their
 * data with other events that have the same name as if it was
 * a single histogram.
 *
 * If the histogram already has a name, this will fail.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_add_name(struct tracefs_hist *hist, const char *name)
{
	if (hist->name)
		return -1;

	hist->name = strdup(name);

	return hist->name ? 0 : -1;
}

/**
 * tracefs_hist_start - enable a histogram
 * @hist: The histogram to start
 *
 * Starts executing a histogram.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_start(struct tracefs_hist *hist)
{
	return trace_hist_start(hist, 0);
}

/**
 * tracefs_hist_pause - pause a histogram
 * @hist: The histogram to pause
 *
 * Pause a histogram.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_pause(struct tracefs_hist *hist)
{
	return trace_hist_start(hist, HIST_CMD_PAUSE);
}

/**
 * tracefs_hist_continue - continue a paused histogram
 * @hist: The histogram to continue
 *
 * Continue a histogram.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_continue(struct tracefs_hist *hist)
{
	return trace_hist_start(hist, HIST_CMD_CONT);
}

/**
 * tracefs_hist_reset - clear a histogram
 * @hist: The histogram to reset
 *
 * Resets a histogram.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_reset(struct tracefs_hist *hist)
{
	return trace_hist_start(hist, HIST_CMD_CLEAR);
}

/**
 * tracefs_hist_destroy - deletes a histogram (needs to be enabled again)
 * @hist: The histogram to delete
 *
 * Deletes (removes) a running histogram. This is different than
 * clear, as clear only clears the data but the histogram still exists.
 * This deletes the histogram and should be called before
 * tracefs_hist_free() to clean up properly.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_destroy(struct tracefs_hist *hist)
{
	return trace_hist_start(hist, HIST_CMD_DESTROY);
}

static char **
add_sort_key(struct tracefs_hist *hist, const char *sort_key, char **list)
{
	char **key_list = hist->keys;
	char **val_list = hist->values;
	int i;

	if (strcmp(sort_key, TRACEFS_HIST_HITCOUNT) == 0)
		goto out;

	for (i = 0; key_list[i]; i++) {
		if (strcmp(key_list[i], sort_key) == 0)
			break;
	}

	if (!key_list[i]) {
		for (i = 0; val_list[i]; i++) {
		if (strcmp(val_list[i], sort_key) == 0)
			break;
		if (!val_list[i])
			return NULL;
		}
	}


 out:
	return tracefs_list_add(list, sort_key);
}

/**
 * tracefs_hist_add_sort_key - add a key for sorting the histogram
 * @hist: The histogram to add the sort key to
 * @sort_key: The key to sort (and the strings after it)
 *  Last one must be NULL.
 *
 * Add a list of sort keys in the order of priority that the
 * keys would be sorted on output. Keys must be added first.
 *
 * Returns 0 on success, -1 on error.
 */
int tracefs_hist_add_sort_key(struct tracefs_hist *hist,
			      const char *sort_key, ...)
{
	char **list = NULL;
	char **tmp;
	va_list ap;

	if (!hist || !sort_key)
		return -1;

	tmp = add_sort_key(hist, sort_key, list);
	if (!tmp)
		goto fail;
	list = tmp;

	va_start(ap, sort_key);
	for (;;) {
		sort_key = va_arg(ap, const char *);
		if (!sort_key)
			break;
		tmp = add_sort_key(hist, sort_key, list);
		if (!tmp)
			goto fail;
		list = tmp;
	}
	va_end(ap);

	tracefs_list_free(hist->sort);
	hist->sort = list;

	return 0;
 fail:
	tracefs_list_free(list);
	return -1;
}

static int end_match(const char *sort_key, const char *ending)
{
	int key_len = strlen(sort_key);
	int end_len = strlen(ending);

	if (key_len <= end_len)
		return 0;

	sort_key += key_len - end_len;

	return strcmp(sort_key, ending) == 0 ? key_len - end_len : 0;
}

/**
 * tracefs_hist_sort_key_direction - set direction of a sort key
 * @hist: The histogram to modify.
 * @sort_str: The sort key to set the direction for
 * @dir: The direction to set the sort key to.
 *
 * Returns 0 on success, and -1 on error;
 */
int tracefs_hist_sort_key_direction(struct tracefs_hist *hist,
				    const char *sort_str,
				    enum tracefs_hist_sort_direction dir)
{
	char **sort = hist->sort;
	char *sort_key;
	char *direct;
	int match;
	int i;

	if (!sort)
		return -1;

	for (i = 0; sort[i]; i++) {
		if (strcmp(sort[i], sort_str) == 0)
			break;
	}
	if (!sort[i])
		return -1;

	sort_key = sort[i];

	switch (dir) {
	case TRACEFS_HIST_SORT_ASCENDING:
		direct = ASCENDING;
		break;
	case TRACEFS_HIST_SORT_DESCENDING:
		direct = DESCENDING;
		break;
	default:
		return -1;
	}

	match = end_match(sort_key, ASCENDING);
	if (match) {
		/* Already match? */
		if (dir == TRACEFS_HIST_SORT_ASCENDING)
			return 0;
	} else {
		match = end_match(sort_key, DESCENDING);
		/* Already match? */
		if (match && dir == TRACEFS_HIST_SORT_DESCENDING)
			return 0;
	}

	if (match)
		/* Clear the original text */
		sort_key[match] = '\0';

	sort_key = realloc(sort_key, strlen(sort_key) + strlen(direct) + 1);
	if (!sort_key) {
		/* Failed to alloc, may need to put back the match */
		sort_key = sort[i];
		if (match)
			sort_key[match] = '.';
		return -1;
	}

	strcat(sort_key, direct);
	sort[i] = sort_key;
	return 0;
}

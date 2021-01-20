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
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include "tracefs.h"
#include "tracefs-local.h"

#define TRACE_CTRL	"tracing_on"

static const char * const options_map[TRACEFS_OPTION_MAX] = {
	"unknown", "annotate", "bin", "blk_cgname", "blk_cgroup", "blk_classic",
	"block", "context-info", "disable_on_free", "display-graph", "event-fork",
	"funcgraph-abstime", "funcgraph-cpu", "funcgraph-duration", "funcgraph-irqs",
	"funcgraph-overhead", "funcgraph-overrun", "funcgraph-proc", "funcgraph-tail",
	"func_stack_trace", "function-fork", "function-trace", "graph-time", "hex",
	"irq-info", "latency-format", "markers", "overwrite", "pause-on-trace",
	"printk-msg-only", "print-parent", "raw", "record-cmd", "record-tgid",
	"sleep-time", "stacktrace", "sym-addr", "sym-offset", "sym-userobj",
	"trace_printk", "userstacktrace", "verbose" };

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

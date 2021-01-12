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

#include "tracefs.h"
#include "tracefs-local.h"

#define TRACE_CTRL	"tracing_on"

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

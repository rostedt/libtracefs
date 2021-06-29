// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * Updates:
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <traceevent/event-parse.h>
#include <traceevent/event-utils.h>
#include "tracefs.h"
#include "tracefs-local.h"

#define TRACEFS_PATH "/sys/kernel/tracing"
#define DEBUGFS_PATH "/sys/kernel/debug"

#define ERROR_LOG "error_log"

#define _STR(x) #x
#define STR(x) _STR(x)

static int log_level = TEP_LOG_CRITICAL;

/**
 * tracefs_set_loglevel - set log level of the library
 * @level: desired level of the library messages
 */
void tracefs_set_loglevel(enum tep_loglevel level)
{
	log_level = level;
	tep_set_loglevel(level);
}

void __weak tracefs_warning(const char *fmt, ...)
{
	va_list ap;

	if (log_level < TEP_LOG_WARNING)
		return;

	va_start(ap, fmt);
	tep_vprint("libtracefs", TEP_LOG_WARNING, true, fmt, ap);
	va_end(ap);
}

static int mount_tracefs(void)
{
	struct stat st;
	int ret;

	/* make sure debugfs exists */
	ret = stat(TRACEFS_PATH, &st);
	if (ret < 0)
		return -1;

	ret = mount("nodev", TRACEFS_PATH,
		    "tracefs", 0, NULL);

	return ret;
}

static int mount_debugfs(void)
{
	struct stat st;
	int ret;

	/* make sure debugfs exists */
	ret = stat(DEBUGFS_PATH, &st);
	if (ret < 0)
		return -1;

	ret = mount("nodev", DEBUGFS_PATH,
		    "debugfs", 0, NULL);

	return ret;
}

/**
 * trace_find_tracing_dir - Find tracing directory
 *
 * Returns string containing the full path to the system's tracing directory.
 * The string must be freed by free()
 */
__hidden char *trace_find_tracing_dir(void)
{
	char *debug_str = NULL;
	char fspath[PATH_MAX+1];
	char *tracing_dir;
	char type[100];
	int use_debug = 0;
	FILE *fp;

	fp = fopen("/proc/mounts", "r");
	if (!fp) {
		tracefs_warning("Can't open /proc/mounts for read");
		return NULL;
	}

	while (fscanf(fp, "%*s %"
		      STR(PATH_MAX)
		      "s %99s %*s %*d %*d\n",
		      fspath, type) == 2) {
		if (strcmp(type, "tracefs") == 0)
			break;
		if (!debug_str && strcmp(type, "debugfs") == 0) {
			debug_str = strdup(fspath);
			if (!debug_str) {
				fclose(fp);
				return NULL;
			}
		}
	}
	fclose(fp);

	if (strcmp(type, "tracefs") != 0) {
		if (mount_tracefs() < 0) {
			if (debug_str) {
				strncpy(fspath, debug_str, PATH_MAX);
				fspath[PATH_MAX] = 0;
			} else {
				if (mount_debugfs() < 0) {
					tracefs_warning("debugfs not mounted, please mount");
					free(debug_str);
					return NULL;
				}
				strcpy(fspath, DEBUGFS_PATH);
			}
			use_debug = 1;
		} else
			strcpy(fspath, TRACEFS_PATH);
	}
	free(debug_str);

	if (use_debug) {
		int ret;

		ret = asprintf(&tracing_dir, "%s/tracing", fspath);
		if (ret < 0)
			return NULL;
	} else {
		tracing_dir = strdup(fspath);
		if (!tracing_dir)
			return NULL;
	}

	return tracing_dir;
}

/**
 * tracefs_tracing_dir - Get tracing directory
 *
 * Returns string containing the full path to the system's tracing directory.
 * The returned string must *not* be freed.
 */
const char *tracefs_tracing_dir(void)
{
	static const char *tracing_dir;

	if (tracing_dir)
		return tracing_dir;

	tracing_dir = trace_find_tracing_dir();
	return tracing_dir;
}

/**
 * tracefs_get_tracing_file - Get tracing file
 * @name: tracing file name
 *
 * Returns string containing the full path to a tracing file in
 * the system's tracing directory.
 *
 * Must use tracefs_put_tracing_file() to free the returned string.
 */
char *tracefs_get_tracing_file(const char *name)
{
	static const char *tracing;
	char *file;
	int ret;

	if (!name)
		return NULL;

	if (!tracing) {
		tracing = trace_find_tracing_dir();
		if (!tracing)
			return NULL;
	}

	ret = asprintf(&file, "%s/%s", tracing, name);
	if (ret < 0)
		return NULL;

	return file;
}

/**
 * tracefs_put_tracing_file - Free tracing file or directory name
 *
 * Frees tracing file or directory, returned by
 * tracefs_get_tracing_file()API.
 */
void tracefs_put_tracing_file(char *name)
{
	free(name);
}

__hidden int str_read_file(const char *file, char **buffer, bool warn)
{
	char stbuf[BUFSIZ];
	char *buf = NULL;
	int size = 0;
	char *nbuf;
	int fd;
	int r;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		if (warn)
			tracefs_warning("File %s not found", file);
		return -1;
	}

	do {
		r = read(fd, stbuf, BUFSIZ);
		if (r <= 0)
			continue;
		nbuf = realloc(buf, size+r+1);
		if (!nbuf) {
			if (warn)
				tracefs_warning("Failed to allocate file buffer");
			size = -1;
			break;
		}
		buf = nbuf;
		memcpy(buf+size, stbuf, r);
		size += r;
	} while (r > 0);

	close(fd);
	if (r == 0 && size > 0) {
		buf[size] = '\0';
		*buffer = buf;
	} else
		free(buf);

	return size;
}

/**
 * tracefs_error_all - return the content of the error log
 * @instance: The instance to read the error log from (NULL for top level)
 *
 * Return NULL if the log is empty, or on error (where errno will be
 * set. Otherwise the content of the entire log is returned in a string
 * that must be freed with free().
 */
char *tracefs_error_all(struct tracefs_instance *instance)
{
	char *content;
	char *path;
	int size;

	errno = 0;

	path = tracefs_instance_get_file(instance, ERROR_LOG);
	if (!path)
		return NULL;
	size = str_read_file(path, &content, false);
	tracefs_put_tracing_file(path);

	if (size <= 0)
		return NULL;

	return content;
}

enum line_states {
	START,
	CARROT,
};

/**
 * tracefs_error_last - return the last error logged
 * @instance: The instance to read the error log from (NULL for top level)
 *
 * Return NULL if the log is empty, or on error (where errno will be
 * set. Otherwise a string containing the content of the last error shown
* in the log that must be freed with free().
 */
char *tracefs_error_last(struct tracefs_instance *instance)
{
	enum line_states state = START;
	char *content;
	char *ret;
	bool done = false;
	int size;
	int i;

	content = tracefs_error_all(instance);
	if (!content)
		return NULL;

	size = strlen(content);
	if (!size) /* Should never happen */
		return content;

	for (i = size - 1; i > 0; i--) {
		switch (state) {
		case START:
			if (content[i] == '\n') {
				/* Remove extra new lines */
				content[i] = '\0';
				break;
			}
			if (content[i] == '^')
				state = CARROT;
			break;
		case CARROT:
			if (content[i] == '\n') {
				/* Remember last new line */
				size = i;
				break;
			}
			if (content[i] == '^') {
				/* Go just passed the last newline */
				i = size + 1;
				done = true;
			}
			break;
		}
		if (done)
			break;
	}

	if (i) {
		ret = strdup(content + i);
		free(content);
	} else {
		ret = content;
	}

	return ret;
}

/**
 * tracefs_error_clear - clear the error log of an instance
 * @instance: The instance to clear (NULL for top level)
 *
 * Clear the content of the error log.
 *
 * Returns 0 on success, -1 otherwise.
 */
int tracefs_error_clear(struct tracefs_instance *instance)
{
	return tracefs_instance_file_clear(instance, ERROR_LOG);
}

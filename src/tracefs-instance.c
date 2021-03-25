// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * Updates:
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include "tracefs.h"
#include "tracefs-local.h"

#define FLAG_INSTANCE_NEWLY_CREATED	(1 << 0)
struct tracefs_instance {
	char	*trace_dir;
	char	*name;
	int	flags;
};

/**
 * instance_alloc - allocate a new ftrace instance
 * @trace_dir - Full path to the tracing directory, where the instance is
 * @name: The name of the instance (instance will point to this)
 *
 * Returns a newly allocated instance, or NULL in case of an error.
 */
static struct tracefs_instance *instance_alloc(const char *trace_dir, const char *name)
{
	struct tracefs_instance *instance;

	instance = calloc(1, sizeof(*instance));
	if (!instance)
		goto error;
	instance->trace_dir = strdup(trace_dir);
	if (!instance->trace_dir)
		goto error;
	if (name) {
		instance->name = strdup(name);
		if (!instance->name)
			goto error;
	}

	return instance;

error:
	if (instance) {
		free(instance->name);
		free(instance->trace_dir);
		free(instance);
	}
	return NULL;
}

/**
 * tracefs_instance_free - Free an instance, previously allocated by
			   tracefs_instance_create()
 * @instance: Pointer to the instance to be freed
 *
 */
void tracefs_instance_free(struct tracefs_instance *instance)
{
	if (!instance)
		return;
	free(instance->trace_dir);
	free(instance->name);
	free(instance);
}

static mode_t get_trace_file_permissions(char *name)
{
	mode_t rmode = 0;
	struct stat st;
	char *path;
	int ret;

	path = tracefs_get_tracing_file(name);
	if (!path)
		return 0;
	ret = stat(path, &st);
	if (ret)
		goto out;
	rmode = st.st_mode & ACCESSPERMS;
out:
	tracefs_put_tracing_file(path);
	return rmode;
}

/**
 * tracefs_instance_is_new - Check if the instance is newly created by the library
 * @instance: Pointer to an ftrace instance
 *
 * Returns true, if the ftrace instance is newly created by the library or
 * false otherwise.
 */
bool tracefs_instance_is_new(struct tracefs_instance *instance)
{
	if (instance && (instance->flags & FLAG_INSTANCE_NEWLY_CREATED))
		return true;
	return false;
}

/**
 * tracefs_instance_create - Create a new ftrace instance
 * @name: Name of the instance to be created
 *
 * Allocates and initializes a new instance structure. If the instance does not
 * exist in the system, create it.
 * Returns a pointer to a newly allocated instance, or NULL in case of an error.
 * The returned instance must be freed by tracefs_instance_free().
 */
struct tracefs_instance *tracefs_instance_create(const char *name)
{
	struct tracefs_instance *inst = NULL;
	char *path = NULL;
	const char *tdir;
	struct stat st;
	mode_t mode;
	int ret;

	tdir = tracefs_tracing_dir();
	if (!tdir)
		return NULL;
	inst = instance_alloc(tdir, name);
	if (!inst)
		return NULL;

	path = tracefs_instance_get_dir(inst);
	ret = stat(path, &st);
	if (ret < 0) {
		/* Cannot create the top instance, if it does not exist! */
		if (!name)
			goto error;
		mode = get_trace_file_permissions("instances");
		if (mkdir(path, mode))
			goto error;
		inst->flags |= FLAG_INSTANCE_NEWLY_CREATED;
	}
	tracefs_put_tracing_file(path);
	return inst;

error:
	tracefs_instance_free(inst);
	return NULL;
}

/**
 * tracefs_instance_alloc - Allocate an instance structure for existing trace instance
 * @tracing_dir: full path to the system trace directory, where the new instance is
 *		 if NULL, the default top tracing directory is used.
 * @name: Name of the instance.
 *
 * Allocates and initializes a new instance structure. If the instance does not
 * exist, do not create it and exit with error.
 * Returns a pointer to a newly allocated instance, or NULL in case of an error
 * or the requested instance does not exists.
 * The returned instance must be freed by tracefs_instance_free().
 */
struct tracefs_instance *tracefs_instance_alloc(const char *tracing_dir,
						const char *name)
{
	struct tracefs_instance *inst = NULL;
	char file[PATH_MAX];
	const char *tdir;
	struct stat st;
	int ret;

	if (tracing_dir) {
		ret = stat(tracing_dir, &st);
		if (ret < 0 || !S_ISDIR(st.st_mode))
			return NULL;
		tdir = tracing_dir;

	} else
		tdir = tracefs_tracing_dir();
	if (!tdir)
		return NULL;

	if (name) {
		sprintf(file, "%s/instances/%s", tdir, name);
		ret = stat(file, &st);
		if (ret < 0 || !S_ISDIR(st.st_mode))
			return NULL;
	}
	inst = instance_alloc(tdir, name);

	return inst;
}

/**
 * tracefs_instance_destroy - Remove a ftrace instance
 * @instance: Pointer to the instance to be removed
 *
 * Returns -1 in case of an error, or 0 otherwise.
 */
int tracefs_instance_destroy(struct tracefs_instance *instance)
{
	char *path;
	int ret = -1;

	if (!instance || !instance->name) {
		warning("Cannot remove top instance");
		return -1;
	}

	path = tracefs_instance_get_dir(instance);
	if (path)
		ret = rmdir(path);
	tracefs_put_tracing_file(path);

	return ret;
}

/**
 * tracefs_instance_get_file - return the path to an instance file.
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of file to return
 *
 * Returns the path of the @file for the given @instance, or NULL in
 * case of an error.
 *
 * Must use tracefs_put_tracing_file() to free the returned string.
 */
char *
tracefs_instance_get_file(struct tracefs_instance *instance, const char *file)
{
	char *path = NULL;
	int ret;

	if (!instance)
		return tracefs_get_tracing_file(file);
	if (!instance->name)
		ret = asprintf(&path, "%s/%s", instance->trace_dir, file);
	else
		ret = asprintf(&path, "%s/instances/%s/%s",
			       instance->trace_dir, instance->name, file);
	if (ret < 0)
		return NULL;

	return path;
}

/**
 * tracefs_instance_get_dir - return the path to the instance directory.
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns the full path to the instance directory
 *
 * Must use tracefs_put_tracing_file() to free the returned string.
 */
char *tracefs_instance_get_dir(struct tracefs_instance *instance)
{
	char *path = NULL;
	int ret;

	if (!instance) /* Top instance of default system trace directory */
		return trace_find_tracing_dir();

	if (!instance->name)
		return strdup(instance->trace_dir);

	ret = asprintf(&path, "%s/instances/%s", instance->trace_dir, instance->name);
	if (ret < 0) {
		warning("Failed to allocate path for instance %s",
			 instance->name);
		return NULL;
	}

	return path;
}

/**
 * tracefs_instance_get_name - return the name of an instance
 * @instance: ftrace instance
 *
 * Returns the name of the given @instance.
 * The returned string must *not* be freed.
 */
const char *tracefs_instance_get_name(struct tracefs_instance *instance)
{
	if (instance)
		return instance->name;
	return NULL;
}

/**
 * tracefs_instance_get_trace_dir - return the top trace directory, where the instance is confuigred
 * @instance: ftrace instance
 *
 * Returns the top trace directory where the given @instance is configured.
 * The returned string must *not* be freed.
 */
const char *tracefs_instance_get_trace_dir(struct tracefs_instance *instance)
{
	if (instance)
		return instance->trace_dir;
	return NULL;
}

static int write_file(const char *file, const char *str)
{
	int ret;
	int fd;

	fd = open(file, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		warning("Failed to open '%s'", file);
		return -1;
	}
	ret = write(fd, str, strlen(str));
	close(fd);
	return ret;
}


/**
 * tracefs_instance_file_write - Write in trace file of specific instance.
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of the file
 * @str: nul terminated string, that will be written in the file.
 *
 * Returns the number of written bytes, or -1 in case of an error
 */
int tracefs_instance_file_write(struct tracefs_instance *instance,
				 const char *file, const char *str)
{
	struct stat st;
	char *path;
	int ret;

	path = tracefs_instance_get_file(instance, file);
	if (!path)
		return -1;
	ret = stat(path, &st);
	if (ret == 0)
		ret = write_file(path, str);
	tracefs_put_tracing_file(path);

	return ret;
}

/**
 * tracefs_instance_file_read - Read from a trace file of specific instance.
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of the file
 * @psize: returns the number of bytes read
 *
 * Returns a pointer to a nul terminated string, read from the file, or NULL in
 * case of an error.
 * The return string must be freed by free()
 */
char *tracefs_instance_file_read(struct tracefs_instance *instance,
				 const char *file, int *psize)
{
	char *buf = NULL;
	int size = 0;
	char *path;

	path = tracefs_instance_get_file(instance, file);
	if (!path)
		return NULL;

	size = str_read_file(path, &buf);

	tracefs_put_tracing_file(path);
	if (buf && psize)
		*psize = size;

	return buf;
}

/**
 * tracefs_instance_file_read_number - Read long long integer from a trace file.
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of the file
 * @res: The integer from the file.
 *
 * Returns 0 if the reading is successful and the result is stored in res, -1
 * in case of an error.
 */
int tracefs_instance_file_read_number(struct tracefs_instance *instance,
				      const char *file, long long *res)
{
	long long num;
	int ret = -1;
	int size = 0;
	char *endptr;
	char *str;

	str = tracefs_instance_file_read(instance, file, &size);
	if (size && str) {
		errno = 0;
		num = strtoll(str, &endptr, 0);
		if (errno == 0 && str != endptr) {
			*res = num;
			ret = 0;
		}
	}
	free(str);
	return ret;
}

/**
 * tracefs_instance_file_open - Open a trace file for reading and writing
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of the file
 * @mode: file open flags, -1 for default O_RDWR
 *
 * Returns -1 in case of an error, or a valid file descriptor otherwise.
 * The returned FD must be closed with close()
 */
int tracefs_instance_file_open(struct tracefs_instance *instance,
			       const char *file, int mode)
{
	int flags = O_RDWR;
	int fd = -1;
	char *path;

	path = tracefs_instance_get_file(instance, file);
	if (!path)
		return -1;

	if (mode >= 0)
		flags = mode;
	fd = open(path, flags);
	tracefs_put_tracing_file(path);

	return fd;
}

static bool check_file_exists(struct tracefs_instance *instance,
			      const char *name, bool dir)
{
	char file[PATH_MAX];
	struct stat st;
	char *path;
	int ret;

	path = tracefs_instance_get_dir(instance);
	if (name)
		snprintf(file, PATH_MAX, "%s/%s", path, name);
	else
		snprintf(file, PATH_MAX, "%s", path);
	tracefs_put_tracing_file(path);
	ret = stat(file, &st);
	if (ret < 0)
		return false;

	return !dir == !S_ISDIR(st.st_mode);
}

/**
 * tracefs_instance_exists - Check an instance with given name exists
 * @name: name of the instance
 *
 * Returns true if the instance exists, false otherwise
 *
 */
bool tracefs_instance_exists(const char *name)
{
	char file[PATH_MAX];

	if (!name)
		return false;
	snprintf(file, PATH_MAX, "instances/%s", name);
	return check_file_exists(NULL, file, true);
}

/**
 * tracefs_file_exists - Check if a file with given name exists in given instance
 * @instance: ftrace instance, can be NULL for the top instance
 * @name: name of the file
 *
 * Returns true if the file exists, false otherwise
 *
 * If a directory with the given name exists, false is returned.
 */
bool tracefs_file_exists(struct tracefs_instance *instance, const char *name)
{
	return check_file_exists(instance, name, false);
}

/**
 * tracefs_dir_exists - Check if a directory with given name exists in given instance
 * @instance: ftrace instance, can be NULL for the top instance
 * @name: name of the directory
 *
 * Returns true if the directory exists, false otherwise
 */
bool tracefs_dir_exists(struct tracefs_instance *instance, const char *name)
{
	return check_file_exists(instance, name, true);
}

/**
 * tracefs_instances_walk - Iterate through all ftrace instances in the system
 * @callback: user callback, called for each instance. Instance name is passed
 *	      as input parameter. If the @callback returns non-zero,
 *	      the iteration stops.
 * @context: user context, passed to the @callback.
 *
 * Returns -1 in case of an error, 1 if the iteration was stopped because of the
 * callback return value or 0 otherwise.
 */
int tracefs_instances_walk(int (*callback)(const char *, void *), void *context)
{
	struct dirent *dent;
	char *path = NULL;
	DIR *dir = NULL;
	struct stat st;
	int fret = -1;
	int ret;

	path = tracefs_get_tracing_file("instances");
	if (!path)
		return -1;
	ret = stat(path, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto out;

	dir = opendir(path);
	if (!dir)
		goto out;
	fret = 0;
	while ((dent = readdir(dir))) {
		char *instance;

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		instance = trace_append_file(path, dent->d_name);
		ret = stat(instance, &st);
		free(instance);
		if (ret < 0 || !S_ISDIR(st.st_mode))
			continue;
		if (callback(dent->d_name, context)) {
			fret = 1;
			break;
		}
	}

out:
	if (dir)
		closedir(dir);
	tracefs_put_tracing_file(path);
	return fret;
}

/**
 * tracefs_get_clock - Get the current trace clock
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns the current trace clock of the given instance, or NULL in
 * case of an error.
 * The return string must be freed by free()
 */
char *tracefs_get_clock(struct tracefs_instance *instance)
{
	char *all_clocks = NULL;
	char *ret = NULL;
	int bytes = 0;
	char *clock;
	char *cont;

	all_clocks  = tracefs_instance_file_read(instance, "trace_clock", &bytes);
	if (!all_clocks || !bytes)
		goto out;

	clock = strstr(all_clocks, "[");
	if (!clock)
		goto out;
	clock++;
	cont = strstr(clock, "]");
	if (!cont)
		goto out;
	*cont = '\0';

	ret = strdup(clock);
out:
	free(all_clocks);
	return ret;
}

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

#define KPROBE_EVENTS "kprobe_events"

static int insert_kprobe(const char *type, const char *system,
			 const char *event, const char *addr,
			 const char *format)
{
	char *str;
	int ret;

	if (!tracefs_file_exists(NULL, KPROBE_EVENTS))
		return -1;

	errno = EBADMSG;
	if (!addr || !format)
		return -1;

	if (!event)
		event = addr;

	if (system)
		ret = asprintf(&str, "%s:%s/%s %s %s\n",
			       type, system, event, addr, format);
	else
		ret = asprintf(&str, "%s:%s %s %s\n",
			       type, event, addr, format);

	if (ret < 0)
		return -1;

	ret = tracefs_instance_file_append(NULL, KPROBE_EVENTS, str);
	free(str);

	return ret < 0 ? ret : 0;
}

/**
 * tracefs_kprobe_raw - Create a kprobe using raw format
 * @system: The system name (NULL for the default kprobes)
 * @event: The event to create (NULL to use @addr for the event)
 * @addr: The function and offset (or address) to insert the probe
 * @format: The raw format string to define the probe.
 *
 * Create a kprobe that will be in the @system group (or kprobes if
 * @system is NULL). Have the name of @event (or @addr if @event is
 * NULL). Will be inserted to @addr (function name, with or without
 * offset, or a address). And the @format will define the raw format
 * of the kprobe. See the Linux documentation file under:
 * Documentation/trace/kprobetrace.rst
 *
 * Return 0 on success, or -1 on error.
 *   If the syntex of @format was incorrect, running
 *   tracefs_error_last(NULL) may show what went wrong.
 *
 * errno will be set to EBADMSG if addr or format is NULL.
 */
int tracefs_kprobe_raw(const char *system, const char *event,
		       const char *addr, const char *format)
{
	return insert_kprobe("p", system, event, addr, format);
}

/**
 * tracefs_kretprobe_raw - Create a kretprobe using raw format
 * @system: The system name (NULL for the default kprobes)
 * @event: The event to create (NULL to use @addr for the event)
 * @addr: The function and offset (or address) to insert the retprobe
 * @format: The raw format string to define the retprobe.
 *
 * Create a kretprobe that will be in the @system group (or kprobes if
 * @system is NULL). Have the name of @event (or @addr if @event is
 * NULL). Will be inserted to @addr (function name, with or without
 * offset, or a address). And the @format will define the raw format
 * of the kprobe. See the Linux documentation file under:
 * Documentation/trace/kprobetrace.rst
 *
 * Return 0 on success, or -1 on error.
 *   If the syntex of @format was incorrect, running
 *   tracefs_error_last(NULL) may show what went wrong.
 *
 * errno will be set to EBADMSG if addr or format is NULL.
 */
int tracefs_kretprobe_raw(const char *system, const char *event,
			  const char *addr, const char *format)
{
	return insert_kprobe("r", system, event, addr, format);
}

/**
 * tracefs_get_kprobes - return a list kprobes (by group/event name)
 * @type: The type of kprobes to return.
 *
 * If @type is TRACEFS_ALL_KPROBES all kprobes in the kprobe_events
 * are returned. Otherwise if it is TRACEFS_KPROBE, then only
 * normal kprobes (p:) are returned, or if type is TRACEFS_KRETPROBE
 * then only kretprobes (r:) are returned.
 *
 * Returns a list of strings that contain the kprobes that exist
 * in the kprobe_events files. The strings returned are in the
 * "group/event" format.
 * The list must be freed with tracefs_list_free().
 * If there are no kprobes, a list is still returned, but it contains
 * only a NULL pointer.
 * On error, NULL is returned.
 */
char **tracefs_get_kprobes(enum tracefs_kprobe_type type)
{
	char **list = NULL;
	char *content;
	char *saveptr;
	char *event;
	char *p;
	int cnt = 0;

	errno = 0;
	content = tracefs_instance_file_read(NULL, KPROBE_EVENTS, NULL);
	if (!content) {
		if (errno)
			return NULL;
		/* content is NULL on empty file, return an empty list */
		list = calloc(1, sizeof(*list));
		return list;
	}

	p = strtok_r(content, ":", &saveptr);

	while (p) {
		char **tmp;

		if (type != TRACEFS_ALL_KPROBES) {
			switch (*p) {
			case 'p':
				if (type != TRACEFS_KPROBE)
					goto next;
				break;
			case 'r':
				if (type != TRACEFS_KRETPROBE)
					goto next;
				break;
			default:
				goto next;
			}
		}

		/* Failed parsing always return a failure */
		p = strtok_r(NULL, " ", &saveptr);
		if (!p)
			break;

		event = strdup(p);
		if (!event)
			goto fail;

		tmp = realloc(list, sizeof(*list) * (cnt + 2));
		if (!tmp)
			goto fail;

		list = tmp;
		list[cnt++] = event;
		list[cnt] = NULL;
 next:
		p = strtok_r(NULL, "\n", &saveptr);
		/* Could be end of content */
		if (!p)
			break;

		/* p is NULL on end of content */
		p = strtok_r(NULL, ":", &saveptr);
	}

	if (!list)
		list = calloc(1, sizeof(*list));
 out:
	free(content);
	return list;
 fail:
	free(list);
	list = NULL;
	goto out;
}

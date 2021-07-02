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
#define KPROBE_DEFAULT_GROUP "kprobes"

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

/*
 * Helper function to parse kprobes.
 * @content: The content of kprobe_events on the first iteration.
 *           NULL on next iterations.
 * @saveptr: Same as saveptr for strtok_r
 * @type: Where to store the type (before ':')
 * @system: Store the system of the kprobe (NULL to have event contain
 *          both system and event, as in "kprobes/myprobe").
 * @event: Where to store the event.
 * @addr: Where to store the addr (may be NULL to ignore)
 * @format: Where to store the format (may be NULL to ignore)
 */
static int parse_kprobe(char *content, char **saveptr,
			char **type, char **system, char **event,
			char **addr, char **format)
{
	char *p;

	p = strtok_r(content, ":", saveptr);
	if (!p)
		return 1; /* eof */
	*type = p;

	if (system) {
		p = strtok_r(NULL, "/", saveptr);
		if (!p)
			return -1;
		*system = p;
	}

	p = strtok_r(NULL, " ", saveptr);
	if (!p)
		return -1;
	*event = p;

	if (addr || format) {
		p = strtok_r(NULL, " ", saveptr);
		if (!p)
			return -1;
		if (addr)
			*addr = p;
	}

	p = strtok_r(NULL, "\n", saveptr);
	if (!p)
		return -1;
	if (format)
		*format = p;

	return 0;
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
	char *ktype;
	int cnt = 0;
	int ret;

	errno = 0;
	content = tracefs_instance_file_read(NULL, KPROBE_EVENTS, NULL);
	if (!content) {
		if (errno)
			return NULL;
		/* content is NULL on empty file, return an empty list */
		list = calloc(1, sizeof(*list));
		return list;
	}

	ret = parse_kprobe(content, &saveptr, &ktype, NULL, &event, NULL, NULL);

	while (!ret) {
		char **tmp;

		if (type != TRACEFS_ALL_KPROBES) {
			switch (*ktype) {
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

		event = strdup(event);
		if (!event)
			goto fail;

		tmp = realloc(list, sizeof(*list) * (cnt + 2));
		if (!tmp)
			goto fail;

		list = tmp;
		list[cnt++] = event;
		list[cnt] = NULL;
 next:
		ret = parse_kprobe(NULL, &saveptr, &ktype, NULL, &event, NULL, NULL);
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

/**
 * tracefs_kprobe_info - return the type of kprobe specified.
 * @group: The group the kprobe is in (NULL for the default "kprobes")
 * @event: The name of the kprobe to find.
 * @type: String to return kprobe type (before ':') NULL to ignore.
 * @addr: String to return address kprobe is attached to. NULL to ignore.
 * @format: String to return kprobe format. NULL to ignore.
 *
 * If @type, @addr, or @format is non NULL, then the returned string
 * must be freed with free(). They will also be set to NULL, and
 * even on error, they may contain strings to be freed. If they are
 * not NULL, then they still need to be freed.
 *
 * Returns TRACEFS_ALL_KPROBES if an error occurs or the kprobe is not found,
 *            or the probe is of an unknown type.
 * TRACEFS_KPROBE if the type of kprobe found is a normal kprobe.
 * TRACEFS_KRETPROBE if the type of kprobe found is a kretprobe.
 */
enum tracefs_kprobe_type tracefs_kprobe_info(const char *group, const char *event,
					     char **type, char **addr, char **format)
{
	enum tracefs_kprobe_type rtype = TRACEFS_ALL_KPROBES;
	char *saveptr;
	char *content;
	char *system;
	char *probe;
	char *ktype;
	char *kaddr;
	char *kfmt;
	int ret;

	if (!group)
		group = KPROBE_DEFAULT_GROUP;

	if (type)
		*type = NULL;
	if (addr)
		*addr = NULL;
	if (format)
		*format = NULL;

	content = tracefs_instance_file_read(NULL, KPROBE_EVENTS, NULL);
	if (!content)
		return rtype;

	ret = parse_kprobe(content, &saveptr, &ktype, &system, &probe,
			   &kaddr, &kfmt);

	while (!ret) {

		if (!strcmp(system, group) && !strcmp(probe, event)) {
			if (type)
				*type = strdup(ktype);
			if (addr)
				*addr = strdup(kaddr);
			if (format)
				*format = strdup(kfmt);

			switch (*ktype) {
			case 'p': rtype = TRACEFS_KPROBE; break;
			case 'r': rtype = TRACEFS_KRETPROBE; break;
			}
			break;
		}
		ret = parse_kprobe(NULL, &saveptr, &ktype, &system, &probe,
				   &kaddr, &kfmt);
	}
	free(content);
	return rtype;
}

static void disable_events(const char *system, const char *event,
			   char **list)
{
	struct tracefs_instance *instance;
	int i;

	/*
	 * Note, this will not fail even on error.
	 * That is because even if something fails, it may still
	 * work enough to clear the kprobes. If that's the case
	 * the clearing after the loop will succeed and the function
	 * is a success, even though other parts had failed. If
	 * one of the kprobe events is enabled in one of the
	 * instances that fail, then the clearing will fail too
	 * and the function will return an error.
	 */

	tracefs_event_disable(NULL, system, event);
	/* No need to test results */

	if (!list)
		return;

	for (i = 0; list[i]; i++) {
		instance = tracefs_instance_alloc(NULL, list[i]);
		/* If this fails, try the next one */
		if (!instance)
			continue;
		tracefs_event_disable(instance, system, event);
		tracefs_instance_free(instance);
	}
	return;
}

static int clear_kprobe(const char *system, const char *event)
{
	/* '-' + ':' + '/' + '\n' + '\0' = 5 bytes */
	int len = strlen(system) + strlen(event) + 5;
	char content[len];

	sprintf(content, "-:%s/%s", system, event);
	return tracefs_instance_file_append(NULL, KPROBE_EVENTS, content);
}

static int kprobe_clear_probes(const char *group, bool force)
{
	char **instance_list;
	char **kprobe_list;
	char *saveptr;
	char *system;
	char *kprobe;
	char *event;
	int ret;
	int i;

	kprobe_list = tracefs_get_kprobes(TRACEFS_ALL_KPROBES);
	if (!kprobe_list)
		return -1;

	instance_list = tracefs_instances(NULL);
	/*
	 * Even if the above failed and instance_list is NULL,
	 * keep going, as the enabled event may simply be in the
	 * top level.
	 */

	/*
	 * If a system is defined, the default is to pass unless
	 * an event fails to be removed. If a system is not defined,
	 * the default is to fail, unless all are removed.
	 */
	ret = group ? 0 : -1;

	for (i = 0; kprobe_list[i]; i++) {
		kprobe = kprobe_list[i];

		system = strtok_r(kprobe, "/", &saveptr);
		if (!system)
			goto out;

		event = strtok_r(NULL," ", &saveptr);
		if (!event)
			goto out;

		/* Skip if this does not match a given system */
		if (group && strcmp(system, group) != 0)
			continue;

		if (force)
			disable_events(system, event, instance_list);

		if (group) {
			ret = clear_kprobe(system, event);
			if (ret < 0)
				goto out;
		} else {
			ret = tracefs_instance_file_clear(NULL, KPROBE_EVENTS);
			/* On success stop the loop */
			if (!ret)
				goto out;
		}

		/* Set the default for whether a system is defined or not */
		ret = group ? 0 : -1;
	}
 out:
	tracefs_list_free(instance_list);
	tracefs_list_free(kprobe_list);
	return ret;
}

/**
 * tracefs_kprobe_clear_all - clear kprobe events
 * @force: Will attempt to disable all kprobe events and clear them
 *
 * Will remove all defined kprobe events. If any of them are enabled,
 * and @force is not set, then it will error with -1 and errno to be
 * EBUSY. If @force is set, then it will attempt to disable all the kprobe
 * events in all instances, and try again.
 *
 * Returns zero on success, -1 otherwise.
 */
int tracefs_kprobe_clear_all(bool force)
{
	if (tracefs_instance_file_clear(NULL, KPROBE_EVENTS) == 0)
		return 0;

	if (!force)
		return -1;

	/* Attempt to disable all kprobe events */
	return kprobe_clear_probes(NULL, force);
}

/**
 * tracefs_kprobe_clear_all - clear kprobe events
 * @system: System to clear (NULL means default)
 * @event: Name of probe to clear in system (NULL for all probes in system)
 * @force: Will attempt to disable all kprobe events and clear them
 *
 * Will remove the kprobes that match the @system and @event. If @system
 * is NULL, then "kprobes" is used and will ignore all other system
 * groups of kprobes. The @event is NULL then all events under the given
 * @system are removed, otherwise only the event that matches.
 *
 * Returns zero on success, -1 otherwise.
 */
int tracefs_kprobe_clear_probe(const char *system, const char *event, bool force)
{
	char **instance_list;
	int ret;

	if (!system)
		system = "kprobes";

	if (!event)
		return kprobe_clear_probes(system, force);

	/*
	 * Since we know we are disabling a specific event, try
	 * to disable it first before clearing it.
	 */
	if (force) {
		instance_list = tracefs_instances(NULL);
		disable_events(system, event, instance_list);
		tracefs_list_free(instance_list);
	}

	ret = clear_kprobe(system, event);

	return ret < 0 ? -1 : 0;
}

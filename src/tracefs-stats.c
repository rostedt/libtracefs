// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2023 Google LLC, Steven Rostedt <rostedt@goodmis.org>
 */
#include <stdlib.h>
#include <ctype.h>
#include "tracefs.h"
#include "tracefs-local.h"

static long long convert_ts(char *value)
{
	long long ts;
	char *saveptr;
	char *secs;
	char *usecs;

	secs = strtok_r(value, ".", &saveptr);
	if (!secs)
		return -1LL;

	ts = strtoll(secs, NULL, 0);

	usecs = strtok_r(NULL, ".", &saveptr);
	if (!usecs)
		return ts;

	/* Could be in nanoseconds */
	if (strlen(usecs) > 6)
		ts *= 1000000000LL;
	else
		ts *= 1000000LL;

	ts += strtoull(usecs, NULL, 0);

	return ts;
}

struct tracefs_buffer_stat *
tracefs_instance_get_stat(struct tracefs_instance *instance, int cpu)
{
	struct tracefs_buffer_stat *tstat;
	char *saveptr;
	char *value;
	char *field;
	char *path;
	char *line;
	char *next;
	char *buf;
	int len;
	int ret;

	ret = asprintf(&path, "per_cpu/cpu%d/stats", cpu);
	if (ret < 0)
		return NULL;

	buf = tracefs_instance_file_read(instance, path, &len);
	free(path);

	if (!buf)
		return NULL;

	tstat = malloc(sizeof(*tstat));
	if (!tstat) {
		free(buf);
		return NULL;
	}

	/* Set everything to -1 */
	memset(tstat, -1, sizeof(*tstat));

	next = buf;
	while ((line = strtok_r(next, "\n", &saveptr))) {
		char *save2;

		next = NULL;

		field = strtok_r(line, ":", &save2);
		if (!field)
			break;

		value = strtok_r(NULL, ":", &save2);
		if (!value)
			break;

		while (isspace(*value))
			value++;

		if (strcmp(field, "entries") == 0) {
			tstat->entries = strtoull(value, NULL, 0);

		} else if (strcmp(field, "overrun") == 0) {
			tstat->overrun = strtoull(value, NULL, 0);

		} else if (strcmp(field, "commit overrun") == 0) {
			tstat->commit_overrun = strtoull(value, NULL, 0);

		} else if (strcmp(field, "bytes") == 0) {
			tstat->bytes = strtoull(value, NULL, 0);

		} else if (strcmp(field, "oldest event ts") == 0) {
			tstat->oldest_ts = convert_ts(value);

		} else if (strcmp(field, "now ts") == 0) {
			tstat->now_ts = convert_ts(value);

		} else if (strcmp(field, "dropped events") == 0) {
			tstat->dropped_events = strtoull(value, NULL, 0);

		} else if (strcmp(field, "read events") == 0) {
			tstat->read_events = strtoull(value, NULL, 0);
		}
	}
	free(buf);

	return tstat;
}

void tracefs_instance_put_stat(struct tracefs_buffer_stat *tstat)
{
	free(tstat);
}

ssize_t tracefs_buffer_stat_entries(struct tracefs_buffer_stat *tstat)
{
	return tstat->entries;
}

ssize_t tracefs_buffer_stat_overrun(struct tracefs_buffer_stat *tstat)
{
	return tstat->overrun;
}

ssize_t tracefs_buffer_stat_commit_overrun(struct tracefs_buffer_stat *tstat)
{
	return tstat->commit_overrun;
}

ssize_t tracefs_buffer_stat_bytes(struct tracefs_buffer_stat *tstat)
{
	return tstat->bytes;
}

long long tracefs_buffer_stat_event_timestamp(struct tracefs_buffer_stat *tstat)
{
	return tstat->oldest_ts;
}

long long tracefs_buffer_stat_timestamp(struct tracefs_buffer_stat *tstat)
{
	return tstat->now_ts;
}

ssize_t tracefs_buffer_stat_dropped_events(struct tracefs_buffer_stat *tstat)
{
	return tstat->dropped_events;
}

ssize_t tracefs_buffer_stat_read_events(struct tracefs_buffer_stat *tstat)
{
	return tstat->read_events;
}


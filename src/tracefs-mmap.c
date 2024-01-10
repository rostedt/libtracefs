// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include "tracefs-local.h"

struct trace_buffer_meta {
	unsigned long	entries;
	unsigned long	overrun;
	unsigned long	read;

	unsigned long	subbufs_touched;
	unsigned long	subbufs_lost;
	unsigned long	subbufs_read;

	struct {
		unsigned long	lost_events;	/* Events lost at the time of the reader swap */
		__u32		id;		/* Reader subbuf ID from 0 to nr_subbufs - 1 */
		__u32		read;		/* Number of bytes read on the reader subbuf */
	} reader;

	__u32		subbuf_size;		/* Size of each subbuf including the header */
	__u32		nr_subbufs;		/* Number of subbufs in the ring-buffer */

	__u32		meta_page_size;		/* Size of the meta-page */
	__u32		meta_struct_len;	/* Len of this struct */
};

#define TRACE_MMAP_IOCTL_GET_READER		_IO('T', 0x1)

struct trace_mmap {
	struct trace_buffer_meta	*map;
	struct kbuffer			*kbuf;
	void				*data;
	int				*data_pages;
	int				fd;
	int				last_idx;
	int				last_read;
	int				meta_len;
	int				data_len;
};

/**
 * trace_mmap - try to mmap the ring buffer
 * @fd: The file descriptor to the trace_pipe_raw file
 * @kbuf: The kbuffer to load the subbuffer to
 *
 * Will try to mmap the ring buffer if it is supported, and
 * if not, will return NULL, otherwise it returns a descriptor
 * to handle the mapping.
 */
__hidden void *trace_mmap(int fd, struct kbuffer *kbuf)
{
	struct trace_mmap *tmap;
	int page_size;
	void *meta;
	void *data;

#ifndef FORCE_MMAP_ENABLE
	return NULL;
#endif

	page_size = getpagesize();
	meta = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
	if (meta == MAP_FAILED)
		return NULL;

	tmap = calloc(1, sizeof(*tmap));
	if (!tmap) {
		munmap(meta, page_size);
		return NULL;
	}

	tmap->kbuf = kbuffer_dup(kbuf);
	if (!tmap->kbuf) {
		munmap(meta, page_size);
		free(tmap);
	}
	kbuf = tmap->kbuf;

	tmap->fd = fd;

	tmap->map = meta;
	tmap->meta_len = tmap->map->meta_page_size;

	if (tmap->meta_len > page_size) {
		munmap(meta, page_size);
		meta = mmap(NULL, tmap->meta_len, PROT_READ, MAP_SHARED, fd, 0);
		if (meta == MAP_FAILED) {
			kbuffer_free(kbuf);
			free(tmap);
			return NULL;
		}
		tmap->map = meta;
	}

	tmap->data_pages = meta + tmap->meta_len;

	tmap->data_len = tmap->map->subbuf_size * tmap->map->nr_subbufs;

	tmap->data = mmap(NULL, tmap->data_len, PROT_READ, MAP_SHARED,
			  fd, tmap->meta_len);
	if (tmap->data == MAP_FAILED) {
		munmap(meta, tmap->meta_len);
		kbuffer_free(kbuf);
		free(tmap);
		return NULL;
	}

	tmap->last_idx = tmap->map->reader.id;

	data = tmap->data + tmap->map->subbuf_size * tmap->last_idx;
	kbuffer_load_subbuffer(kbuf, data);

	/*
	 * The page could have left over data on it that was already
	 * consumed. Move the "read" forward in that case.
	 */
	if (tmap->map->reader.read) {
		int size = kbuffer_start_of_data(kbuf) + tmap->map->reader.read;
		char tmpbuf[size];
		kbuffer_read_buffer(kbuf, tmpbuf, size);
	}

	return tmap;
}

__hidden void trace_unmap(void *mapping)
{
	struct trace_mmap *tmap = mapping;

	if (!tmap)
		return;

	munmap(tmap->data, tmap->data_len);
	munmap(tmap->map, tmap->meta_len);
	kbuffer_free(tmap->kbuf);
	free(tmap);
}

static int get_reader(struct trace_mmap *tmap)
{
	return ioctl(tmap->fd, TRACE_MMAP_IOCTL_GET_READER);
}

__hidden int trace_mmap_load_subbuf(void *mapping, struct kbuffer *kbuf)
{
	struct trace_mmap *tmap = mapping;
	void *data;
	int id;

	if (!tmap)
		return -1;

	id = tmap->map->reader.id;
	data = tmap->data + tmap->map->subbuf_size * id;

	/*
	 * If kbuf doesn't point to the current sub-buffer
	 * just load it and return.
	 */
	if (data != kbuffer_subbuffer(kbuf)) {
		kbuffer_load_subbuffer(kbuf, data);
		return 1;
	}

	/*
	 * Perhaps the reader page had a write that added
	 * more data.
	 */
	kbuffer_refresh(kbuf);

	/* Are there still events to read? */
	if (kbuffer_curr_size(kbuf)) {
		/* If current is greater than what was read, refresh */
		if (kbuffer_curr_offset(kbuf) + kbuffer_curr_size(kbuf) >
		    tmap->map->reader.read) {
			if (get_reader(tmap) < 0)
				return -1;
		}
		return 1;
	}

	/* See if a new page is ready? */
	if (get_reader(tmap) < 0)
		return -1;
	id = tmap->map->reader.id;
	data = tmap->data + tmap->map->subbuf_size * id;

	/*
	 * If the sub-buffer hasn't changed, then there's no more
	 * events to read.
	 */
	if (data == kbuffer_subbuffer(kbuf))
		return 0;

	kbuffer_load_subbuffer(kbuf, data);
	return 1;
}

__hidden int trace_mmap_read(void *mapping, void *buffer)
{
	struct trace_mmap *tmap = mapping;
	struct kbuffer *kbuf;
	int ret;

	if (!tmap)
		return -1;

	kbuf = tmap->kbuf;

	ret = trace_mmap_load_subbuf(mapping, kbuf);
	/* Return for error or no more events */
	if (ret <= 0)
		return ret;

	/* Update the buffer */
	ret = kbuffer_read_buffer(kbuf, buffer, tmap->map->subbuf_size);
	if (ret <= 0)
		return ret;

	/* This needs to include the size of the meta data too */
	return ret + kbuffer_start_of_data(kbuf);
}

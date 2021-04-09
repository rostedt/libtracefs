/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#ifndef _TRACE_FS_H
#define _TRACE_FS_H

#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <traceevent/event-parse.h>

char *tracefs_get_tracing_file(const char *name);
void tracefs_put_tracing_file(char *name);

/* the returned string must *not* be freed */
const char *tracefs_tracing_dir(void);

/* ftrace instances */
struct tracefs_instance;

void tracefs_instance_free(struct tracefs_instance *instance);
struct tracefs_instance *tracefs_instance_create(const char *name);
struct tracefs_instance *tracefs_instance_alloc(const char *tracing_dir,
						const char *name);
int tracefs_instance_destroy(struct tracefs_instance *instance);
bool tracefs_instance_is_new(struct tracefs_instance *instance);
const char *tracefs_instance_get_name(struct tracefs_instance *instance);
const char *tracefs_instance_get_trace_dir(struct tracefs_instance *instance);
char *
tracefs_instance_get_file(struct tracefs_instance *instance, const char *file);
char *tracefs_instance_get_dir(struct tracefs_instance *instance);
int tracefs_instance_file_write(struct tracefs_instance *instance,
				const char *file, const char *str);
char *tracefs_instance_file_read(struct tracefs_instance *instance,
				 const char *file, int *psize);
int tracefs_instance_file_read_number(struct tracefs_instance *instance,
				      const char *file, long long *res);
int tracefs_instance_file_open(struct tracefs_instance *instance,
			       const char *file, int mode);
int tracefs_instances_walk(int (*callback)(const char *, void *), void *context);

bool tracefs_instance_exists(const char *name);
bool tracefs_file_exists(struct tracefs_instance *instance, const char *name);
bool tracefs_dir_exists(struct tracefs_instance *instance, const char *name);

int tracefs_trace_is_on(struct tracefs_instance *instance);
int tracefs_trace_on(struct tracefs_instance *instance);
int tracefs_trace_off(struct tracefs_instance *instance);
int tracefs_trace_on_fd(int fd);
int tracefs_trace_off_fd(int fd);

/**
 * tracefs_trace_on_get_fd - Get a file descriptor of "tracing_on" in given instance
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns -1 in case of an error, or a valid file descriptor to "tracing_on"
 * file for reading and writing.The returned FD must be closed with close().
 */
static inline int tracefs_trace_on_get_fd(struct tracefs_instance *instance)
{
	return tracefs_instance_file_open(instance, "tracing_on", O_RDWR);
}

/* trace print string*/
int tracefs_print_init(struct tracefs_instance *instance);
int tracefs_printf(struct tracefs_instance *instance, const char *fmt, ...);
int tracefs_vprintf(struct tracefs_instance *instance, const char *fmt, va_list ap);
void tracefs_print_close(struct tracefs_instance *instance);

/* trace write binary data*/
int tracefs_binary_init(struct tracefs_instance *instance);
int tracefs_binary_write(struct tracefs_instance *instance, void *data, int len);
void tracefs_binary_close(struct tracefs_instance *instance);

/* events */
void tracefs_list_free(char **list);
char **tracefs_event_systems(const char *tracing_dir);
char **tracefs_system_events(const char *tracing_dir, const char *system);
int tracefs_iterate_raw_events(struct tep_handle *tep,
				struct tracefs_instance *instance,
				cpu_set_t *cpus, int cpu_size,
				int (*callback)(struct tep_event *,
						struct tep_record *,
						int, void *),
				void *callback_context);

char **tracefs_tracers(const char *tracing_dir);

struct tep_handle *tracefs_local_events(const char *tracing_dir);
struct tep_handle *tracefs_local_events_system(const char *tracing_dir,
					       const char * const *sys_names);
int tracefs_fill_local_events(const char *tracing_dir,
			       struct tep_handle *tep, int *parsing_failures);

char *tracefs_get_clock(struct tracefs_instance *instance);

enum tracefs_option_id {
	TRACEFS_OPTION_INVALID = 0,
	TRACEFS_OPTION_ANNOTATE,
	TRACEFS_OPTION_BIN,
	TRACEFS_OPTION_BLK_CGNAME,
	TRACEFS_OPTION_BLK_CGROUP,
	TRACEFS_OPTION_BLK_CLASSIC,
	TRACEFS_OPTION_BLOCK,
	TRACEFS_OPTION_CONTEXT_INFO,
	TRACEFS_OPTION_DISABLE_ON_FREE,
	TRACEFS_OPTION_DISPLAY_GRAPH,
	TRACEFS_OPTION_EVENT_FORK,
	TRACEFS_OPTION_FGRAPH_ABSTIME,
	TRACEFS_OPTION_FGRAPH_CPU,
	TRACEFS_OPTION_FGRAPH_DURATION,
	TRACEFS_OPTION_FGRAPH_IRQS,
	TRACEFS_OPTION_FGRAPH_OVERHEAD,
	TRACEFS_OPTION_FGRAPH_OVERRUN,
	TRACEFS_OPTION_FGRAPH_PROC,
	TRACEFS_OPTION_FGRAPH_TAIL,
	TRACEFS_OPTION_FUNC_STACKTRACE,
	TRACEFS_OPTION_FUNCTION_FORK,
	TRACEFS_OPTION_FUNCTION_TRACE,
	TRACEFS_OPTION_GRAPH_TIME,
	TRACEFS_OPTION_HEX,
	TRACEFS_OPTION_IRQ_INFO,
	TRACEFS_OPTION_LATENCY_FORMAT,
	TRACEFS_OPTION_MARKERS,
	TRACEFS_OPTION_OVERWRITE,
	TRACEFS_OPTION_PAUSE_ON_TRACE,
	TRACEFS_OPTION_PRINTK_MSG_ONLY,
	TRACEFS_OPTION_PRINT_PARENT,
	TRACEFS_OPTION_RAW,
	TRACEFS_OPTION_RECORD_CMD,
	TRACEFS_OPTION_RECORD_TGID,
	TRACEFS_OPTION_SLEEP_TIME,
	TRACEFS_OPTION_STACKTRACE,
	TRACEFS_OPTION_SYM_ADDR,
	TRACEFS_OPTION_SYM_OFFSET,
	TRACEFS_OPTION_SYM_USEROBJ,
	TRACEFS_OPTION_TRACE_PRINTK,
	TRACEFS_OPTION_USERSTACKTRACE,
	TRACEFS_OPTION_VERBOSE,
};
#define TRACEFS_OPTION_MAX (TRACEFS_OPTION_VERBOSE + 1)

struct tracefs_options_mask {
	unsigned long long	mask;
};
void tracefs_option_set(struct tracefs_options_mask *options, enum tracefs_option_id id);
void tracefs_option_clear(struct tracefs_options_mask *options, enum tracefs_option_id id);
bool tracefs_option_is_set(struct tracefs_options_mask *options,
			   enum tracefs_option_id id);
struct tracefs_options_mask *tracefs_options_get_supported(struct tracefs_instance *instance);
bool tracefs_option_is_supported(struct tracefs_instance *instance, enum tracefs_option_id id);
struct tracefs_options_mask *tracefs_options_get_enabled(struct tracefs_instance *instance);
bool tracefs_option_is_enabled(struct tracefs_instance *instance, enum tracefs_option_id id);
int tracefs_option_enable(struct tracefs_instance *instance, enum tracefs_option_id id);
int tracefs_option_diasble(struct tracefs_instance *instance, enum tracefs_option_id id);
const char *tracefs_option_name(enum tracefs_option_id id);
enum tracefs_option_id tracefs_option_id(const char *name);

/*
 * RESET	- Reset on opening filter file (O_TRUNC)
 * CONTINUE	- Do not close filter file on return.
 * FUTURE	- For kernels that support this feature, enable filters for
 *		  a module that has yet to be loaded.
 */
enum {
	TRACEFS_FL_RESET	= (1 << 0),
	TRACEFS_FL_CONTINUE	= (1 << 1),
	TRACEFS_FL_FUTURE	= (1 << 2),
};

int tracefs_function_filter(struct tracefs_instance *instance, const char *filter,
			    const char *module, unsigned int flags);
int tracefs_function_notrace(struct tracefs_instance *instance, const char *filter,
			     const char *module, unsigned int flags);

#endif /* _TRACE_FS_H */

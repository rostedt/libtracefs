#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <linux/perf_event.h>

#include <tracefs.h>

static void perf_init_pe(struct perf_event_attr *pe)
{
	memset(pe, 0, sizeof(struct perf_event_attr));
	pe->type = PERF_TYPE_SOFTWARE;
	pe->sample_type = PERF_SAMPLE_CPU;
	pe->size = sizeof(struct perf_event_attr);
	pe->config = PERF_COUNT_HW_CPU_CYCLES;
	pe->disabled = 1;
	pe->exclude_kernel = 1;
	pe->freq = 1;
	pe->sample_freq = 1000;
	pe->inherit = 1;
	pe->mmap = 1;
	pe->comm = 1;
	pe->task = 1;
	pe->precise_ip = 1;
	pe->sample_id_all = 1;
	pe->read_format = PERF_FORMAT_ID |
			PERF_FORMAT_TOTAL_TIME_ENABLED|
			PERF_FORMAT_TOTAL_TIME_RUNNING;

}

static long perf_event_open(struct perf_event_attr *event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, event, pid, cpu, group_fd, flags);
}

#define MAP_SIZE (9 * getpagesize())

static struct perf_event_mmap_page *perf_mmap(int fd)
{
	struct perf_event_mmap_page *perf_mmap;

	/* associate a buffer with the file */
	perf_mmap = mmap(NULL, MAP_SIZE,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (perf_mmap == MAP_FAILED)
		return NULL;

	return perf_mmap;
}

static int perf_read_maps(int cpu, int *shift, int *mult, long long *offset)
{
	struct perf_event_attr perf_attr;
	struct perf_event_mmap_page *mpage;
	int fd;

	/* We succeed if theres' nothing to do! */
	if (!shift && !mult && !offset)
		return 0;

	perf_init_pe(&perf_attr);
	fd = perf_event_open(&perf_attr, getpid(), cpu, -1, 0);
	if (fd < 0)
		return -1;

	mpage = perf_mmap(fd);
	if (!mpage) {
		close(fd);
		return -1;
	}

	if (shift)
		*shift = mpage->time_shift;
	if (mult)
		*mult = mpage->time_mult;
	if (offset)
		*offset = mpage->time_offset;
	munmap(mpage, MAP_SIZE);
	return 0;
}

/**
 * tracefs_time_conversion - Find how the kernel converts the raw counters
 * @cpu: The CPU to check for
 * @shift: If non-NULL it will be set to the shift value
 * @mult: If non-NULL it will be set to the multiplier value
 * @offset: If non-NULL it will be set to the offset
 */
int tracefs_time_conversion(int cpu, int *shift, int *mult, long long *offset)
{
	return perf_read_maps(cpu, shift, mult, offset);
}

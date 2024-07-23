#include <stdlib.h>
#include <ctype.h>
#include <tracefs.h>

static void read_subbuf(struct tep_handle *tep, struct kbuffer *kbuf)
{
	static struct trace_seq seq;
	struct tep_record record;
	int missed_events;

	if (seq.buffer)
		trace_seq_reset(&seq);
	else
		trace_seq_init(&seq);

	while ((record.data = kbuffer_read_event(kbuf, &record.ts))) {
		record.size = kbuffer_event_size(kbuf);
		missed_events = kbuffer_missed_events(kbuf);
		if (missed_events) {
			printf("[MISSED EVENTS");
			if (missed_events > 0)
				printf(": %d]\n", missed_events);
			else
				printf("]\n");
		}
		kbuffer_next_event(kbuf, NULL);
		tep_print_event(tep, &seq, &record,
				"%s-%d %6.1000d\t%s: %s\n",
				TEP_PRINT_COMM,
				TEP_PRINT_PID,
				TEP_PRINT_TIME,
				TEP_PRINT_NAME,
				TEP_PRINT_INFO);
		trace_seq_do_printf(&seq);
		trace_seq_reset(&seq);
	}
}

int main (int argc, char **argv)
{
	struct tracefs_cpu *tcpu;
	struct tep_handle *tep;
	struct kbuffer *kbuf;
	bool mapped;
	int cpu;

	if (argc < 2 || !isdigit(argv[1][0])) {
		printf("usage: %s cpu\n\n", argv[0]);
		exit(-1);
	}

	cpu = atoi(argv[1]);

	tep = tracefs_local_events(NULL);
	if (!tep) {
		perror("Reading trace event formats");
		exit(-1);
	}

	tcpu = tracefs_cpu_open_mapped(NULL, cpu, 0);
	if (!tcpu) {
		perror("Open CPU 0 file");
		exit(-1);
	}

	/*
	 * If this kernel supports mapping, use normal read,
	 * otherwise use the piped buffer read, although if
	 * the mapping succeeded, tracefs_cpu_buffered_read_buf()
	 * acts the same as tracefs_cpu_read_buf(). But this is just
	 * an example on how to use tracefs_cpu_is_mapped().
	 */
	mapped = tracefs_cpu_is_mapped(tcpu);
	if (!mapped)
		printf("Was not able to map, falling back to buffered read\n");
	while ((kbuf = mapped ? tracefs_cpu_read_buf(tcpu, true) :
			tracefs_cpu_buffered_read_buf(tcpu, true))) {
		read_subbuf(tep, kbuf);
	}

	kbuf = tracefs_cpu_flush_buf(tcpu);
	if (kbuf)
		read_subbuf(tep, kbuf);

	tracefs_cpu_close(tcpu);
	tep_free(tep);

	return 0;
}


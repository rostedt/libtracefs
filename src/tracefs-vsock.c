#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

#include <tracefs.h>

static int open_vsock(unsigned int cid, unsigned int port)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
	int sd;

	sd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sd < 0)
		return -1;

	if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)))
		return -1;

	return sd;
}

struct pids {
	struct pids		*next;
	int			pid;
};

struct trace_info {
	struct tracefs_instance		*instance;
	struct tep_handle		*tep;
	struct tep_event		*wake_up;
	struct tep_event		*kvm_exit;
	struct tep_format_field		*wake_pid;
	struct pids			*pids;
	int				pid;
};

static void tear_down_trace(struct trace_info *info)
{
	tracefs_event_disable(info->instance, NULL, NULL);
	tep_free(info->tep);
	info->tep = NULL;
}

static int add_pid(struct pids **pids, int pid)
{
	struct pids *new_pid;

	new_pid = malloc(sizeof(*new_pid));
	if (!new_pid)
		return -1;

	new_pid->pid = pid;
	new_pid->next = *pids;
	*pids = new_pid;
	return 0;
}

static bool match_pid(struct pids *pids, int pid)
{
	while (pids) {
		if (pids->pid == pid)
			return true;
		pids = pids->next;
	}
	return false;
}

static int waking_callback(struct tep_event *event, struct tep_record *record,
			   int cpu, void *data)
{
	struct trace_info *info = data;
	unsigned long long val;
	int flags;
	int pid;
	int ret;

	pid = tep_data_pid(event->tep, record);
	if (!match_pid(info->pids, pid))
		return 0;

	/* Ignore wakeups in interrupts */
	flags = tep_data_flags(event->tep, record);
	if (flags & (TRACE_FLAG_HARDIRQ | TRACE_FLAG_SOFTIRQ))
		return 0;

	if (!info->wake_pid) {
		info->wake_pid = tep_find_field(event, "pid");

		if (!info->wake_pid)
			return -1;
	}

	ret = tep_read_number_field(info->wake_pid, record->data, &val);
	if (ret < 0)
		return -1;

	return add_pid(&info->pids, (int)val);
}

static int exit_callback(struct tep_event *event, struct tep_record *record,
			 int cpu, void *data)
{
	struct trace_info *info = data;
	int pid;

	pid = tep_data_pid(event->tep, record);
	if (!match_pid(info->pids, pid))
		return 0;

	info->pid = pid;

	/* Found the pid we are looking for, stop the trace */
	return -1;
}

static int setup_trace(struct trace_info *info)
{
	const char *systems[] = { "sched", "kvm", NULL};
	int ret;

	info->pids = NULL;

	tracefs_trace_off(info->instance);
	info->tep = tracefs_local_events_system(NULL, systems);
	if (!info->tep)
		return -1;

	/*
	 * Follow the wake ups, starting with this pid, to find
	 * the one that exits to the guest. That will be the thread
	 * of the vCPU of the guest.
	 */
	ret = tracefs_follow_event(info->tep, info->instance,
				   "sched", "sched_waking",
				   waking_callback, info);
	if (ret < 0)
		goto fail;

	ret = tracefs_follow_event(info->tep, info->instance,
				   "kvm", "kvm_exit",
				   exit_callback, info);
	if (ret < 0)
		goto fail;

	ret = tracefs_event_enable(info->instance, "sched", "sched_waking");
	if (ret < 0)
		goto fail;

	ret = tracefs_event_enable(info->instance, "kvm", "kvm_exit");
	if (ret < 0)
		goto fail;

	return 0;
fail:
	tear_down_trace(info);
	return -1;
}


static void free_pids(struct pids *pids)
{
	struct pids *next;

	while (pids) {
		next = pids;
		pids = pids->next;
		free(next);
	}
}

static int find_thread_leader(int pid)
{
	FILE *fp;
	char *path;
	char *save;
	char *buf = NULL;
	size_t l = 0;
	int tgid = -1;

	if (asprintf(&path, "/proc/%d/status", pid) < 0)
		return -1;

	fp = fopen(path, "r");
	free(path);
	if (!fp)
		return -1;

	while (getline(&buf, &l, fp) > 0) {
		char *tok;

		if (strncmp(buf, "Tgid:", 5) != 0)
			continue;
		tok = strtok_r(buf, ":", &save);
		if (!tok)
			continue;
		tok = strtok_r(NULL, ":", &save);
		if (!tok)
			continue;
		while (isspace(*tok))
			tok++;
		tgid = strtol(tok, NULL, 0);
		break;
	}
	free(buf);

	return tgid > 0 ? tgid : -1;
}

int tracefs_instance_find_cid_pid(struct tracefs_instance *instance, int cid)
{
	struct trace_info info = {};
	int this_pid = getpid();
	int ret;
	int fd;

	info.instance = instance;

	if (setup_trace(&info) < 0)
		return -1;

	ret = add_pid(&info.pids, this_pid);
	if (ret < 0)
		goto out;

	tracefs_instance_file_clear(info.instance, "trace");
	tracefs_trace_on(info.instance);
	fd = open_vsock(cid, -1);
	tracefs_trace_off(info.instance);
	if (fd >= 0)
		close(fd);
	info.pid = -1;
	ret = tracefs_iterate_raw_events(info.tep, info.instance,
					 NULL, 0, NULL, &info);
	if (info.pid <= 0)
		ret = -1;
	if (ret == 0)
		ret = find_thread_leader(info.pid);

 out:
	free_pids(info.pids);
	info.pids = NULL;
	tear_down_trace(&info);

	return ret;
}

int tracefs_find_cid_pid(int cid)
{
	struct tracefs_instance *instance;
	char *name;
	int ret;

	ret = asprintf(&name, "_tracefs_vsock_find-%d\n", getpid());
	if (ret < 0)
		return ret;

	instance = tracefs_instance_create(name);
	free(name);
	if (!instance)
		return -1;

	ret = tracefs_instance_find_cid_pid(instance, cid);

	tracefs_instance_destroy(instance);
	tracefs_instance_free(instance);

	return ret;
}

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <sys/sysinfo.h>
#include <scx/common.h>
#include "scx_eevdf.bpf.skel.h"

struct load_avg {
	u64 last_update_time;
	u64 load_sum;
	u32 period_contrib;
	unsigned long load_avg;
};

struct cpu_load {
	bool migrating;
	u64 weight;
	u64 last_balance_time;
	struct task_struct *prev;
	struct load_avg avg;
};

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_eevdf *skel;
	struct bpf_link *link;

	__u64 ecode;
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(eevdf_ops, scx_eevdf);
	const u32 nr_cpu_ids = libbpf_num_possible_cpus();
	skel->rodata->nr_cpu_ids = nr_cpu_ids;
	SCX_OPS_LOAD(skel, eevdf_ops, scx_eevdf, uei);
	link = SCX_OPS_ATTACH(skel, eevdf_ops, scx_eevdf);

	const u32 idx = 0;
	struct cpu_load loads[nr_cpu_ids];
	// u64 loads[nr_cpu_ids];
	u64 vtimes[nr_cpu_ids];
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		int cpu, ret;
		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.percpu_load), &idx, loads);
		if (ret < 0)
		    continue;
		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.vtime_now), &idx, vtimes);
		if (ret < 0)
		    continue;
		for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		    printf("CPU %d:\tload = %ld\tvtime = %ld\n", cpu, loads[cpu].avg.load_avg, vtimes[cpu]);
		}
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_eevdf__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}


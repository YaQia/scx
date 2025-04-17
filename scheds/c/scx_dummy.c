#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <sys/sysinfo.h>
#include <scx/common.h>
#include "scx_dummy.bpf.skel.h"

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_dummy *skel;
	struct bpf_link *link;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	skel = SCX_OPS_OPEN(dummy_ops, scx_dummy);
	SCX_OPS_LOAD(skel, dummy_ops, scx_dummy, uei);
	link = SCX_OPS_ATTACH(skel, dummy_ops, scx_dummy);

	while (!exit_req) {
		sleep(1);
	}

	bpf_link__destroy(link);
	scx_dummy__destroy(skel);

	return 0;
}


/* SPDX-License-Identifier: GPL-2.0 */
/*
 * To be included to the main.bpf.c
 */

/*
 * Preemption related ones
 */
struct preemption_info {
	u64		stopping_tm_est_ns;
	u64		last_kick_clk;
	u64		lat_cri;
	struct cpu_ctx	*cpuc;
};

static u64 get_est_stopping_time(struct task_ctx *taskc)
{
	return bpf_ktime_get_ns() + taskc->run_time_ns;
}

static int comp_preemption_info(struct preemption_info *prm_a,
				struct preemption_info *prm_b)
{
	/*
	 * Never preeempt a lock holder.
	 */
	if (prm_b->cpuc->lock_holder)
		return 1;

	/*
	 * Check if one's latency priority _or_ deadline is smaller or not.
	 */
	if ((prm_a->lat_cri > prm_b->lat_cri) ||
	    (prm_a->stopping_tm_est_ns < prm_b->stopping_tm_est_ns))
		return -1;
	if ((prm_a->lat_cri < prm_b->lat_cri) ||
	    (prm_a->stopping_tm_est_ns > prm_b->stopping_tm_est_ns))
		return 1;
	return 0;
}

static  bool can_task1_kick_task2(struct preemption_info *prm_task1,
				  struct preemption_info *prm_task2)
{
	return comp_preemption_info(prm_task1, prm_task2) < 0;
}

static  bool can_cpu1_kick_cpu2(struct preemption_info *prm_cpu1,
				struct preemption_info *prm_cpu2,
				struct cpu_ctx *cpuc2)
{
	/*
	 * Set a CPU information
	 */
	prm_cpu2->stopping_tm_est_ns = cpuc2->stopping_tm_est_ns;
	prm_cpu2->lat_cri = cpuc2->lat_cri;
	prm_cpu2->cpuc = cpuc2;
	prm_cpu2->last_kick_clk = cpuc2->last_kick_clk;

	/*
	 * If that CPU runs a lower priority task, that's a victim
	 * candidate.
	 */
	return can_task1_kick_task2(prm_cpu1, prm_cpu2);
}

static bool is_worth_kick_other_task(struct task_ctx *taskc)
{
	/*
	 * The scx_bpf_kick_cpu() used for preemption is expensive as an IPI is
	 * involved. Hence, we first judiciously check whether it is worth
	 * trying to victimize another CPU as the current task is urgent
	 * enough.
	 */
	struct sys_stat *stat_cur = get_sys_stat_cur();

	return (taskc->lat_cri >= stat_cur->thr_lat_cri);
}

static bool can_cpu_be_kicked(u64 now, struct cpu_ctx *cpuc)
{
	return cpuc->is_online &&
	       (now - cpuc->last_kick_clk) >= LAVD_PREEMPT_KICK_MARGIN;
}

static struct cpu_ctx *find_victim_cpu(const struct cpumask *cpumask,
				       struct task_ctx *taskc,
				       u64 *p_old_last_kick_clk)
{
	/*
	 * We see preemption as a load-balancing problem. In a system with N
	 * CPUs, ideally, the top N tasks with the highest latency priorities
	 * should run on the N CPUs all the time. This is the same as the
	 * load-balancing problem; the load-balancing problem finds a least
	 * loaded server, and the preemption problem finds a CPU running a
	 * least latency critical task. Hence, we use the 'power of two random
	 * choices' technique.
	 */
	u64 now = bpf_ktime_get_ns();
	struct cpu_ctx *cpuc;
	struct preemption_info prm_task, prm_cpus[2], *victim_cpu;
	int cpu, nr_cpus;
	int i, v = 0, cur_cpu = bpf_get_smp_processor_id();
	int ret;

	/*
	 * Get task's preemption information for comparison.
	 */
	prm_task.stopping_tm_est_ns = get_est_stopping_time(taskc) +
				      LAVD_PREEMPT_KICK_MARGIN;
	prm_task.lat_cri = taskc->lat_cri;
	prm_task.cpuc = cpuc = get_cpu_ctx();
	if (!cpuc) {
		scx_bpf_error("Failed to lookup the current cpu_ctx");
		goto null_out;
	}
	prm_task.last_kick_clk = cpuc->last_kick_clk;

	/*
	 * First, test the current CPU since it can skip the expensive IPI.
	 */
	if (can_cpu_be_kicked(now, cpuc) &&
	    bpf_cpumask_test_cpu(cur_cpu, cpumask) &&
	    can_cpu1_kick_cpu2(&prm_task, &prm_cpus[0], cpuc)) {
		victim_cpu = &prm_task;
		goto bingo_out;
	}

	/*
	 * If the current CPU cannot be a victim, let's check if it is worth to
	 * try to kick other CPU at the expense of IPI.
	 */
	if (!is_worth_kick_other_task(taskc))
		goto null_out;

	/*
	 * Randomly find _two_ CPUs that run lower-priority tasks than @p. To
	 * traverse CPUs in a random order, we start from a random CPU ID in a
	 * random direction (left or right). The random-order traversal helps
	 * to mitigate the thundering herd problem. Otherwise, all CPUs may end
	 * up finding the same victim CPU.
	 *
	 * In the worst case, the current logic traverses _all_ CPUs. It would
	 * be too expensive to perform every task queue. We need to revisit
	 * this if the traversal cost becomes problematic.
	 */
	barrier();
	nr_cpus = bpf_cpumask_weight(cpumask);
	bpf_for(i, 0, nr_cpus) {
		/*
		 * Decide a CPU ID to examine.
		 */
		cpu = bpf_cpumask_any_distribute(cpumask);

		if (cpu >= nr_cpu_ids || cur_cpu == cpu)
			continue;

		/*
		 * Check whether that CPU is qualified to run @p.
		 */
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			goto null_out;
		}

		if (!can_cpu_be_kicked(now, cpuc))
			continue;

		/*
		 * If that CPU runs a lower priority task, that's a victim
		 * candidate.
		 */
		ret = can_cpu1_kick_cpu2(&prm_task, &prm_cpus[v], cpuc);
		if (ret == true && ++v >= 2)
			break;
	}

	/*
	 * Choose a final victim CPU.
	 */
	switch(v) {
	case 2:	/* two dandidates */
		victim_cpu = can_task1_kick_task2(&prm_cpus[0], &prm_cpus[1]) ?
				&prm_cpus[0] : &prm_cpus[1];
		goto bingo_out;
	case 1:	/* one candidate */
		victim_cpu = &prm_cpus[0];
		goto bingo_out;
	case 0:	/* no candidate */
		goto null_out;
	default:/* something wrong */
		goto null_out;
	}

bingo_out:
	taskc->victim_cpu = victim_cpu->cpuc->cpu_id;
	*p_old_last_kick_clk = victim_cpu->last_kick_clk;
	return victim_cpu->cpuc;

null_out:
	taskc->victim_cpu = (s32)LAVD_CPU_ID_NONE;
	return NULL;
}

static bool kick_cpu(struct cpu_ctx *victim_cpuc, u64 victim_last_kick_clk)
{
	/*
	 * If the current CPU is a victim, we just reset the current task's
	 * time slice as an optimization. Othewise, kick the remote CPU for
	 * preemption.
	 *
	 * Kicking the victim CPU does _not_ guarantee that task @p will run on
	 * that CPU. Enqueuing @p to the global queue is one operation, and
	 * kicking the victim is another asynchronous operation. However, it is
	 * okay because, anyway, the victim CPU will run a higher-priority task
	 * than @p.
	 */
	if (bpf_get_smp_processor_id() == victim_cpuc->cpu_id) {
		struct task_struct *tsk = bpf_get_current_task_btf();
		tsk->scx.slice = 0;
		return true;
	}

	/*
	 * Kick the remote victim CPU if it is not victimized yet by another
	 * concurrent kick task.
	 */
	bool ret = __sync_bool_compare_and_swap(&victim_cpuc->last_kick_clk,
						victim_last_kick_clk,
						bpf_ktime_get_ns());
	if (ret)
		scx_bpf_kick_cpu(victim_cpuc->cpu_id, SCX_KICK_PREEMPT);

	return ret;
}

static bool try_find_and_kick_victim_cpu(struct task_struct *p,
					 struct task_ctx *taskc,
					 struct cpu_ctx *cpuc_cur,
					 u64 dsq_id)
{
	struct bpf_cpumask *cd_cpumask, *cpumask;
	struct cpdom_ctx *cpdomc;
	struct cpu_ctx *victim_cpuc;
	u64 victim_last_kick_clk;
	bool ret = false;

	/*
	 * Prepare a cpumak so we find a victim @p's compute domain.
	 */
	cpumask = cpuc_cur->tmp_t_mask;
	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [dsq_id]);
	if (!cpdomc || !cd_cpumask || !cpumask)
		return false;

	bpf_cpumask_and(cpumask, cast_mask(cd_cpumask), p->cpus_ptr);

	/*
	 * Find a victim CPU among CPUs that run lower-priority tasks.
	 */
	victim_cpuc = find_victim_cpu(cast_mask(cpumask), taskc, &victim_last_kick_clk);

	/*
	 * If a victim CPU is chosen, preempt the victim by kicking it.
	 */
	if (victim_cpuc)
		ret = kick_cpu(victim_cpuc, victim_last_kick_clk);

	if (!ret)
		taskc->victim_cpu = (s32)LAVD_CPU_ID_NONE;

	return ret;
}

static bool try_yield_current_cpu(struct task_struct *p_run,
				  struct cpu_ctx *cpuc_run,
				  struct task_ctx *taskc_run)
{
	struct task_struct *p_wait;
	struct task_ctx *taskc_wait;
	struct preemption_info prm_run, prm_wait;
	s32 cpu_id = scx_bpf_task_cpu(p_run), wait_vtm_cpu_id;
	bool ret = false;

	/*
	 * If a task holds a lock, never yield.
	 */
	if (is_lock_holder(taskc_run))
		return false;

	/*
	 * If there is a higher priority task waiting on the global rq, the
	 * current running task yield the CPU by shrinking its time slice to
	 * zero.
	 */
	prm_run.stopping_tm_est_ns = taskc_run->last_running_clk +
				     taskc_run->run_time_ns -
				     LAVD_PREEMPT_TICK_MARGIN;
	prm_run.lat_cri = taskc_run->lat_cri;

	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p_wait, cpuc_run->cpdom_id, 0) {
		taskc_wait = get_task_ctx(p_wait);
		if (!taskc_wait)
			break;

		wait_vtm_cpu_id = taskc_wait->victim_cpu;
		if (wait_vtm_cpu_id != (s32)LAVD_CPU_ID_NONE)
			break;

		prm_wait.stopping_tm_est_ns = get_est_stopping_time(taskc_wait);
		prm_wait.lat_cri = taskc_wait->lat_cri;

		if (can_task1_kick_task2(&prm_wait, &prm_run)) {
			/*
			 * The atomic CAS guarantees only one task yield its
			 * CPU for the waiting task.
			 */
			ret = __sync_bool_compare_and_swap(
					&taskc_wait->victim_cpu,
					(s32)LAVD_CPU_ID_NONE, cpu_id);
			if (ret)
				p_run->scx.slice = 0;
		}

		/*
		 * Test only the first entry on the DSQ.
		 */
		break;
	}
	bpf_rcu_read_unlock();

	return ret;
}



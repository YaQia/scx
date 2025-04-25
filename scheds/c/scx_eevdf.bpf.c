#include "scx_eevdf.h"

#define BALANCE_LOAD_THRESH         10
#define BALANCE_INTERVAL_NS         2000000
#define BALANCE_PREV_INTERVAL_NS    10000000
#define LC_APP_SLICE_THRESH         100000
#define LC_APP_LOAD_THRESH          10
#define DEFAULT_SLICE_NS            1000000
char _license[] SEC("license") = "GPL";

const volatile u32 nr_cpu_ids = 1;

UEI_DEFINE(uei);
// use percpu is not flexible enought, we can't update cpu_load of other CPUs
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_load);
} percpu_load SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} vtime_now SEC(".maps");

static u64 decay_load(u64 val, u64 n)
{
	u32 local_n;
 
	if (unlikely(n > LOAD_AVG_PERIOD * 63))                              /* 1 */
		return 0;
 
	/* after bounds checking we can collapse to 32-bit */
	local_n = (u32)n;
 
	/*
	 * As y^PERIOD = 1/2, we can combine
	 *    y^n = 1/2^(n/PERIOD) * y^(n%PERIOD)
	 * With a look-up table which covers y^n (n<PERIOD)
	 *
	 * To achieve constant time decay_load.
	 */
	if (unlikely(local_n >= LOAD_AVG_PERIOD)) {                           /* 2 */
		val >>= local_n / LOAD_AVG_PERIOD;
	}
    local_n %= LOAD_AVG_PERIOD;
 
	val = mul_u64_u32_shr(val, runnable_avg_yN_inv[local_n], 32);         /* 2 */
	return val;
}

static u32 __accumulate_pelt_segments(u64 periods, u32 d1, u32 d3)
{
	u32 c1, c2, c3 = d3; /* y^0 == 1 */

	/*
	 * c1 = d1 y^p
	 */
	c1 = decay_load((u64)d1, periods);

	/*
	 *            p-1
	 * c2 = 1024 \Sum y^n
	 *            n=1
	 *
	 *              inf        inf
	 *    = 1024 ( \Sum y^n - \Sum y^n - y^0 )
	 *              n=0        n=p
	 */
	c2 = LOAD_AVG_MAX - decay_load(LOAD_AVG_MAX, periods) - 1024;

	return c1 + c2 + c3;
}

static __always_inline u32
accumulate_sum(u64 delta, struct load_avg *la, u64 load)
{
	u32 contrib = (u32)delta; /* p == 0 -> delta < 1024 */
	u64 periods;

	delta += la->period_contrib;

	periods = delta / 1024; /* A period is 1024us (~1ms) */
	/*
	 * Step 1: decay old *_sum if we crossed period boundaries.
	 */
	if (periods) {
		la->load_sum = decay_load(la->load_sum, periods);

		/*
		 * Step 2
		 */
		delta %= 1024;
		if (load) {
			/*
			 * This relies on the:
			 *
			 * if (!load)
			 *	runnable = running = 0;
			 *
			 * clause from ___update_load_sum(); this results in
			 * the below usage of @contrib to disappear entirely,
			 * so no point in calculating it.
			 */
			contrib = __accumulate_pelt_segments(periods,
					1024 - la->period_contrib, delta);
		}
	}
	la->period_contrib = delta;

	if (load)
		la->load_sum += load * contrib;

	return periods;
}

static __always_inline s32
___update_load_sum(u64 now, struct load_avg *la, u64 load)
{
	u64 delta;

	delta = now - la->last_update_time;
	/*
	 * This should only happen when time goes backwards, which it
	 * unfortunately does during sched clock init when we swap over to TSC.
	 */
	if ((s64)delta < 0) {
		la->last_update_time = now;
		return 0;
	}

	/*
	 * Use 1024ns as the unit of measurement since it's a reasonable
	 * approximation of 1us and fast to compute.
	 */
	delta >>= 10;
	if (!delta)
		return 0;

	la->last_update_time += delta << 10;

	/*
	 * Now we know we crossed measurement unit boundaries. The *_avg
	 * accrues by two steps:
	 *
	 * Step 1: accumulate *_sum since last_update_time. If we haven't
	 * crossed period boundaries, finish.
	 */
	if (!accumulate_sum(delta, la, load))
		return 0;

	return 1;
}

static __always_inline void
___update_load_avg(struct load_avg *la, unsigned long load)
{
	u32 divider = get_pelt_divider(la);

	/*
	 * Step 2: update *_avg.
	 */
	la->load_avg = (load * la->load_sum) / divider;
}

int __update_load_avg_p(u64 now, struct task_ctx *p_ctx)
{
    if (unlikely(!p_ctx)) {
        return 0;
    }
	if (___update_load_sum(now, &p_ctx->avg, p_ctx->runnable)) {
		___update_load_avg(&p_ctx->avg, p_ctx->weight);
		return 1;
	}
	return 0;
}

int __update_load_avg_cpu(u64 now, struct cpu_load *cpu_load)
{
    if (unlikely(!cpu_load)) {
        return 0;
    }
	if (___update_load_sum(now, &cpu_load->avg, cpu_load->weight)) {
		___update_load_avg(&cpu_load->avg, 1);
		return 1;
	}

	return 0;
}

static inline void
enqueue_load_avg(struct cpu_load *cpu_load, struct task_ctx *p_ctx)
{
	cpu_load->avg.load_avg += p_ctx->avg.load_avg;
	cpu_load->avg.load_sum += p_ctx->weight * p_ctx->avg.load_sum;
}

static inline void
dequeue_load_avg(struct cpu_load *cpu_load, struct task_ctx *p_ctx)
{
	sub_positive(&cpu_load->avg.load_avg, p_ctx->avg.load_avg);
	sub_positive(&cpu_load->avg.load_sum, p_ctx->weight * p_ctx->avg.load_sum);
	/* See update_cfs_rq_load_avg() */
	cpu_load->avg.load_sum = cpu_load->avg.load_sum >= cpu_load->avg.load_avg * PELT_MIN_DIVIDER 
                       ? cpu_load->avg.load_sum : cpu_load->avg.load_avg * PELT_MIN_DIVIDER;
}

static void attach_entity_load_avg(struct cpu_load *cpu_load, struct task_ctx *p_ctx)
{
	/*
	 * cfs_rq->avg.period_contrib can be used for both cfs_rq and se.
	 * See ___update_load_avg() for details.
	 */
	u32 divider = get_pelt_divider(&cpu_load->avg);

	/*
	 * When we attach the @se to the @cfs_rq, we must align the decay
	 * window because without that, really weird and wonderful things can
	 * happen.
	 *
	 * XXX illustrate
	 */
	p_ctx->avg.last_update_time = cpu_load->avg.last_update_time;
	p_ctx->avg.period_contrib = cpu_load->avg.period_contrib;

	p_ctx->avg.load_sum = p_ctx->avg.load_avg * divider;
	if (p_ctx->weight < p_ctx->avg.load_sum)
		p_ctx->avg.load_sum = p_ctx->avg.load_sum / p_ctx->weight;
	else
		p_ctx->avg.load_sum = 1;

	enqueue_load_avg(cpu_load, p_ctx);
}

static void detach_entity_load_avg(struct cpu_load *cpu_load, struct task_ctx *p_load)
{
	dequeue_load_avg(cpu_load, p_load);
    // reset last_update_time here.
    p_load->avg.last_update_time = 0;
}

static inline void update_load_avg(struct cpu_load *cpu_load, struct task_ctx *p_ctx, s32 flags)
{
    if (unlikely(!p_ctx || !cpu_load)) {
        return;
    }

    // this might be strange, but better than using `vtime_now`
    u64 now = scx_bpf_now();

    if (p_ctx->avg.last_update_time)
        __update_load_avg_p(now, p_ctx);

    __update_load_avg_cpu(now, cpu_load);
    if (!p_ctx->avg.last_update_time && (flags & DO_ATTACH)) {
        /*
		 * DO_ATTACH means we're here from enqueue_task_scx().
		 * !last_update_time means the task been detached or
         * is not runnable before.
		 *
		 * IOW we're enqueueing a task on a new CPU.
		 */
        attach_entity_load_avg(cpu_load, p_ctx);
    } else if (flags & DO_DETACH) {
        detach_entity_load_avg(cpu_load, p_ctx);
    }
}

static inline bool vtime_before(u64 a, u64 b)
{
    return (s64)(a - b) < 0;
}

static s32 get_affine_cpu(struct task_struct *p, s32 prev_cpu, bool *idle, u64 wake_flags)
{
    const s32 this_cpu = bpf_get_smp_processor_id();
    s32 cpu = this_cpu;
    *idle = false;
    if (wake_flags & WF_TTWU && (wake_flags & WF_CURRENT_CPU) &&
        bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
        return cpu;
    }
    const struct cpumask *idle_cpumask = scx_bpf_get_idle_cpumask();
    
    if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr) 
        && bpf_cpumask_test_cpu(cpu, idle_cpumask)) {
        if (bpf_cpumask_test_cpu(prev_cpu, idle_cpumask))
            cpu = prev_cpu;

        scx_bpf_put_cpumask(idle_cpumask);
        goto has_idle;
    }
    const struct rq *this_rq = scx_bpf_cpu_rq(this_cpu);
    if (!this_rq) {
        scx_bpf_put_cpumask(idle_cpumask);
        scx_bpf_error("can not get rq.");
        return -1;
    }
    const struct task_struct *current = this_rq->curr;
    if (!current) {
        scx_bpf_put_cpumask(idle_cpumask);
        scx_bpf_error("current is NULL (impossible).");
        return -1;
    }
    // Current rq only has waker running
    if (bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr)
        && (wake_flags & SCX_WAKE_SYNC) 
        && this_rq->nr_running <= 1) {
        scx_bpf_put_cpumask(idle_cpumask);
        cpu = this_cpu;
        goto has_idle;
    }
    // if prev_cpu is idle, use it
    if (bpf_cpumask_test_cpu(prev_cpu, idle_cpumask)) {
        scx_bpf_put_cpumask(idle_cpumask);
        cpu = prev_cpu;
        goto has_idle;
    }
    scx_bpf_put_cpumask(idle_cpumask);
    cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0) {
        goto has_idle;
    }
    // Need some SMT logic here.
    // The test VM has no SMT, so it should be fine.
    const struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (unlikely(!p_ctx)) {
        scx_bpf_error("task load can not be referenced.");
        return -1;
    }
    const struct rq *prev_rq = scx_bpf_cpu_rq(prev_cpu);
    if (unlikely(!prev_rq)) {
        scx_bpf_error("cpu rq can not be referenced.");
        return -1;
    }
    const u32 idx = 0;
    const struct cpu_load *prev_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, prev_cpu);
    if (unlikely(!prev_load)) {
        scx_bpf_error("previous CPU's percpu_load can not be referenced.");
        return -1;
    }
    const struct cpu_load *this_load = bpf_map_lookup_elem(&percpu_load, &idx);
    if (unlikely(!this_load)) {
        scx_bpf_error("previous CPU's percpu_load can not be referenced.");
        return -1;
    }
    // u64 prev_eff_load;
    // prev_eff_load = prev_load->avg.load_avg * prev_rq->cpu_capacity;
    // if (p_ctx->avg.last_update_time == 0) {
    //     // p is migrating. So we don't need to subtract its load.
    //     prev_eff_load = prev_load->avg.load_avg * prev_rq->cpu_capacity;
    // } else {
    //     prev_eff_load = (prev_load->avg.load_avg - p_load_avg) * prev_rq->cpu_capacity;
    // }
    // struct cpu_load *min_load;
    // u64 min_eff_load;
    // s32 min_load_cpu;
    // const struct rq *min_rq = prev_rq;
    // min_load = prev_load;
    // min_eff_load = prev_eff_load;
    // min_load_cpu = prev_cpu;
    // bpf_for(cpu, 0, nr_cpu_ids) {
    //     if (cpu == prev_cpu || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
    //         continue;
    //     struct cpu_load *this_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    //     if (unlikely(!this_load)) {
    //         scx_bpf_error("percpu_load can not be referenced.");
    //         return -1;
    //     }
    //     const struct rq *this_rq = scx_bpf_cpu_rq(cpu);
    //     if (unlikely(!this_rq)) {
    //         scx_bpf_error("cpu rq can not be referenced.");
    //         return -1;
    //     }
    //     const u64 this_eff_load = this_load->avg.load_avg * this_rq->cpu_capacity;
    //     if (idle_cpu(cpu)) {
    //         if (__sync_val_compare_and_swap(&this_load->selecting, 0, 1) != 0)
    //             continue;
    //         if (min_load_cpu != prev_cpu) {
    //             __sync_lock_test_and_set(&min_load->selecting, 0);
    //         }
    //         min_load = this_load;
    //         min_eff_load = this_eff_load;
    //         min_load_cpu = cpu;
    //         min_rq = this_rq;
    //         break;
    //     } else if (this_eff_load < min_eff_load) {
    //         if (__sync_val_compare_and_swap(&this_load->selecting, 0, 1) != 0)
    //             continue;
    //         if (min_load_cpu != prev_cpu) {
    //             __sync_lock_test_and_set(&min_load->selecting, 0);
    //         }
    //         min_load = this_load;
    //         min_eff_load = this_eff_load;
    //         min_load_cpu = cpu;
    //         min_rq = this_rq;
    //     }
    // }

    // if min_eff_load is not full, we should consider load balance.
    const u64 p_load_avg = p_ctx->avg.load_avg;
    // If p is migrating, we don't need to subtract its load.
    u64 prev_eff_load = (prev_load->avg.load_avg - p_load_avg) * prev_rq->cpu_capacity;
    u64 this_eff_load = (this_load->avg.load_avg + p_load_avg) * this_rq->cpu_capacity;
    if ((wake_flags & WF_SYNC) && !(this_rq->curr->flags & PF_EXITING)) {
        const u64 current_load = this_rq->curr->scx.weight;
        if (this_eff_load < current_load) {
            return this_cpu;
        }
        this_eff_load -= current_load;
    }
    if (this_eff_load < prev_eff_load) {
	    return this_cpu;
    } else {
	    return prev_cpu;
    }
has_idle:
    *idle = true;
    return cpu;
}

s32 BPF_STRUCT_OPS(eevdf_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu = -1;
    bool is_idle = false;
    cpu = get_affine_cpu(p, prev_cpu, &is_idle, wake_flags);
    if (is_idle) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, DEFAULT_SLICE_NS, 0);
    }
    return cpu;
}

void BPF_STRUCT_OPS(eevdf_enqueue, struct task_struct *p, u64 enq_flags)
{
    const s32 cpu = scx_bpf_task_cpu(p);
    const u32 idx = 0;
    u64 vtime = p->scx.dsq_vtime;
    struct cpu_load *cpu_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    if (unlikely(!cpu_load)) {
        scx_bpf_error("can not get cpu load.");
        return ;
    }
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (unlikely(!p_ctx)) {
        scx_bpf_error("[enqueue]: can not get task load.");
        return ;
    }
    if (task_on_rq_migrating(p)) {
        update_load_avg(cpu_load, p_ctx, DO_ATTACH);
        __sync_fetch_and_add(&cpu_load->weight, p_ctx->weight);

        u64 *cpu_vtime_now = bpf_map_lookup_percpu_elem(&vtime_now, &idx, cpu);
        if (unlikely(!cpu_vtime_now)) {
            scx_bpf_error("target CPU's vtime_now can not be referenced.");
            return ;
        }
        if (p_ctx->avg.load_avg < LC_APP_LOAD_THRESH) {
            vtime += *cpu_vtime_now - DEFAULT_SLICE_NS;
        } else {
            vtime += *cpu_vtime_now;
        }
        // vtime += *cpu_vtime_now - DEFAULT_SLICE_NS;
    } else {
        update_load_avg(cpu_load, p_ctx, 0);
    }
    p_ctx->enq_flags = enq_flags;
    // this will update p->scx.dsq_vtime into vtime, don't worry.
    scx_bpf_dsq_insert_vtime(p, cpu, DEFAULT_SLICE_NS, vtime, enq_flags);
}

void BPF_STRUCT_OPS(eevdf_dequeue, struct task_struct *p, u64 deq_flags)
{
    const s32 cpu = scx_bpf_task_cpu(p);
    const u32 idx = 0;
    struct cpu_load *cpu_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    if (unlikely(!cpu_load)) {
        scx_bpf_error("can not get cpu load.");
        return ;
    }
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (unlikely(!p_ctx)) {
        scx_bpf_error("[dequeue]: can not get task load.");
        return ;
    }
    if (task_on_rq_migrating(p)) {
        update_load_avg(cpu_load, p_ctx, DO_DETACH);
        sub_positive(&cpu_load->weight, p_ctx->weight);
        u64 *cpu_vtime_now = bpf_map_lookup_percpu_elem(&vtime_now, &idx, cpu);
        if (unlikely(!cpu_vtime_now)) {
            scx_bpf_error("target CPU's vtime_now can not be referenced.");
            return ;
        }
        sub_positive(&p->scx.dsq_vtime, *cpu_vtime_now);
    } else {
        update_load_avg(cpu_load, p_ctx, 0);
    }
}

/**
 * We should maintain vtime and cpu_load when consume tasks from the other CPU,
 * because `scx_bpf_dsq_move_vtime` will not trigger runnable state to be changed.
 */
void BPF_STRUCT_OPS(eevdf_dispatch, s32 cpu, struct task_struct *prev)
{
    if (scx_bpf_dsq_move_to_local(cpu)) {
        return ;
    }
    const u32 idx = 0;
    struct cpu_load *this_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    if (unlikely(!this_load)) {
        scx_bpf_error("this_load can not be referenced.");
        return ;
    }
    const u64 now = scx_bpf_now();
    if (unlikely(nr_cpu_ids == 1)) {
        goto run_prev_again;
    }
 //    const u64 now = scx_bpf_now();
 //    if (now - this_load->last_balance_time < BALANCE_INTERVAL_NS) {
 //        goto run_prev_again;
 //    }
 //    const struct cpumask *idle_mask = scx_bpf_get_idle_cpumask();
 //    const struct cpumask *online_mask = scx_bpf_get_online_cpumask();
 //    struct bpf_cpumask *notidle_mask = bpf_cpumask_create();
 //    if (!notidle_mask) {
 //        scx_bpf_put_cpumask(idle_mask);
 //        scx_bpf_put_cpumask(online_mask);
 //        scx_bpf_error("can not allocate a cpumask.");
 //        return ;
 //    }
 //    bpf_cpumask_xor(notidle_mask, online_mask, idle_mask);
 //    s32 target_cpu = bpf_cpumask_any_and_distribute(cast_mask(notidle_mask), online_mask);
 //    if (target_cpu == cpu || target_cpu >= nr_cpu_ids) {
 //        scx_bpf_put_cpumask(idle_mask);
 //        scx_bpf_put_cpumask(online_mask);
 //        bpf_cpumask_release(notidle_mask);
 //        goto run_prev_again;
 //    }
 //    scx_bpf_put_cpumask(idle_mask);
 //    scx_bpf_put_cpumask(online_mask);
 //    bpf_cpumask_release(notidle_mask);
	// struct cpu_load *target_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, target_cpu);
	// if (unlikely(!target_load)) {
	//     scx_bpf_error("target_load can not be referenced.");
 //        return ;
	// }
 //    if (!scx_bpf_dsq_nr_queued(target_cpu)) {
 //        goto run_prev_again;
 //    }

    if (now - this_load->last_balance_time < BALANCE_INTERVAL_NS) {
        goto run_prev_again;
    }
    this_load->last_balance_time = now;
    struct cpu_load *max_load = this_load;
    s32 max_load_cpu = cpu;
    s32 i;
	bpf_for(i, 0, nr_cpu_ids) {
	    if (i == cpu || !scx_bpf_dsq_nr_queued(i))
	        continue;

	    struct cpu_load *i_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, i);
	    if (unlikely(!i_load)) {
	        scx_bpf_error("i_load can not be referenced.");
	        return ;
	    }
        
	    if (i_load->avg.load_avg > max_load->avg.load_avg) {
            if (__sync_val_compare_and_swap(&this_load->selecting, 0, 1) != 0)
                continue;
            if (max_load_cpu != cpu) {
                __sync_lock_test_and_set(&max_load->selecting, 0);
            }
            max_load = i_load;
            max_load_cpu = i;
	    }
    }
    // This means all CPUs have at most 1 task now. Skip the pull.
	if (max_load_cpu == cpu || !scx_bpf_dsq_nr_queued(max_load_cpu)
        || max_load->avg.load_avg < this_load->avg.load_avg + BALANCE_LOAD_THRESH) {
        __sync_lock_test_and_set(&max_load->selecting, 0);
        goto run_prev_again;
    }
    s32 target_cpu = max_load_cpu;
    struct cpu_load *target_load = max_load;

    const u64 *vtime_now_prev = bpf_map_lookup_percpu_elem(&vtime_now, &idx, target_cpu);
    if (unlikely(!vtime_now_prev)) {
        scx_bpf_error("vtime_now_prev can not be referenced.");
        return ;
    }
    const struct rq *this_rq = scx_bpf_cpu_rq(cpu);
    if (unlikely(!this_rq)) {
        scx_bpf_error("failed to read rq of cpu.");
        return ;
    }
    const struct rq *target_rq = scx_bpf_cpu_rq(target_cpu);
    if (unlikely(!target_rq)) {
        scx_bpf_error("failed to read rq of target.");
        return ;
    }
	struct bpf_iter_scx_dsq iter;
	if (unlikely(bpf_iter_scx_dsq_new(&iter, target_cpu, SCX_DSQ_ITER_REV) < 0)) {
	    scx_bpf_error("failed to start dsq iteration");
	    bpf_iter_scx_dsq_destroy(&iter);
	    return ;
	}

	struct task_struct *p;
	while ((p = bpf_iter_scx_dsq_next(&iter))) {
        // skip if the task can not run in this cpu
        if (p->nr_cpus_allowed == 1 || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
            continue;
        }

        if (p->scx.dsq_vtime < *vtime_now_prev) {
            break;
        }
        struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
        if (unlikely(!p_ctx)) {
            scx_bpf_error("task load can not be referenced.");
            bpf_iter_scx_dsq_destroy(&iter);
            return ;
        }
        const u64 p_load_avg = p_ctx->avg.load_avg;
        const u64 target_eff_load = (target_load->avg.load_avg - p_load_avg) * target_rq->cpu_capacity;
        const u64 this_eff_load = (this_load->avg.load_avg + p_load_avg) * this_rq->cpu_capacity;
        // task is still hot
        if ((target_load->prev == p/*  && now - p_ctx->last_balance_time < BALANCE_PREV_INTERVAL_NS */)
            || target_eff_load < this_eff_load
            || p_ctx->avg.load_avg < LC_APP_LOAD_THRESH) {
            continue;
        }
        if (unlikely(!__COMPAT_scx_bpf_dsq_move(&iter, p, SCX_DSQ_LOCAL_ON | cpu, p_ctx->enq_flags)))
            continue;

        p_ctx->last_balance_time = now;
        this_load->last_balance_time = now;
        const u64 *vtime_now_curr = bpf_map_lookup_percpu_elem(&vtime_now, &idx, cpu);
        if (unlikely(!vtime_now_curr)) {
            scx_bpf_error("vtime_now_curr can not be referenced.");
            bpf_iter_scx_dsq_destroy(&iter);
            return ;
        }

        u64 vtime = p->scx.dsq_vtime;
        sub_positive(&vtime, *vtime_now_prev);
        vtime += *vtime_now_curr - DEFAULT_SLICE_NS;
        p->scx.dsq_vtime = vtime;
        update_load_avg(target_load, p_ctx, DO_DETACH);
        sub_positive(&target_load->weight, p_ctx->weight);
        update_load_avg(this_load, p_ctx, DO_ATTACH);
        __sync_fetch_and_add(&this_load->weight, p_ctx->weight);
        // if (unlikely(!scx_bpf_dsq_move_to_local(cpu))) {
        //     update_load_avg(this_load, p_ctx, DO_DETACH);
        //     sub_positive(&this_load->weight, p_ctx->weight);
        // }
        bpf_iter_scx_dsq_destroy(&iter);
        __sync_lock_test_and_set(&max_load->selecting, 0);
        return ;
	}
	bpf_iter_scx_dsq_destroy(&iter);
    __sync_lock_test_and_set(&max_load->selecting, 0);
run_prev_again:
    if (prev && prev->scx.flags & SCX_TASK_QUEUED) {
        prev->scx.slice = now - this_load->last_balance_time;
    }
}

void BPF_STRUCT_OPS(eevdf_runnable, struct task_struct *p, u64 enq_flags)
{
    const u32 idx = 0;
    const s32 cpu = scx_bpf_task_cpu(p);

    struct cpu_load *cpu_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    if (unlikely(!cpu_load)) {
        scx_bpf_error("can not get cpu load.");
        return ;
    }
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (unlikely(!p_ctx)) {
        scx_bpf_error("[runnable]: can not get task load.");
        return ;
    }
    // Not always attaching, only the task on a new CPU will do it.
    // See `update_load_avg` DO_ATTACH comment.
    update_load_avg(cpu_load, p_ctx, DO_ATTACH);
    __sync_fetch_and_add(&cpu_load->weight, p_ctx->weight);

    u64 *cpu_vtime_now = bpf_map_lookup_percpu_elem(&vtime_now, &idx, cpu);
    if (unlikely(!cpu_vtime_now)) {
        scx_bpf_error("target CPU's vtime_now can not be referenced.");
        return ;
    }

    if (p_ctx->avg.load_avg < LC_APP_LOAD_THRESH) {
        p->scx.dsq_vtime += *cpu_vtime_now - SCX_SLICE_DFL;
    } else {
        p->scx.dsq_vtime += *cpu_vtime_now;
    }
    // p->scx.dsq_vtime += *cpu_vtime_now - DEFAULT_SLICE_NS;

    p_ctx->runnable = true;
}

void BPF_STRUCT_OPS(eevdf_running, struct task_struct *p)
{
    const u32 idx = 0;
    u64 *vtime_now_local = bpf_map_lookup_elem(&vtime_now, &idx);
    if (unlikely(!vtime_now_local)) {
        scx_bpf_error("vimte_now_local can not be referenced.");
        return ;
    }
    if (vtime_before(*vtime_now_local, p->scx.dsq_vtime))
        *vtime_now_local = p->scx.dsq_vtime;
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!p_ctx) {
        scx_bpf_error("task_ctx can not be referenced.");
        return ;
    }
    p_ctx->running_at = scx_bpf_now();
    // force the slice to be DEFAULT_SLICE_NS
    // if (unlikely(p->scx.slice > DEFAULT_SLICE_NS)) {
    //     p->scx.slice = DEFAULT_SLICE_NS;
    // }
}

void BPF_STRUCT_OPS(eevdf_stopping, struct task_struct *p, bool runnable)
{
    const u32 idx = 0;
    struct cpu_load *cpu_load = bpf_map_lookup_elem(&percpu_load, &idx);
    if (unlikely(!cpu_load)) {
        scx_bpf_error("can not get cpu load.");
        return ;
    }
    cpu_load->prev = p;
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!p_ctx) {
        scx_bpf_error("task_ctx can not be referenced.");
        return ;
    }
    u64 duration = scx_bpf_now() - p_ctx->running_at;
    // if (DEFAULT_SLICE_NS > p->scx.slice)
    //     duration = DEFAULT_SLICE_NS - p->scx.slice;
    // else
    //     duration = 0;
    p->scx.dsq_vtime += duration * 100 / p->scx.weight;
    u64 *vtime_now_local = bpf_map_lookup_elem(&vtime_now, &idx);
    if (unlikely(!vtime_now_local)) {
        scx_bpf_error("vimte_now_local can not be referenced.");
        return ;
    }
    if (vtime_before(*vtime_now_local, p->scx.dsq_vtime))
        *vtime_now_local = p->scx.dsq_vtime;
}

// Unlike ops.dequeue(), this function below will only be called when dequeue_task_scx().
void BPF_STRUCT_OPS(eevdf_quiescent, struct task_struct *p, u64 deq_flags)
{
    const u32 idx = 0;
    const u32 cpu = scx_bpf_task_cpu(p);
    struct cpu_load *cpu_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    if (unlikely(!cpu_load)) {
        scx_bpf_error("can not get cpu load.");
        return ;
    }
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (unlikely(!p_ctx)) {
        scx_bpf_error("[quiescent]: can not get task load.");
        return ;
    }
    // IMPORTANT: Don't detach it! Slept task should not be detached at all!
    update_load_avg(cpu_load, p_ctx, 0);
    sub_positive(&cpu_load->weight, p_ctx->weight);
    u64 *cpu_vtime_now = bpf_map_lookup_percpu_elem(&vtime_now, &idx, cpu);
    if (unlikely(!cpu_vtime_now)) {
        scx_bpf_error("target CPU's vtime_now can not be referenced.");
        return ;
    }
    sub_positive(&p->scx.dsq_vtime, *cpu_vtime_now);
    p_ctx->runnable = false;
}

void BPF_STRUCT_OPS(eevdf_set_weight, struct task_struct *p, u32 weight)
{
    const u32 idx = 0;
    const s32 cpu = scx_bpf_task_cpu(p);
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!p_ctx) {
        scx_bpf_error("can not find task load.");
        return ;
    }
    if (!p_ctx->runnable) {
        p_ctx->weight = weight;
        return ;
    }
    struct cpu_load *cpu_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    if (!cpu_load) {
        scx_bpf_error("can not find cpu load.");
        return ;
    }
    update_load_avg(cpu_load, p_ctx, 0);
    sub_positive(&cpu_load->weight, p_ctx->weight);
    dequeue_load_avg(cpu_load, p_ctx);
    p_ctx->weight = weight;
    enqueue_load_avg(cpu_load, p_ctx);
    __sync_fetch_and_add(&cpu_load->weight, p_ctx->weight);
}

void BPF_STRUCT_OPS(eevdf_enable, struct task_struct *p)
{
    struct task_ctx *p_ctx;
    if (!(p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0))) {
        scx_bpf_error("can not get task load map.");
        return ;
    }
    u64 weight = p->scx.weight;
    p_ctx->weight = weight;
    p_ctx->avg.load_avg = weight;
}

s32 BPF_STRUCT_OPS(eevdf_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
    p->scx.dsq_vtime = 0;
    p->scx.slice = DEFAULT_SLICE_NS;
    struct task_ctx *p_ctx;
    if (!(p_ctx = bpf_task_storage_get(&task_ctx, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))) {
        scx_bpf_error("can not create task load map.");
        return 1;
    }
    // struct task_ctx *pp_ctx;
    // if (!args->fork || !p->parent || !(pp_ctx = bpf_task_storage_get(&task_ctx, p->parent, 0, 0))) {
    //     u64 weight = p->scx.weight;
    //     p_ctx->weight = weight;
    //     p_ctx->avg.load_avg = weight;
    // } else {
    //     *p_ctx = *pp_ctx;
    // }
    p_ctx->runnable = false;
    p_ctx->avg.last_update_time = 0;
    p_ctx->last_balance_time = 0;
    return 0;
}

void BPF_STRUCT_OPS(eevdf_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
    const u32 idx = 0;
    const s32 cpu = scx_bpf_task_cpu(p);
    struct cpu_load *cpu_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    if (unlikely(!cpu_load)) {
        scx_bpf_error("can not get cpu load.");
        return ;
    }
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    // this is possible, ignore it.
    if (unlikely(!p_ctx)) {
        return ;
    }
    // if (unlikely(p_ctx->avg.last_update_time != 0)) {
    //     update_load_avg(cpu_load, p_ctx, DO_DETACH);
    //     sub_positive(&cpu_load->weight, p_ctx->weight);
    // }
    // if (unlikely(cpu_load->weight > 0 && scx_bpf_cpu_rq(cpu)->scx.nr_running == 0)) {
    //     __sync_lock_test_and_set(&cpu_load->weight, 0);
    // }
    // IMPORTANT: we have to delete the task_ctx here,
    // or ops.dispatch will get exited tasks to dispatch.
    bpf_task_storage_delete(&task_ctx, p);
}

void BPF_STRUCT_OPS(eevdf_tick, struct task_struct *p)
{
    // const s32 cpu = scx_bpf_task_cpu(p);
    const u32 idx = 0;
    struct cpu_load *cpu_load = bpf_map_lookup_elem(&percpu_load, &idx);
    if (!cpu_load) {
        scx_bpf_error("can not get cpu load.");
        return ;
    }
    struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!p_ctx) {
        scx_bpf_error("can not get task_ctx.");
        return ;
    }
    update_load_avg(cpu_load, p_ctx, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(eevdf_init)
{
    u32 i;
    const u32 idx = 0;
    bpf_for (i, 0, nr_cpu_ids) {
        scx_bpf_create_dsq(i, -1);
        u64 *vtime_now_local = bpf_map_lookup_percpu_elem(&vtime_now, &idx, i);
        if (unlikely(!vtime_now_local)) {
            scx_bpf_error("vtime_now_local can not be referenced.");
            return 1;
        }
        struct cpu_load *cpu_load_local = bpf_map_lookup_percpu_elem(&percpu_load, &idx, i);
        if (unlikely(!cpu_load_local)) {
            scx_bpf_error("cpu_load_local can not be referenced.");
            return 1;
        }
        *vtime_now_local = DEFAULT_SLICE_NS;
        __sync_lock_test_and_set(&cpu_load_local->selecting, 0);
        __sync_lock_test_and_set(&cpu_load_local->weight, 0);
        cpu_load_local->prev = NULL;
        cpu_load_local->avg.load_avg = 0;
        cpu_load_local->avg.load_sum = 0;
        cpu_load_local->avg.last_update_time = 0;
    }
    return 0;
}

void BPF_STRUCT_OPS(eevdf_exit, struct scx_exit_info *ei)
{
    u32 i;
    bpf_for (i, 0, nr_cpu_ids) {
        scx_bpf_destroy_dsq(i);
    }
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(eevdf_ops,
           .select_cpu      = (void *)eevdf_select_cpu,
           .enqueue         = (void *)eevdf_enqueue,
           .dequeue         = (void *)eevdf_dequeue,
           .dispatch        = (void *)eevdf_dispatch,
           .runnable        = (void *)eevdf_runnable,
           .running         = (void *)eevdf_running,
           .stopping        = (void *)eevdf_stopping,
           .quiescent       = (void *)eevdf_quiescent,
           .set_weight      = (void *)eevdf_set_weight,
           .enable          = (void *)eevdf_enable,
           .init_task       = (void *)eevdf_init_task,
           .exit_task       = (void *)eevdf_exit_task,
           .tick            = (void *)eevdf_tick,
           .init            = (void *)eevdf_init,
           .exit            = (void *)eevdf_exit,
           // .root_cgroup_path = "/",
           .name            = "eevdf");

    // cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
    // struct cpu_load *this_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
    // if (!this_load) {
    //     return -3;
    // }
    //
    // struct rq *this_rq = scx_bpf_cpu_rq(cpu);
    // struct rq *prev_rq = scx_bpf_cpu_rq(prev_cpu);
    // if (!this_rq || !prev_rq) {
    //     return -4;
    // }
    // u64 this_eff_load = this_load->load;
    // u64 prev_eff_load = prev_load->load;
    // this_eff_load += p->scx.weight;
    // prev_eff_load -= p->scx.weight;
    // this_eff_load *= this_rq->cpu_capacity;
    // prev_eff_load *= prev_rq->cpu_capacity;
    // // anyway we need to subtract p's weight of previous CPU
    // // because enqueue will add this weight again
    // prev_load->load -= p->scx.weight;
    // if (this_eff_load < prev_eff_load) {
    //     return cpu;
    // } else {
    //     return prev_cpu;
    // }
    //

	//    struct bpf_cpumask *all_but_prev_mask = bpf_cpumask_create();
	//    if (!all_but_prev_mask) {
	// scx_bpf_error("can not creat a cpumask.");
	// return -1;
	//    }
	//    bpf_cpumask_setall(all_but_prev_mask);
	//    bpf_cpumask_clear_cpu(prev_cpu, all_but_prev_mask);
	//    // select 2 random CPUs
	//    s32 tmp_cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, (struct cpumask *)all_but_prev_mask);
	//    s32 tmp_cpu2 = bpf_cpumask_any_and_distribute(p->cpus_ptr, (struct cpumask *)all_but_prev_mask);
	//    bpf_cpumask_release(all_but_prev_mask);
	//    struct cpu_load *tmp_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, tmp_cpu);
	//    struct cpu_load *tmp_load2 = bpf_map_lookup_percpu_elem(&percpu_load, &idx, tmp_cpu);
	//    if (!tmp_load || !tmp_load2) {
	// scx_bpf_error("percpu_load can not be referenced.");
	//        return -1;
	//    }
	//    struct rq *tmp_rq = scx_bpf_cpu_rq(tmp_cpu);
	//    struct rq *tmp_rq2 = scx_bpf_cpu_rq(tmp_cpu2);
	//    if (!tmp_rq || !tmp_rq2) {
	// scx_bpf_error("cpu rq can not be referenced.");
	// return -1;
	//    }
	//    struct cpu_load *this_load;
	//    if (tmp_load->load * tmp_rq->cpu_capacity > tmp_load2->load * tmp_rq2->cpu_capacity) {
	// cpu = tmp_cpu2;
	// this_load = tmp_load2;
	//    } else {
	// cpu = tmp_cpu;
	// this_load = tmp_load;
	//    }
	//
	//    struct rq *this_rq = scx_bpf_cpu_rq(cpu);
	//    struct rq *prev_rq = scx_bpf_cpu_rq(prev_cpu);
	//    if (!this_rq || !prev_rq) {
	// scx_bpf_error("cpu rq can not be referenced.");
	//        return -1;
	//    }
	//    u64 this_eff_load = this_load->load;
	//    // means it is syncing, subtract the weight of the task going to sleep.
	//    if ((wake_flags & WF_SYNC) && !(this_rq->curr->flags & PF_EXITING)) {
	// u64 current_load = this_rq->curr->scx.weight;
	// if (this_eff_load < current_load) {
	//            prev_load->load = prev_load->load >= p->scx.weight ? prev_load->load - p->scx.weight: 0;
	//     return cpu;
	// }
	// this_eff_load -= current_load;
	//    }
	//    u64 prev_eff_load = prev_load->load;
	//    this_eff_load += p->scx.weight;
	//    prev_eff_load = prev_eff_load >= p->scx.weight ? prev_eff_load - p->scx.weight: 0;
	//    this_eff_load *= this_rq->cpu_capacity;
	//    prev_eff_load *= prev_rq->cpu_capacity;
	//    // anyway we need to subtract p's weight of previous CPU
	//    // because enqueue will add this weight again
	//    prev_load->load = prev_load->load >= p->scx.weight ? prev_load->load - p->scx.weight: 0;
	//    if (this_eff_load < prev_eff_load) {
	//        return cpu;
	//    } else {
	//        return prev_cpu;
	//    }

// old dispatch logic
    // consume failed, means this CPU is idle now.
    // Try to pull other CPU's tasks.
	// s32 i, max_load_cpu = cpu;
	// const u32 idx = 0;
	// struct cpu_load *this_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, cpu);
	// if (unlikely(!this_load)) {
	//     scx_bpf_error("this_load can not be referenced.");
 //        return ;
	// }
 //    u64 now = scx_bpf_now();
 //    if (now - this_load->last_balance_time < BALANCE_INTERVAL_NS) {
 //        return ;
 //    }
 //    this_load->last_balance_time = now;
 //    struct cpu_load *max_load = this_load;
	// bpf_for(i, 0, nr_cpu_ids) {
	//     if (i == cpu)
	//         continue;
	//
	//     struct cpu_load *i_load = bpf_map_lookup_percpu_elem(&percpu_load, &idx, i);
	//     if (unlikely(!i_load)) {
	//         scx_bpf_error("i_load can not be referenced.");
	//         return ;
	//     }
	//     if (i_load->avg.load_avg > max_load->avg.load_avg) {
 //            max_load = i_load;
 //            max_load_cpu = i;
	//     }
	// }
	// This means all CPUs have at most 1 task now. Skip the pull.
	// if (max_load_cpu == cpu || !scx_bpf_dsq_nr_queued(max_load_cpu))
	//     return ;
 //    const struct rq *this_rq = scx_bpf_cpu_rq(cpu);
 //    if (unlikely(!this_rq)) {
 //        scx_bpf_error("rq can not be referenced.");
 //        return ;
 //    }
 //    const struct rq *max_load_rq = scx_bpf_cpu_rq(max_load_cpu);
 //    if (unlikely(!max_load_rq)) {
 //        scx_bpf_error("rq can not be referenced.");
 //        return ;
 //    }
	// struct bpf_iter_scx_dsq iter;
	// if (unlikely(bpf_iter_scx_dsq_new(&iter, max_load_cpu, SCX_DSQ_ITER_REV) < 0)) {
	//     scx_bpf_dump("failed to start dsq iteration");
	//     bpf_iter_scx_dsq_destroy(&iter);
	//     return ;
	// }
 //    const u64 this_load_avg = this_load->avg.load_avg;
 //    const u64 this_cpu_capacity = this_rq->cpu_capacity;
 //    const u64 max_load_avg = max_load->avg.load_avg;
 //    const u64 max_cpu_capacity = max_load_rq->cpu_capacity;
	// struct task_struct *p;
	// while ((p = bpf_iter_scx_dsq_next(&iter))) {
 //        // skip other schedulers' tasks(SCHED_DEADLINE/SCHED_FIFO/SCHED_RR)
 //        if (p->policy != SCHED_EXT && p->policy != SCHED_NORMAL) {
 //            continue;
 //        }
	//
 //        if (p->nr_cpus_allowed == 1 || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
 //            continue;
 //        }
 //        struct task_ctx *p_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
 //        if (unlikely(!p_ctx)) {
 //            scx_bpf_error("task load can not be referenced.");
 //            bpf_iter_scx_dsq_destroy(&iter);
 //            return ;
 //        }
 //        if (p_ctx->avg.load_avg < LC_APP_LOAD_THRESH) {
 //            continue;
 //        }
 //        const u64 p_load_avg = p_ctx->avg.load_avg;
 //        const u64 this_eff_load = (this_load_avg + p_load_avg) * this_cpu_capacity;
 //        const u64 max_eff_load = (max_load_avg - p_load_avg) * max_cpu_capacity;
	//     if (this_eff_load >= max_eff_load) {
 //            continue;
 //        }
 //        // We might need `enq_flags` here, but a hashmap to store the `enq_flags` for each process seems consuming.
 //        if (!scx_bpf_dsq_move_vtime(&iter, p, cpu, 0))
 //            continue;
	//
 //        const u64 *vtime_now_prev = bpf_map_lookup_percpu_elem(&vtime_now, &idx, max_load_cpu);
 //        if (unlikely(!vtime_now_prev)) {
 //            scx_bpf_error("vtime_now_prev can not be referenced.");
 //            bpf_iter_scx_dsq_destroy(&iter);
 //            return ;
 //        }
 //        const u64 *vtime_now_curr = bpf_map_lookup_percpu_elem(&vtime_now, &idx, cpu);
 //        if (unlikely(!vtime_now_curr)) {
 //            scx_bpf_error("vtime_now_curr can not be referenced.");
 //            bpf_iter_scx_dsq_destroy(&iter);
 //            return ;
 //        }
 //        u64 vtime = p->scx.dsq_vtime;
 //        sub_positive(&vtime, *vtime_now_prev);
 //        vtime += *vtime_now_curr;
 //        p->scx.dsq_vtime = vtime;
	//
 //        update_load_avg(max_load, p_ctx, DO_DETACH);
 //        max_load->weight -= p_ctx->weight;
 //        update_load_avg(this_load, p_ctx, DO_ATTACH);
 //        this_load->weight += p_ctx->weight;
 //        scx_bpf_dsq_move_to_local(cpu);
 //        break;
	// }
	// bpf_iter_scx_dsq_destroy(&iter);

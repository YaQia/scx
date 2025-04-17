#include <scx/common.bpf.h>

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

struct task_ctx {
	bool runnable;
  u64 last_balance_time;
  u64 running_at;
	u64 weight;
  u64 avg_slice;
  u64 enq_flags;
	struct load_avg avg;
};

#define for_each_domain(cpu, __sd)                                             \
  for (__sd = READ_ONCE(scx_bpf_cpu_rq(cpu)->sd); __sd; __sd = __sd->parent)

#define WF_SYNC 0x10          /* Waker goes to sleep after wakeup */
#define PF_EXITING 0x00000004 /* Getting shut down */

#define LOAD_AVG_PERIOD 32
#define LOAD_AVG_MAX 47742
static const u32 runnable_avg_yN_inv[LOAD_AVG_PERIOD] = {
    0xffffffff, 0xfa83b2da, 0xf5257d14, 0xefe4b99a, 0xeac0c6e6, 0xe5b906e6,
    0xe0ccdeeb, 0xdbfbb796, 0xd744fcc9, 0xd2a81d91, 0xce248c14, 0xc9b9bd85,
    0xc5672a10, 0xc12c4cc9, 0xbd08a39e, 0xb8fbaf46, 0xb504f333, 0xb123f581,
    0xad583ee9, 0xa9a15ab4, 0xa5fed6a9, 0xa2704302, 0x9ef5325f, 0x9b8d39b9,
    0x9837f050, 0x94f4efa8, 0x91c3d373, 0x8ea4398a, 0x8b95c1e3, 0x88980e80,
    0x85aac367, 0x82cd8698,
};

#define SCHED_FIXEDPOINT_SHIFT 10
#define scale_load(w) ((w) << SCHED_FIXEDPOINT_SHIFT)
#define scale_load_down(w)                                                     \
  ({                                                                           \
    u64 __w = (w);                                                             \
                                                                               \
    if (__w)                                                                   \
      __w = 2UL > __w >> SCHED_FIXEDPOINT_SHIFT                                \
                ? 2UL                                                          \
                : __w >> SCHED_FIXEDPOINT_SHIFT;                               \
    __w;                                                                       \
  })

static __always_inline u64 mul_u64_u32_shr(u64 a, u32 mul, u32 shift) {
	return (u64)((a * mul) >> shift);
}

#define PELT_MIN_DIVIDER (LOAD_AVG_MAX - 1024)

static inline u32 get_pelt_divider(struct load_avg *avg) {
	return PELT_MIN_DIVIDER + avg->period_contrib;
}

static inline u64 se_weight(struct sched_entity *se) {
	return scale_load_down(se->load.weight);
}

static inline u64 p_weight(struct task_struct *p) {
	return scale_load_down(p->se.load.weight);
}
#define DO_ATTACH 0x4
#define DO_DETACH 0x8

#define sub_positive(_ptr, _val)                                               \
  do {                                                                         \
    typeof(_ptr) ptr = (_ptr);                                                 \
    typeof(*ptr) val = (_val);                                                 \
    typeof(*ptr) res, var = READ_ONCE(*ptr);                                   \
    res = var - val;                                                           \
    if (res > var)                                                             \
      res = 0;                                                                 \
    WRITE_ONCE(*ptr, res);                                                     \
  } while (0)
#define DEQUEUE_SLEEP 0x01   /* Matches ENQUEUE_WAKEUP */
#define DEQUEUE_SAVE 0x02    /* Matches ENQUEUE_RESTORE */
#define DEQUEUE_MOVE 0x04    /* Matches ENQUEUE_MOVE */
#define DEQUEUE_NOCLOCK 0x08 /* Matches ENQUEUE_NOCLOCK */
#define DEQUEUE_SPECIAL 0x10
#define DEQUEUE_MIGRATING 0x100 /* Matches ENQUEUE_MIGRATING */
#define DEQUEUE_DELAYED 0x200   /* Matches ENQUEUE_DELAYED */

#define ENQUEUE_WAKEUP 0x01
#define ENQUEUE_RESTORE 0x02
#define ENQUEUE_MOVE 0x04
#define ENQUEUE_NOCLOCK 0x08

#define ENQUEUE_HEAD 0x10
#define ENQUEUE_REPLENISH 0x20
#define ENQUEUE_MIGRATED 0x40
#define ENQUEUE_INITIAL 0x80
#define ENQUEUE_MIGRATING 0x100
#define ENQUEUE_DELAYED 0x200
#define ENQUEUE_RQ_SELECTED 0x400

#define SCHED_NORMAL 0
#define SCHED_FIFO 1
#define SCHED_RR 2
#define SCHED_BATCH 3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE 5
#define SCHED_DEADLINE 6
#define SCHED_EXT 7

/* task_struct::on_rq states: */
#define TASK_ON_RQ_QUEUED	1
#define TASK_ON_RQ_MIGRATING	2

#define WF_EXEC			0x02 /* Wakeup after exec; maps to SD_BALANCE_EXEC */
#define WF_FORK			0x04 /* Wakeup after fork; maps to SD_BALANCE_FORK */
#define WF_TTWU			0x08 /* Wakeup;            maps to SD_BALANCE_WAKE */

#define WF_SYNC			0x10 /* Waker goes to sleep after wakeup */
#define WF_MIGRATED		0x20 /* Internal use, task got migrated */
#define WF_CURRENT_CPU		0x40 /* Prefer to move the wakee to the current CPU. */
#define WF_RQ_SELECTED		0x80 /* ->select_task_rq() was called */

static inline int task_on_rq_migrating(struct task_struct *p)
{
	return READ_ONCE(p->on_rq) == TASK_ON_RQ_MIGRATING;
}

#define ENQUEUE_MIGRATED	0x40

static inline bool task_is_runnable(struct task_struct *p)
{
	return p->on_rq && !p->se.sched_delayed;
}

#define entity_is_task(se)	(!se->my_q)

static inline long se_runnable(struct sched_entity *se)
{
	if (se->sched_delayed)
		return false;

	if (entity_is_task(se))
		return !!se->on_rq;
	else
		return se->runnable_weight;
}

int idle_cpu(int cpu)
{
	struct rq *rq = scx_bpf_cpu_rq(cpu);

	if (rq->curr != rq->idle)
		return 0;

	if (rq->nr_running)
		return 0;

	if (rq->ttwu_pending)
		return 0;

	return 1;
}


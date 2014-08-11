/* drivers/misc/lowmemorykiller.c
 *
 * The lowmemorykiller driver lets user-space specify a set of memory thresholds
 * where processes with a range of oom_score_adj values will get killed. Specify
 * the minimum oom_score_adj values in
 * /sys/module/lowmemorykiller/parameters/adj and the number of free pages in
 * /sys/module/lowmemorykiller/parameters/minfree. Both files take a comma
 * separated list of numbers in ascending order.
 *
 * For example, write "0,8" to /sys/module/lowmemorykiller/parameters/adj and
 * "1024,4096" to /sys/module/lowmemorykiller/parameters/minfree to kill
 * processes with a oom_score_adj value of 8 or higher when the free memory
 * drops below 4096 pages and kill processes with a oom_score_adj value of 0 or
 * higher when the free memory drops below 1024 pages.
 *
 * The driver considers memory used for caches to be free, but if a large
 * percentage of the cached memory is locked this can be very inaccurate
 * and processes may not get killed until the normal oom killer is triggered.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/notifier.h>

#include <linux/ratelimit.h>

#ifdef CONFIG_ZSWAP
#include <linux/fs.h>
#include <linux/swap.h>
#endif

#include <linux/ratelimit.h>
#ifdef CONFIG_ZRAM_FOR_ANDROID
#include <linux/fs.h>
#include <linux/swap.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/mm_inline.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/cpu.h>
#include <asm/atomic.h>

#if defined(CONFIG_SMP)
#define NR_TO_RECLAIM_PAGES 		(1024 * NR_CPUS)/* 4MB*cpu_core, include file pages */
#define MIN_FREESWAP_PAGES 		(NR_TO_RECLAIM_PAGES*2) /* 4MB*cpu_core*2 */
#define MIN_RECLAIM_PAGES 		(NR_TO_RECLAIM_PAGES/8)
#define MIN_CSWAP_INTERVAL 		(10*HZ) /* 10 senconds */
#else /* CONFIG_SMP */
#define NR_TO_RECLAIM_PAGES 		1024 /* 4MB, include file pages */
#define MIN_FREESWAP_PAGES 		(NR_TO_RECLAIM_PAGES*2)  /* 4MB*2 */
#define MIN_RECLAIM_PAGES 		(NR_TO_RECLAIM_PAGES/8)
#define MIN_CSWAP_INTERVAL 		(10*HZ) /* 10 senconds */
#endif
#include <linux/mutex.h>
#include <linux/delay.h>
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
#include <linux/string.h>
#endif
static int
task_notify_func(struct notifier_block *self, unsigned long val, void *data);

struct soft_reclaim {
	atomic_t kcompcached_running;
	atomic_t need_to_reclaim;
	atomic_t lmk_running;
	struct task_struct *kcompcached;
};

static struct soft_reclaim s_reclaim;
extern atomic_t kswapd_thread_on;
static unsigned long prev_jiffy;
static uint32_t number_of_reclaim_pages = NR_TO_RECLAIM_PAGES;
static uint32_t minimum_freeswap_pages = MIN_FREESWAP_PAGES;
static uint32_t minimum_reclaim_pages = MIN_RECLAIM_PAGES;
static uint32_t minimum_interval_time = MIN_CSWAP_INTERVAL;
#endif /* CONFIG_ZRAM_FOR_ANDROID */

#define ENHANCED_LMK_ROUTINE
#define LMK_COUNT_READ

#ifdef ENHANCED_LMK_ROUTINE
#define LOWMEM_DEATHPENDING_DEPTH 3
#endif

#ifdef LMK_COUNT_READ
static uint32_t lmk_count = 0;
#endif

#ifdef CONFIG_SEC_OOM_KILLER
#define MULTIPLE_OOM_KILLER
#define OOM_COUNT_READ
#endif

#ifdef OOM_COUNT_READ
static uint32_t oom_count = 0;
#endif

#ifdef MULTIPLE_OOM_KILLER
#define OOM_DEPTH 7
#endif

static uint32_t lowmem_debug_level = 2;
static int lowmem_adj[6] = {
	0,
	1,
	6,
	12,
};
static int lowmem_adj_size = 4;
static int lowmem_minfree[6] = {
	3 * 512,	/* 6MB */
	2 * 1024,	/* 8MB */
	4 * 1024,	/* 16MB */
	16 * 1024,	/* 64MB */
};
static int lowmem_minfree_size = 4;

#ifdef ENHANCED_LMK_ROUTINE
static struct task_struct *lowmem_deathpending[LOWMEM_DEATHPENDING_DEPTH] = {NULL,};
#else
static struct task_struct *lowmem_deathpending;
#endif
static unsigned long lowmem_deathpending_timeout;

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
#define MAX_NOT_KILLABLE_PROCESSES	25	/* Max number of not killable processes */
#define MANAGED_PROCESS_TYPES		3	/* Numer of managed process types (lowmem_process_type) */

/*
 * Enumerator for the managed process types
 */
enum lowmem_process_type {
	KILLABLE_PROCESS,
	DO_NOT_KILL_PROCESS,
	DO_NOT_KILL_SYSTEM_PROCESS
};

/*
 * Data struct for the management of not killable processes
 */
struct donotkill {
	uint enabled;
	char *names[MAX_NOT_KILLABLE_PROCESSES];
	int names_count;
};

static struct donotkill donotkill_proc;		/* User processes to preserve from killing */
static struct donotkill donotkill_sysproc;	/* System processes to preserve from killing */

/*
 * Checks if a process name is inside a list of processes to be preserved from killing
 */
static bool is_in_donotkill_list(char *proc_name, struct donotkill *donotkill_proc)
{
	int i = 0;

	/* If the do not kill feature is enabled and the process names to be preserved
	 * is not empty, then check if the passed process name is contained inside it */
	if (donotkill_proc->enabled && donotkill_proc->names_count > 0) {
		for (i = 0; i < donotkill_proc->names_count; i++) {
			if (strstr(donotkill_proc->names[i], proc_name) != NULL)
				return true; /* The process must be preserved from killing */
		}
	}

	return false; /* The process is not contained inside the process names list */
}

/*
 * Checks if a process name is inside a list of user processes to be preserved from killing
 */
static bool is_in_donotkill_proc_list(char *proc_name)
{
	return is_in_donotkill_list(proc_name, &donotkill_proc);
}

/*
 * Checks if a process name is inside a list of system processes to be preserved from killing
 */
static bool is_in_donotkill_sysproc_list(char *proc_name)
{
	return is_in_donotkill_list(proc_name, &donotkill_sysproc);
}
#else
#define MANAGED_PROCESS_TYPES		1	/* Numer of managed process types (lowmem_process_type) */

/*
 * Enumerator for the managed process types
 */
enum lowmem_process_type {
	KILLABLE_PROCESS
};
#endif

#define lowmem_print(level, x...)			\
	do {						\
		if (lowmem_debug_level >= (level))	\
			pr_info(x);			\
	} while (0)
#if defined(CONFIG_SEC_DEBUG_LMK_MEMINFO)
static void dump_tasks_info(void)
{
	struct task_struct *p;
	struct task_struct *task;

	pr_info("[ pid ]   uid	tgid total_vm	   rss cpu oom_adj oom_score_adj name\n");
	for_each_process(p) {
		/* check unkillable tasks */
		if (is_global_init(p))
			continue;
		if (p->flags & PF_KTHREAD)
			continue;

		task = find_lock_task_mm(p);
		if (!task) {
			/*
			* This is a kthread or all of p's threads have already
			* detached their mm's.	There's no need to report
			* them; they can't be oom killed anyway.
			*/
			continue;
		}

		pr_info("[%5d] %5d %5d %8lu %8lu %3u	 %3d	     %5d %s\n",
		task->pid, task_uid(task), task->tgid,
		task->mm->total_vm, get_mm_rss(task->mm),
		task_cpu(task), task->signal->oom_adj,
		task->signal->oom_score_adj, task->comm);
		task_unlock(task);
	}
}
#endif
static struct notifier_block task_nb = {
	.notifier_call	= task_notify_func,
};



static int
task_notify_func(struct notifier_block *self, unsigned long val, void *data)
{
	struct task_struct *task = data;

#ifdef ENHANCED_LMK_ROUTINE
	int i = 0;
	for (i = 0; i < LOWMEM_DEATHPENDING_DEPTH; i++)
		if (task == lowmem_deathpending[i]) {
			lowmem_deathpending[i] = NULL;
		break;
	}
#else
	if (task == lowmem_deathpending)
		lowmem_deathpending = NULL;
#endif
	return NOTIFY_OK;
}

static int test_task_flag(struct task_struct *p, int flag)
{
	struct task_struct *t = p;

	do {
		task_lock(t);
		if (test_tsk_thread_flag(t, flag)) {
			task_unlock(t);
			return 1;
		}
		task_unlock(t);
	} while_each_thread(p, t);

	return 0;
}

static DEFINE_MUTEX(scan_mutex);

static int lowmem_shrink(struct shrinker *s, struct shrink_control *sc)
{
	struct task_struct *tsk;
	struct task_struct *selected[MANAGED_PROCESS_TYPES] = {NULL};
	int rem = 0;
	int tasksize;
	int i;
	int min_score_adj = OOM_SCORE_ADJ_MAX + 1;
	int minfree = 0;
	enum lowmem_process_type proc_type = KILLABLE_PROCESS;
	int selected_tasksize[MANAGED_PROCESS_TYPES] = {0};
	int selected_oom_score_adj[MANAGED_PROCESS_TYPES];
	int array_size = ARRAY_SIZE(lowmem_adj);
	int other_free;
	int other_file;
	unsigned long nr_to_scan = sc->nr_to_scan;
#ifdef CONFIG_SEC_DEBUG_LMK_MEMINFO
	static DEFINE_RATELIMIT_STATE(lmk_rs, DEFAULT_RATELIMIT_INTERVAL, 1);
#endif
#if defined(CONFIG_ZRAM_FOR_ANDROID) || defined(CONFIG_ZSWAP)
	other_file -= total_swapcache_pages;
#endif /* CONFIG_ZRAM_FOR_ANDROID */

	if (nr_to_scan > 0) {
		if (mutex_lock_interruptible(&scan_mutex) < 0)
			return 0;
	}

#ifndef CONFIG_CMA
	other_free = global_page_state(NR_FREE_PAGES);
#else
	other_free = global_page_state(NR_FREE_PAGES) -
					global_page_state(NR_FREE_CMA_PAGES);
#endif
	if (global_page_state(NR_SHMEM) + total_swapcache_pages <
		global_page_state(NR_FILE_PAGES))
		other_file = global_page_state(NR_FILE_PAGES) -
						global_page_state(NR_SHMEM) -
						total_swapcache_pages;
	else
		other_file = 0;

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;
	if (lowmem_minfree_size < array_size)
		array_size = lowmem_minfree_size;
	for (i = 0; i < array_size; i++) {
		minfree = lowmem_minfree[i];
		if (other_free < minfree && other_file < minfree) {
			min_score_adj = lowmem_adj[i];
			break;
		}
	}
	if (nr_to_scan > 0)
		lowmem_print(3, "lowmem_shrink %lu, %x, ofree %d %d, ma %d\n",
				nr_to_scan, sc->gfp_mask, other_free,
				other_file, min_score_adj);
	rem = global_page_state(NR_ACTIVE_ANON) +
		global_page_state(NR_ACTIVE_FILE) +
		global_page_state(NR_INACTIVE_ANON) +
		global_page_state(NR_INACTIVE_FILE);
	if (nr_to_scan <= 0 || min_score_adj == OOM_SCORE_ADJ_MAX + 1) {
		lowmem_print(5, "lowmem_shrink %lu, %x, return %d\n",
			     nr_to_scan, sc->gfp_mask, rem);

		if (nr_to_scan > 0)
			mutex_unlock(&scan_mutex);

		return rem;
	}

	/* Set the initial oom_score_adj for each managed process type */
	for (proc_type = KILLABLE_PROCESS; proc_type < MANAGED_PROCESS_TYPES; proc_type++)
		selected_oom_score_adj[proc_type] = min_score_adj;

#ifdef CONFIG_ZRAM_FOR_ANDROID
	atomic_set(&s_reclaim.lmk_running, 1);
#endif /* CONFIG_ZRAM_FOR_ANDROID */

	rcu_read_lock();
	for_each_process(tsk) {
		struct task_struct *p;
		int oom_score_adj;

		if (tsk->flags & PF_KTHREAD)
			continue;

		/* if task no longer has any memory ignore it */
		if (test_task_flag(tsk, TIF_MM_RELEASED))
			continue;

		if (time_before_eq(jiffies, lowmem_deathpending_timeout)) {
			if (test_task_flag(tsk, TIF_MEMDIE)) {
				rcu_read_unlock();
				/* give the system time to free up the memory */
				msleep_interruptible(20);
				mutex_unlock(&scan_mutex);
				return 0;
			}
		}

		p = find_lock_task_mm(tsk);
		if (!p)
			continue;

		oom_score_adj = p->signal->oom_score_adj;
		if (oom_score_adj < min_score_adj) {
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
		task_unlock(p);
		if (tasksize <= 0)
			continue;
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
		/* Check if the process name is contained inside the process to be preserved lists */
		if (is_in_donotkill_proc_list(p->comm)) {
			/* This user process must be preserved from killing */
			proc_type = DO_NOT_KILL_PROCESS;
			lowmem_print(2, "The process '%s' is inside the donotkill_proc_names", p->comm);
		} else if (is_in_donotkill_sysproc_list(p->comm)) {
			/* This system process must be preserved from killing */
			proc_type = DO_NOT_KILL_SYSTEM_PROCESS;
			lowmem_print(2, "The process '%s' is inside the donotkill_sysproc_names", p->comm);
		}
#endif

		if (selected[proc_type]) {
			if (oom_score_adj < selected_oom_score_adj[proc_type])
				continue;
			if (oom_score_adj == selected_oom_score_adj[proc_type] &&
			    tasksize <= selected_tasksize[proc_type])
				continue;
		}
		selected[proc_type] = p;
		selected_tasksize[proc_type] = tasksize;
		selected_oom_score_adj[proc_type] = oom_score_adj;
		lowmem_print(2, "select '%s' (%d), adj %d, size %d, to kill\n",
			     p->comm, p->pid, oom_score_adj, tasksize);
	}

	/* For each managed process type check if a process to be killed has been found:
	 * - check first if a standard killable process has been found, if so kill it
	 * - if there is no killable process, then check if a user process has been found,
	 *   if so kill it to prevent system slowdowns, hangs, etc.
	 * - if there is no killable and user process, then check if a system process has been found,
	 *   if so kill it to prevent system slowdowns, hangs, etc. */
	for (proc_type = KILLABLE_PROCESS; proc_type < MANAGED_PROCESS_TYPES; proc_type++) {
		if (selected[proc_type]) {
			lowmem_print(1, "Killing '%s' (%d), adj %d,\n" \
					"   to free %ldkB on behalf of '%s' (%d) because\n" \
					"   cache %ldkB is below limit %ldkB for oom_score_adj %d\n" \
					"   Free memory is %ldkB above reserved\n",
					 selected[proc_type]->comm, selected[proc_type]->pid,
					 selected_oom_score_adj[proc_type],
					 selected_tasksize[proc_type] * (long)(PAGE_SIZE / 1024),
					 current->comm, current->pid,
					 other_file * (long)(PAGE_SIZE / 1024),
					 minfree * (long)(PAGE_SIZE / 1024),
					 min_score_adj,
					 other_free * (long)(PAGE_SIZE / 1024));
			lowmem_deathpending_timeout = jiffies + HZ;
			send_sig(SIGKILL, selected[proc_type], 0);
			set_tsk_thread_flag(selected[proc_type], TIF_MEMDIE);
			rem -= selected_tasksize[proc_type];
			break;
		}
	}

	rcu_read_unlock();
	/* give the system time to free up the memory */
	msleep_interruptible(20);

#ifdef LMK_COUNT_READ
                lmk_count++;
#endif

#ifdef CONFIG_SEC_DEBUG_LMK_MEMINFO
	if (__ratelimit(&lmk_rs)) {
		lowmem_print(1, "lowmem_shrink %lu, %x, ofree %d %d, ma %d\n",
				nr_to_scan, sc->gfp_mask, other_free,
				other_file, min_score_adj);
		show_mem(SHOW_MEM_FILTER_NODES);
		dump_tasks_info();
	}
#endif

	lowmem_print(4, "lowmem_shrink %lu, %x, return %d\n",
		     nr_to_scan, sc->gfp_mask, rem);
	mutex_unlock(&scan_mutex);
	return rem;
}

static void dump_tasks_info(void)
{
	struct task_struct *p;
	struct task_struct *task;

	pr_info("[ pid ]   uid	tgid total_vm	   rss cpu oom_adj oom_score_adj name\n");
	for_each_process(p) {
		/* check unkillable tasks */
		if (is_global_init(p))
			continue;
		if (p->flags & PF_KTHREAD)
			continue;

		task = find_lock_task_mm(p);
		if (!task) {
			/*
			* This is a kthread or all of p's threads have already
			* detached their mm's.	There's no need to report
			* them; they can't be oom killed anyway.
			*/
			continue;
		}

		pr_info("[%5d] %5d %5d %8lu %8lu %3u	 %3d	     %5d %s\n",
		task->pid, task_uid(task), task->tgid,
		task->mm->total_vm, get_mm_rss(task->mm),
		task_cpu(task), task->signal->oom_adj,
		task->signal->oom_score_adj, task->comm);
		task_unlock(task);
	}
}



/*
 * CONFIG_SEC_OOM_KILLER : klaatu@sec
 *
 * The way to select victim by oom-killer provided by
 * linux kernel is totally different from android policy.
 * Hence, it makes more sense that we select the oom victim
 * as android does when LMK is invoked.
 *
*/
#ifdef CONFIG_SEC_OOM_KILLER

static int android_oom_handler(struct notifier_block *nb,
				      unsigned long val, void *data)
{
	struct task_struct *tsk;
#ifdef MULTIPLE_OOM_KILLER
	struct task_struct *selected[OOM_DEPTH] = {NULL,};
#else
	struct task_struct *selected = NULL;
#endif
	int rem = 0;
	int tasksize;
	int i;
	int min_score_adj = OOM_SCORE_ADJ_MAX + 1;
#ifdef MULTIPLE_OOM_KILLER
	int selected_tasksize[OOM_DEPTH] = {0,};
	int selected_oom_score_adj[OOM_DEPTH] = {OOM_ADJUST_MAX,};
	int all_selected_oom = 0;
	int max_selected_oom_idx = 0;
#else
	int selected_tasksize = 0;
	int selected_oom_score_adj;
#endif
	static DEFINE_RATELIMIT_STATE(oom_rs, DEFAULT_RATELIMIT_INTERVAL/5, 1);

	unsigned long *freed = data;

	/* show status */
	pr_warning("%s invoked Android-oom-killer: "
		"oom_adj=%d, oom_score_adj=%d\n",
		current->comm, current->signal->oom_adj,
		current->signal->oom_score_adj);
	dump_stack();
	show_mem(SHOW_MEM_FILTER_NODES);
	if (__ratelimit(&oom_rs))
		dump_tasks_info();

	min_score_adj = 0;
#ifdef MULTIPLE_OOM_KILLER
	for (i = 0; i < OOM_DEPTH; i++)
		selected_oom_score_adj[i] = min_score_adj;
#else
	selected_oom_score_adj = min_score_adj;
#endif

#ifdef CONFIG_ZRAM_FOR_ANDROID
	atomic_set(&s_reclaim.lmk_running, 1);
#endif

	read_lock(&tasklist_lock);
	for_each_process(tsk) {
		struct task_struct *p;
		int oom_score_adj;
#ifdef MULTIPLE_OOM_KILLER
		int is_exist_oom_task = 0;
#endif

		if (tsk->flags & PF_KTHREAD)
			continue;

		p = find_lock_task_mm(tsk);
		if (!p)
			continue;

		oom_score_adj = p->signal->oom_score_adj;
		if (oom_score_adj < min_score_adj) {
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
		task_unlock(p);
		if (tasksize <= 0)
			continue;

		lowmem_print(2, "oom: ------ %d (%s), adj %d, size %d\n",
			     p->pid, p->comm, oom_score_adj, tasksize);
#ifdef MULTIPLE_OOM_KILLER
		if (all_selected_oom < OOM_DEPTH) {
			for (i = 0; i < OOM_DEPTH; i++) {
				if (!selected[i]) {
					is_exist_oom_task = 1;
					max_selected_oom_idx = i;
					break;
				}
			}
		} else if (selected_oom_score_adj[max_selected_oom_idx] < oom_score_adj ||
			(selected_oom_score_adj[max_selected_oom_idx] == oom_score_adj &&
			selected_tasksize[max_selected_oom_idx] < tasksize)) {
			is_exist_oom_task = 1;
		}

		if (is_exist_oom_task) {
			selected[max_selected_oom_idx] = p;
			selected_tasksize[max_selected_oom_idx] = tasksize;
			selected_oom_score_adj[max_selected_oom_idx] = oom_score_adj;

			if (all_selected_oom < OOM_DEPTH)
				all_selected_oom++;

			if (all_selected_oom == OOM_DEPTH) {
				for (i = 0; i < OOM_DEPTH; i++) {
					if (selected_oom_score_adj[i] < selected_oom_score_adj[max_selected_oom_idx])
						max_selected_oom_idx = i;
					else if (selected_oom_score_adj[i] == selected_oom_score_adj[max_selected_oom_idx] &&
						selected_tasksize[i] < selected_tasksize[max_selected_oom_idx])
						max_selected_oom_idx = i;
				}
			}

			lowmem_print(2, "oom: max_selected_oom_idx(%d) select %d (%s), adj %d, \
					size %d, to kill\n",
				max_selected_oom_idx, p->pid, p->comm, oom_score_adj, tasksize);
		}
#else
		if (selected) {
			if (oom_score_adj < selected_oom_score_adj)
				continue;
			if (oom_score_adj == selected_oom_score_adj &&
			    tasksize <= selected_tasksize)
				continue;
		}
		selected = p;
		selected_tasksize = tasksize;
		selected_oom_score_adj = oom_score_adj;
		lowmem_print(2, "oom: select %d (%s), adj %d, size %d, to kill\n",
			     p->pid, p->comm, oom_score_adj, tasksize);
#endif
	}
#ifdef MULTIPLE_OOM_KILLER
	for (i = 0; i < OOM_DEPTH; i++) {
		if (selected[i]) {
			lowmem_print(1, "oom: send sigkill to %d (%s), adj %d,\
				     size %d\n",
				     selected[i]->pid, selected[i]->comm,
				     selected_oom_score_adj[i],
				     selected_tasksize[i]);
			send_sig(SIGKILL, selected[i], 0);
			rem -= selected_tasksize[i];
			*freed += (unsigned long)selected_tasksize[i];
#ifdef OOM_COUNT_READ
			oom_count++;
#endif

		}
	}
#else
	if (selected) {
		lowmem_print(1, "oom: send sigkill to %d (%s), adj %d, size %d\n",
			     selected->pid, selected->comm,
			     selected_oom_score_adj, selected_tasksize);
		send_sig(SIGKILL, selected, 0);
		set_tsk_thread_flag(selected, TIF_MEMDIE);
		rem -= selected_tasksize;
		*freed += (unsigned long)selected_tasksize;
#ifdef OOM_COUNT_READ
		oom_count++;
#endif
	}
#endif
	read_unlock(&tasklist_lock);

#ifdef CONFIG_ZRAM_FOR_ANDROID
	atomic_set(&s_reclaim.lmk_running, 0);
#endif

	lowmem_print(2, "oom: get memory %lu", *freed);
	return rem;
}

static struct notifier_block android_oom_notifier = {
	.notifier_call = android_oom_handler,
};
#endif /* CONFIG_ANDROID_OOM_KILLER */

#ifdef CONFIG_ZRAM_FOR_ANDROID
void could_cswap(void)
{
	if (atomic_read(&s_reclaim.need_to_reclaim) == 0)
		return;

	if (time_before(jiffies, prev_jiffy + minimum_interval_time))
		return;

	if (atomic_read(&s_reclaim.lmk_running) == 1 || atomic_read(&kswapd_thread_on) == 1) 
		return;

	if (nr_swap_pages < minimum_freeswap_pages)
		return;

	if (idle_cpu(task_cpu(s_reclaim.kcompcached)) && this_cpu_loadx(4) == 0) {
		if (atomic_read(&s_reclaim.kcompcached_running) == 0) {
			wake_up_process(s_reclaim.kcompcached);
			atomic_set(&s_reclaim.kcompcached_running, 1);
			prev_jiffy = jiffies;
		}
	}
}

inline void need_soft_reclaim(void)
{
	atomic_set(&s_reclaim.need_to_reclaim, 1);
}

inline void cancel_soft_reclaim(void)
{
	atomic_set(&s_reclaim.need_to_reclaim, 0);
}

int get_soft_reclaim_status(void)
{
	int kcompcache_running = atomic_read(&s_reclaim.kcompcached_running);
	return kcompcache_running;
}

extern long rtcc_reclaim_pages(long nr_to_reclaim);
static int do_compcache(void * nothing)
{
	int ret;
	set_freezable();

	for ( ; ; ) {
		ret = try_to_freeze();
		if (kthread_should_stop())
			break;

		if (atomic_read(&s_reclaim.kcompcached_running) == 1) {
			if (rtcc_reclaim_pages(number_of_reclaim_pages) < minimum_reclaim_pages)
				cancel_soft_reclaim();

			atomic_set(&s_reclaim.kcompcached_running, 0);
		}

		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	return 0;
}

static ssize_t rtcc_trigger_store(struct class *class, struct class_attribute *attr,
			const char *buf, size_t count)
{
	long val, magic_sign;

	sscanf(buf, "%ld,%ld", &val, &magic_sign);

	if (val < 0 || ((val * val - 1) != magic_sign)) {
		pr_warning("Invalid command.\n");
		goto out;
	}

	need_soft_reclaim();

out:
	return count;
}
static CLASS_ATTR(rtcc_trigger, 0200, NULL, rtcc_trigger_store);
static struct class *kcompcache_class;

static int kcompcache_idle_notifier(struct notifier_block *nb, unsigned long val, void *data)
{
	could_cswap();
	return 0;
}

static struct notifier_block kcompcache_idle_nb = {
	.notifier_call = kcompcache_idle_notifier,
};
#endif /* CONFIG_ZRAM_FOR_ANDROID */



#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
static int lowmem_oom_adj_to_oom_score_adj(int oom_adj)
{
	if (oom_adj == OOM_ADJUST_MAX)
		return OOM_SCORE_ADJ_MAX;
	else
		return (oom_adj * OOM_SCORE_ADJ_MAX) / -OOM_DISABLE;
}

static void lowmem_autodetect_oom_adj_values(void)
{
	int i;
	int oom_adj;
	int oom_score_adj;
	int array_size = ARRAY_SIZE(lowmem_adj);

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;

	if (array_size <= 0)
		return;

	oom_adj = lowmem_adj[array_size - 1];
	if (oom_adj > OOM_ADJUST_MAX)
		return;

	oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
	if (oom_score_adj <= OOM_ADJUST_MAX)
		return;

	lowmem_print(1, "lowmem_shrink: convert oom_adj to oom_score_adj:\n");
	for (i = 0; i < array_size; i++) {
		oom_adj = lowmem_adj[i];
		oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
		lowmem_adj[i] = oom_score_adj;
		lowmem_print(1, "oom_adj %d => oom_score_adj %d\n",
			     oom_adj, oom_score_adj);
	}
}

static int lowmem_adj_array_set(const char *val, const struct kernel_param *kp)
{
	int ret;

	ret = param_array_ops.set(val, kp);

	/* HACK: Autodetect oom_adj values in lowmem_adj array */
	lowmem_autodetect_oom_adj_values();

	return ret;
}

static int lowmem_adj_array_get(char *buffer, const struct kernel_param *kp)
{
        return param_array_ops.get(buffer, kp);
}

static void lowmem_adj_array_free(void *arg)
{
        param_array_ops.free(arg);
}

static struct kernel_param_ops lowmem_adj_array_ops = {
        .set = lowmem_adj_array_set,
        .get = lowmem_adj_array_get,
        .free = lowmem_adj_array_free,
};

static const struct kparam_array __param_arr_adj = {
        .max = ARRAY_SIZE(lowmem_adj),
        .num = &lowmem_adj_size,
        .ops = &param_ops_int,
        .elemsize = sizeof(lowmem_adj[0]),
        .elem = lowmem_adj,
};
#endif
static struct shrinker lowmem_shrinker = {
	.shrink = lowmem_shrink,
	.seeks = DEFAULT_SEEKS * 16
};

static int __init lowmem_init(void)
{
	task_free_register(&task_nb);
	register_shrinker(&lowmem_shrinker);
#ifdef CONFIG_MEMORY_HOTPLUG
	hotplug_memory_notifier(lmk_hotplug_callback, 0);
#endif
#ifdef CONFIG_ZRAM_FOR_ANDROID
	s_reclaim.kcompcached = kthread_run(do_compcache, NULL, "kcompcached");
	if (IS_ERR(s_reclaim.kcompcached)) {
		/* failure at boot is fatal */
		BUG_ON(system_state == SYSTEM_BOOTING);
	}
	set_user_nice(s_reclaim.kcompcached, 0);
	atomic_set(&s_reclaim.need_to_reclaim, 0);
	atomic_set(&s_reclaim.kcompcached_running, 0);
	prev_jiffy = jiffies;

	idle_notifier_register(&kcompcache_idle_nb);

	kcompcache_class = class_create(THIS_MODULE, "kcompcache");
	if (IS_ERR(kcompcache_class)) {
		pr_err("%s: couldn't create kcompcache class.\n", __func__);
		return 0;
	}
	if (class_create_file(kcompcache_class, &class_attr_rtcc_trigger) < 0) {
		pr_err("%s: couldn't create rtcc trigger sysfs file.\n", __func__);
		class_destroy(kcompcache_class);
	}
#endif /* CONFIG_ZRAM_FOR_ANDROID */
	return 0;
}

static void __exit lowmem_exit(void)
{
	unregister_shrinker(&lowmem_shrinker);
	task_free_unregister(&task_nb);

#ifdef CONFIG_ZRAM_FOR_ANDROID
	idle_notifier_unregister(&kcompcache_idle_nb);
	if (s_reclaim.kcompcached) {
		cancel_soft_reclaim();
		kthread_stop(s_reclaim.kcompcached);
		s_reclaim.kcompcached = NULL;
	}

	if (kcompcache_class) {
		class_remove_file(kcompcache_class, &class_attr_rtcc_trigger);
		class_destroy(kcompcache_class);
	}
#endif /* CONFIG_ZRAM_FOR_ANDROID */
}

module_param_named(cost, lowmem_shrinker.seeks, int, S_IRUGO | S_IWUSR);
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
__module_param_call(MODULE_PARAM_PREFIX, adj,
		    &lowmem_adj_array_ops,
		    .arr = &__param_arr_adj,
		    S_IRUGO | S_IWUSR, -1);
__MODULE_PARM_TYPE(adj, "array of int");
#else
module_param_array_named(adj, lowmem_adj, int, &lowmem_adj_size,
			 S_IRUGO | S_IWUSR);
#endif
module_param_array_named(minfree, lowmem_minfree, uint, &lowmem_minfree_size,
			 S_IRUGO | S_IWUSR);
module_param_named(debug_level, lowmem_debug_level, uint, S_IRUGO | S_IWUSR);
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
module_param_named(donotkill_proc, donotkill_proc.enabled, uint, S_IRUGO | S_IWUSR);
module_param_array_named(donotkill_proc_names, donotkill_proc.names, charp,
			 &donotkill_proc.names_count, S_IRUGO | S_IWUSR);
module_param_named(donotkill_sysproc, donotkill_sysproc.enabled, uint, S_IRUGO | S_IWUSR);
module_param_array_named(donotkill_sysproc_names, donotkill_sysproc.names, charp,
			 &donotkill_sysproc.names_count, S_IRUGO | S_IWUSR);
#endif
#ifdef LMK_COUNT_READ
module_param_named(lmkcount, lmk_count, uint, S_IRUGO);
#endif


#ifdef OOM_COUNT_READ
module_param_named(oomcount, oom_count, uint, S_IRUGO);
#endif

#ifdef CONFIG_ZRAM_FOR_ANDROID
module_param_named(nr_reclaim, number_of_reclaim_pages, uint, S_IRUSR | S_IWUSR);
module_param_named(min_freeswap, minimum_freeswap_pages, uint, S_IRUSR | S_IWUSR);
module_param_named(min_reclaim, minimum_reclaim_pages, uint, S_IRUSR | S_IWUSR);
module_param_named(min_interval, minimum_interval_time, uint, S_IRUSR | S_IWUSR);
#endif /* CONFIG_ZRAM_FOR_ANDROID */

module_init(lowmem_init);
module_exit(lowmem_exit);

MODULE_LICENSE("GPL");

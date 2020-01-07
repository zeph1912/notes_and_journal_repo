## Softirq

Linux kernel splits interrupt handling into two parts. The first part executes right away and mask the interrupt line. Hardware interrupts must be handled quick, and that's why we need the second part to handle the heavy work deferred from a interrupt handler. Historically, BH (Linux naming for Bottom Halves) statistically book-keeps the deferred functions. Softirq and its higher level abstraction, Tasklet, replace BH since 2.3 kernel.

We are going to look at the implementation of softirq. The source code is in `kernel/softirq.c`.

### Define softirq

```c
static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;
```

Each softirq is statistically defined as a `softirq_action` struct in the softirq_vec array. The structs are smp cacheline aligned. The maximum size of this array is 32, while only 10 is currently in use in Linux. The definition is in `linux/include/linux/interrupt.h`.

```c
/* PLEASE, avoid to allocate new softirqs, if you need not _really_ high
   frequency threaded job scheduling. For almost all the purposes
   tasklets are more than enough. F.e. all serial device BHs et
   al. should be converted to tasklets, not to softirqs.
 */

enum
{
	HI_SOFTIRQ=0,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	BLOCK_SOFTIRQ,
	IRQ_POLL_SOFTIRQ,
	TASKLET_SOFTIRQ,
	SCHED_SOFTIRQ,
	HRTIMER_SOFTIRQ,
	RCU_SOFTIRQ,    /* Preferable RCU should always be the last softirq */

	NR_SOFTIRQS
};
```

You can also see the string names of these softirq in `kernel/softirq.c`.
```c
const char * const softirq_to_name[NR_SOFTIRQS] = {
	"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
	"TASKLET", "SCHED", "HRTIMER", "RCU"
};
```

`open_softirq` provides an interface for the kernel to register the action function for a specific softirq number.

```c
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
	softirq_vec[nr].action = action;
}
```

Tasklet is an abstraction of softirq. It is kernel developer friendly, i.e. you can add your own deferred work as tasklet. Directly adding as static softirq is not advisable. The kernel comments above clearly says that.

The code snippet below initializes tasklets. It calls `open_softirq` to register `TASKLET_SOFTIRQ` and `HI_SOFTIRQ`. They are both used for implementing tasklet. `HI_SOFTIRQ` has higher priority than `TASKLET_SOFTIRQ`. Note that softirq are per CPU. In contrast, tasklet only allow one of the same type tasklet to run concurrently across different CPUs. 

```c
void __init softirq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		per_cpu(tasklet_vec, cpu).tail =
			&per_cpu(tasklet_vec, cpu).head;
		per_cpu(tasklet_hi_vec, cpu).tail =
			&per_cpu(tasklet_hi_vec, cpu).head;
	}

	open_softirq(TASKLET_SOFTIRQ, tasklet_action);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}
```

Each softirq are checked whether or not it needs to run 1) in the return from hardware interrupt handler; 2) in the `ksoftirqd` kernel thread; 3) explicitly checks [1].

### Explicit raise_softirq

`raise_softirq` takes the softirq number as an argument, and raise that specific softirq. Hardware interrupt must be disabled while handling softirq.

```c
void raise_softirq(unsigned int nr)
{
	unsigned long flags;

	local_irq_save(flags);
	raise_softirq_irqoff(nr);
	local_irq_restore(flags);
}
```

If the softirq is raised in a nested softirq context or we are in an hardware interrupt, the code below delays the raise of softirq and let `ksoftirqd` thread to handle it. We will look at `ksoftirqd` thread later.

```c
/*
 * This function must run with irqs disabled!
 */
inline void raise_softirq_irqoff(unsigned int nr)
{
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 */
	if (!in_interrupt())
		wakeup_softirqd();
}
```

### Handle softirq when exit an interrupt context

```c
/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
#ifndef __ARCH_IRQ_EXIT_IRQS_DISABLED
	local_irq_disable();
#else
	lockdep_assert_irqs_disabled();
#endif
	account_irq_exit_time(current);
	preempt_count_sub(HARDIRQ_OFFSET);
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();

	tick_irq_exit();
	rcu_irq_exit();
	trace_hardirq_exit(); /* must be last! */
}
```

If `irq_exit` cannot clear all the softirqs within `MAX_SOFTIRQ_TIME` or `MAX_SOFTIRQ_RESTART` (see the checks in `__do_softirq`), it will starts a kernel thread `ksoftirqd` to clear all softirqs. This mechanism prevents too many softirq from blocking the current kernel context.

```c
/*
 * We restart softirq processing for at most MAX_SOFTIRQ_RESTART times,
 * but break the loop if need_resched() is set or after 2 ms.
 * The MAX_SOFTIRQ_TIME provides a nice upper bound in most cases, but in
 * certain cases, such as stop_machine(), jiffies may cease to
 * increment and so we need the MAX_SOFTIRQ_RESTART limit as
 * well to make sure we eventually return from this method.
 *
 * These limits have been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_TIME  msecs_to_jiffies(2)
#define MAX_SOFTIRQ_RESTART 10
```

`invoke_softirq` is defined as, 

```c
static inline void invoke_softirq(void)
{
	if (ksoftirqd_running(local_softirq_pending()))
		return;

	if (!force_irqthreads) {
#ifdef CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK
		/*
		 * We can safely execute softirq on the current stack if
		 * it is the irq stack, because it should be near empty
		 * at this stage.
		 */
		__do_softirq();
#else
		/*
		 * Otherwise, irq_exit() is called on the task stack that can
		 * be potentially deep already. So call softirq in its own stack
		 * to prevent from any overrun.
		 */
		do_softirq_own_stack();
#endif
	} else {
		wakeup_softirqd();
	}
}
```

### ksoftirq

`ksoftirqd` struct is defined as,

```c
static struct smp_hotplug_thread softirq_threads = {
	.store			= &ksoftirqd,
	.thread_should_run	= ksoftirqd_should_run,
	.thread_fn		= run_ksoftirqd,
	.thread_comm		= "ksoftirqd/%u",
};
```

The thread function is `run_ksoftirqd`. It calls `__do_softirq` to clear all the softirqs.

```c
static void run_ksoftirqd(unsigned int cpu)
{
	local_irq_disable();
	if (local_softirq_pending()) {
		/*
		 * We can safely run softirq on inline stack, as we are not deep
		 * in the task stack here.
		 */
		__do_softirq();
		local_irq_enable();
		cond_resched();
		return;
	}
	local_irq_enable();
}
```

### Finally: do softirq

```c
asmlinkage __visible void __softirq_entry __do_softirq(void)
{
	unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
	unsigned long old_flags = current->flags;
	int max_restart = MAX_SOFTIRQ_RESTART;
	struct softirq_action *h;
	bool in_hardirq;
	__u32 pending;
	int softirq_bit;

	/*
	 * Mask out PF_MEMALLOC as the current task context is borrowed for the
	 * softirq. A softirq handled, such as network RX, might set PF_MEMALLOC
	 * again if the socket is related to swapping.
	 */
	current->flags &= ~PF_MEMALLOC;

	pending = local_softirq_pending();
	account_irq_enter_time(current);

	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);
	in_hardirq = lockdep_softirq_start();

restart:
	/* Reset the pending bitmask before enabling irqs */
	set_softirq_pending(0);

	local_irq_enable();

	h = softirq_vec;

	while ((softirq_bit = ffs(pending))) {
		unsigned int vec_nr;
		int prev_count;

		h += softirq_bit - 1;

		vec_nr = h - softirq_vec;
		prev_count = preempt_count();

		kstat_incr_softirqs_this_cpu(vec_nr);

		trace_softirq_entry(vec_nr);
		h->action(h);
		trace_softirq_exit(vec_nr);
		if (unlikely(prev_count != preempt_count())) {
			pr_err("huh, entered softirq %u %s %p with preempt_count %08x, exited with %08x?\n",
			       vec_nr, softirq_to_name[vec_nr], h->action,
			       prev_count, preempt_count());
			preempt_count_set(prev_count);
		}
		h++;
		pending >>= softirq_bit;
	}

	if (__this_cpu_read(ksoftirqd) == current)
		rcu_softirq_qs();
	local_irq_disable();

	pending = local_softirq_pending();
	if (pending) {
		if (time_before(jiffies, end) && !need_resched() &&
		    --max_restart)
			goto restart;

		wakeup_softirqd();
	}

	lockdep_softirq_end(in_hardirq);
	account_irq_exit_time(current);
	__local_bh_enable(SOFTIRQ_OFFSET);
	WARN_ON_ONCE(in_interrupt());
	current_restore_flags(old_flags, PF_MEMALLOC);
}
```

`__softirq_entry` is a macro defined in `linux/include/linux/interrupt.h`. `__attribute__((__section__(".softirqentry.text")))` specifies that the function must be placed in `".softirqentry.text"` section. 

```c
/*
 * We want to know which function is an entrypoint of a hardirq or a softirq.
 */
#define __irq_entry		 __attribute__((__section__(".irqentry.text")))
#define __softirq_entry  \
	__attribute__((__section__(".softirqentry.text")))
```

`local_softirq_pending` is a macro expended to `#define local_softirq_pending()	(__this_cpu_read(local_softirq_pending_ref))`. It gets the current pending softirqs on a specific processor.

`account_irq_enter_time` and `account_irq_exit_time` take the current task struct as input. It is for logging softirq time.

```c
static inline void account_irq_enter_time(struct task_struct *tsk)
{
	vtime_account_irq_enter(tsk);
	irqtime_account_irq(tsk);
}

static inline void account_irq_exit_time(struct task_struct *tsk)
{
	vtime_account_irq_exit(tsk);
	irqtime_account_irq(tsk);
}
```

`__local_bh_disable_ip` and `__local_bh_enable` works as a barrier to prevent entering softirq while raising softirq.

```c
static __always_inline void __local_bh_disable_ip(unsigned long ip, unsigned int cnt)
{
	preempt_count_add(cnt);
	barrier();
}

static inline void local_bh_enable_ip(unsigned long ip)
{
	__local_bh_enable_ip(ip, SOFTIRQ_DISABLE_OFFSET);
}
```

As mentioned above, `__do_softirq` will attempt to mask MAX_SOFTIRQ_RESTART (i.e. 10) pending soft interrupts. If there are more, a kernel thread, `ksoftirqd`, will be launched to mask them all.

`set_softirq_pending(0)` clears the pending softirq on the current CPU. This function is platform specific. A generic definition can be found in `include/linux/interrupt.h`.

```c
#define set_softirq_pending(x)	(__this_cpu_write(local_softirq_pending_ref, (x)))
```

`h = softirq_vec` points to the head of the pending softirq vectors.

`ffs()` finds the first bit that equal to 1 in a word. In this case, it finds the first 1 in `pending`.

```c
/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 * Note __ffs(0) = undef, __ffs(1) = 0, __ffs(0x80000000) = 31.
 *
 */
static inline unsigned long __ffs(unsigned long x)
{
	asm (" bitr  .M1  %0,%0\n"
	     " nop\n"
	     " lmbd  .L1  1,%0,%0\n"
	     : "+a"(x));

	return x;
}
```

`h` is used as a pointer to locate the softirq type and `softirq_action`. `h += softirq_bit - 1` points to the `softirq_action` of the softirq being handled. `vec_nr = h - softirq_vec` gets the index of the softirq, which is equal to its type. The callback function as stored in `softirq_action` is actually called by the line, `h->action(h)`.




References:

[1] Linux Kernel Development Third Edition, Robert Love (2010)

[2] https://blog.csdn.net/yhb1047818384/article/details/63687126

[3] https://blog.csdn.net/longwang155069/article/details/52457287

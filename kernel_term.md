## Linux kernel reading notes: process exit()

I had some reading notes on the clone syscall a couple of days ago, [link](https://zeph1912.github.io/notes_and_journal_repo/kernel_fork).
Now, we are looking at the inevitable death of a process. 

do_exit() function is defined in [kernel/exit](https://github.com/torvalds/linux/blob/master/kernel/exit.c).
The function is much simpler than do_clone() which creates a process.

```c
void __noreturn do_exit(long code)
{
    // some validations
    if (unlikely(tsk->flags & PF_EXITING)) {
    		tsk->flags |= PF_EXITPIDONE;
		    set_current_state(TASK_UNINTERRUPTIBLE);
		    schedule();
    }
    exit_signals(tsk);  /* sets PF_EXITING */
```

After some validations, it checks whether or not the process is in the exiting state (the `PF_EXITING` flag).
Normally, the `PF_EXITING` flag is not set.
If the flag is already set, it updates the flag to `PF_EXITPIDONE`, sets the schedule state to `TASK_UNINTERRUPTIBLE`, and then do a schedule so other processes can run.
The process is in the uninterruptable waiting state.
Under the normal execution flow, `exit_signals(tsk)` will set the flag and move on.

```c
/*
	 * Ensure that all new tsk->pi_lock acquisitions must observe
	 * PF_EXITING. Serializes against futex.c:attach_to_pi_owner().
	 */
	smp_mb();
	/*
	 * Ensure that we must observe the pi_state in exit_mm() ->
	 * mm_release() -> exit_pi_state_list().
	 */
	raw_spin_lock_irq(&tsk->pi_lock);
	raw_spin_unlock_irq(&tsk->pi_lock);

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, task_pid_nr(current),
			preempt_count());
		preempt_count_set(PREEMPT_ENABLED);
	}
  /* sync mm's RSS info before statistics gathering */
	if (tsk->mm)
		sync_mm_rss(tsk->mm);
	acct_update_integrals(tsk);
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
#ifdef CONFIG_POSIX_TIMERS
		hrtimer_cancel(&tsk->signal->real_timer);
		exit_itimers(tsk->signal);
#endif
		if (tsk->mm)
			setmax_mm_hiwater_rss(&tsk->signal->maxrss, tsk->mm);
	}
	acct_collect(code, group_dead);
	if (group_dead)
		tty_audit_exit();
	audit_free(tsk);
  ```
  
`smp_mb()` is a [memory barrier](https://www.kernel.org/doc/Documentation/memory-barriers.txt) to ensure the previous execution is finished.
`acct_update_integrals()` records the process' CPU time.
I am not very sure about `atomic_dec_and_test() and the group_dead condition. I will leave it alone for now.

```c
  tsk->exit_code = code;
	taskstats_exit(tsk, group_dead);

	exit_mm();

	if (group_dead)
		acct_process();
	trace_sched_process_exit(tsk);

	exit_sem(tsk);
	exit_shm(tsk);
	exit_files(tsk);
	exit_fs(tsk);
	if (group_dead)
		disassociate_ctty(1);
	exit_task_namespaces(tsk);
	exit_task_work(tsk);
	exit_thread(tsk);
	exit_umh(tsk);
```

It sets the exiting code and proceeds to release resources.
`exit_mm()` releases the mm if nobody is using it.
```c
static void exit_mm(void)
{
	struct mm_struct *mm = current->mm;
	struct core_state *core_state;

	mm_release(current, mm);
	if (!mm)
		return;
	sync_mm_rss(mm);
	/*
	 * Serialize with any possible pending coredump.
	 * We must hold mmap_sem around checking core_state
	 * and clearing tsk->mm.  The core-inducing thread
	 * will increment ->nr_threads for each thread in the
	 * group with ->mm != NULL.
	 */
	down_read(&mm->mmap_sem);
	core_state = mm->core_state;
	if (core_state) {
		struct core_thread self;

		up_read(&mm->mmap_sem);

		self.task = current;
		self.next = xchg(&core_state->dumper.next, &self);
		/*
		 * Implies mb(), the result of xchg() must be visible
		 * to core_state->dumper.
		 */
		if (atomic_dec_and_test(&core_state->nr_threads))
			complete(&core_state->startup);

		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!self.task) /* see coredump_finish() */
				break;
			freezable_schedule();
		}
		__set_current_state(TASK_RUNNING);
		down_read(&mm->mmap_sem);
	}
	mmgrab(mm);
	BUG_ON(mm != current->active_mm);
	/* more a memory barrier than a real lock */
	task_lock(current);
	current->mm = NULL;
	up_read(&mm->mmap_sem);
	enter_lazy_tlb(mm, current);
	task_unlock(current);
	mm_update_next_owner(mm);
	mmput(mm);
	if (test_thread_flag(TIF_MEMDIE))
		exit_oom_victim();
}
```
If there are other threads sharing the mm, or the process has been vfolked and the vfolked process is alive, then it will not release the mm.
Lazy TLB mode delays TLB updates.

`exit_sem()` releases semaphores.
```c
/*
 * add semadj values to semaphores, free undo structures.
 * undo structures are not freed when semaphore arrays are destroyed
 * so some of them may be out of date.
 * IMPLEMENTATION NOTE: There is some confusion over whether the
 * set of adjustments that needs to be done should be done in an atomic
 * manner or not. That is, if we are attempting to decrement the semval
 * should we queue up and wait until we can do so legally?
 * The original implementation attempted to do this (queue and wait).
 * The current implementation does not do so. The POSIX standard
 * and SVID should be consulted to determine what behavior is mandated.
 */
void exit_sem(struct task_struct *tsk)
{
	struct sem_undo_list *ulp;

	ulp = tsk->sysvsem.undo_list;
	if (!ulp)
		return;
	tsk->sysvsem.undo_list = NULL;

	if (!refcount_dec_and_test(&ulp->refcnt))
		return;

	for (;;) {
		struct sem_array *sma;
		struct sem_undo *un;
		int semid, i;
		DEFINE_WAKE_Q(wake_q);

		cond_resched();

		rcu_read_lock();
		un = list_entry_rcu(ulp->list_proc.next,
				    struct sem_undo, list_proc);
		if (&un->list_proc == &ulp->list_proc) {
			/*
			 * We must wait for freeary() before freeing this ulp,
			 * in case we raced with last sem_undo. There is a small
			 * possibility where we exit while freeary() didn't
			 * finish unlocking sem_undo_list.
			 */
			spin_lock(&ulp->lock);
			spin_unlock(&ulp->lock);
			rcu_read_unlock();
			break;
		}
		spin_lock(&ulp->lock);
		semid = un->semid;
		spin_unlock(&ulp->lock);

		/* exit_sem raced with IPC_RMID, nothing to do */
		if (semid == -1) {
			rcu_read_unlock();
			continue;
		}

		sma = sem_obtain_object_check(tsk->nsproxy->ipc_ns, semid);
		/* exit_sem raced with IPC_RMID, nothing to do */
		if (IS_ERR(sma)) {
			rcu_read_unlock();
			continue;
		}

		sem_lock(sma, NULL, -1);
		/* exit_sem raced with IPC_RMID, nothing to do */
		if (!ipc_valid_object(&sma->sem_perm)) {
			sem_unlock(sma, -1);
			rcu_read_unlock();
			continue;
		}
		un = __lookup_undo(ulp, semid);
		if (un == NULL) {
			/* exit_sem raced with IPC_RMID+semget() that created
			 * exactly the same semid. Nothing to do.
			 */
			sem_unlock(sma, -1);
			rcu_read_unlock();
			continue;
		}

		/* remove un from the linked lists */
		ipc_assert_locked_object(&sma->sem_perm);
		list_del(&un->list_id);

		/* we are the last process using this ulp, acquiring ulp->lock
		 * isn't required. Besides that, we are also protected against
		 * IPC_RMID as we hold sma->sem_perm lock now
		 */
		list_del_rcu(&un->list_proc);

		/* perform adjustments registered in un */
		for (i = 0; i < sma->sem_nsems; i++) {
			struct sem *semaphore = &sma->sems[i];
			if (un->semadj[i]) {
				semaphore->semval += un->semadj[i];
				/*
				 * Range checks of the new semaphore value,
				 * not defined by sus:
				 * - Some unices ignore the undo entirely
				 *   (e.g. HP UX 11i 11.22, Tru64 V5.1)
				 * - some cap the value (e.g. FreeBSD caps
				 *   at 0, but doesn't enforce SEMVMX)
				 *
				 * Linux caps the semaphore value, both at 0
				 * and at SEMVMX.
				 *
				 *	Manfred <manfred@colorfullife.com>
				 */
				if (semaphore->semval < 0)
					semaphore->semval = 0;
				if (semaphore->semval > SEMVMX)
					semaphore->semval = SEMVMX;
				ipc_update_pid(&semaphore->sempid, task_tgid(current));
			}
		}
		/* maybe some queued-up processes were waiting for this */
		do_smart_update(sma, NULL, 0, 1, &wake_q);
		sem_unlock(sma, -1);
		rcu_read_unlock();
		wake_up_q(&wake_q);

		kfree_rcu(un, rcu);
	}
	kfree(ulp);
}
```

`exit_shm()` releases shared memory allocated for IPC. It basically walks the `&task->sysvshm.shm_clist` linked list and remove them.
```
/* Locking assumes this will only be called with task == current */
void exit_shm(struct task_struct *task)
{
	struct ipc_namespace *ns = task->nsproxy->ipc_ns;
	struct shmid_kernel *shp, *n;

	if (list_empty(&task->sysvshm.shm_clist))
		return;

	/*
	 * If kernel.shm_rmid_forced is not set then only keep track of
	 * which shmids are orphaned, so that a later set of the sysctl
	 * can clean them up.
	 */
	if (!ns->shm_rmid_forced) {
		down_read(&shm_ids(ns).rwsem);
		list_for_each_entry(shp, &task->sysvshm.shm_clist, shm_clist)
			shp->shm_creator = NULL;
		/*
		 * Only under read lock but we are only called on current
		 * so no entry on the list will be shared.
		 */
		list_del(&task->sysvshm.shm_clist);
		up_read(&shm_ids(ns).rwsem);
		return;
	}

	/*
	 * Destroy all already created segments, that were not yet mapped,
	 * and mark any mapped as orphan to cover the sysctl toggling.
	 * Destroy is skipped if shm_may_destroy() returns false.
	 */
	down_write(&shm_ids(ns).rwsem);
	list_for_each_entry_safe(shp, n, &task->sysvshm.shm_clist, shm_clist) {
		shp->shm_creator = NULL;

		if (shm_may_destroy(ns, shp)) {
			shm_lock_by_ptr(shp);
			shm_destroy(ns, shp);
		}
	}

	/* Remove the list head from any segments still attached. */
	list_del(&task->sysvshm.shm_clist);
	up_write(&shm_ids(ns).rwsem);
}
```

`exit_files()` releases opened file descriptors (or files->count -= 1).
```c
void exit_files(struct task_struct *tsk)
{
	struct files_struct * files = tsk->files;

	if (files) {
		task_lock(tsk);
		tsk->files = NULL;
		task_unlock(tsk);
		put_files_struct(files);
	}
}
```

`exit_fs()` releases file system data structures (or fs->count -= 1).
```c
void exit_fs(struct task_struct *tsk)
{
	struct fs_struct *fs = tsk->fs;

	if (fs) {
		int kill;
		task_lock(tsk);
		spin_lock(&fs->lock);
		tsk->fs = NULL;
		kill = !--fs->users;
		spin_unlock(&fs->lock);
		task_unlock(tsk);
		if (kill)
			free_fs_struct(fs);
	}
}
```

`exit_thread()` releases the thread struct.
The code below is only for arm processors.
```c
/*
 * Free current thread data structures etc..
 */
void exit_thread(struct task_struct *tsk)
{
	thread_notify(THREAD_NOTIFY_EXIT, task_thread_info(tsk));
}
```

`exit_umh()` releases data relevant to the usermode helper (if any).
For example, the process have invoked some userspace command from the kernel space.
```c
void __exit_umh(struct task_struct *tsk)
{
	struct umh_info *info;
	pid_t pid = tsk->pid;

	mutex_lock(&umh_list_lock);
	list_for_each_entry(info, &umh_list, list) {
		if (info->pid == pid) {
			list_del(&info->list);
			mutex_unlock(&umh_list_lock);
			goto out;
		}
	}
	mutex_unlock(&umh_list_lock);
	return;
out:
	if (info->cleanup)
		info->cleanup(info);
}
```

```c
	exit_notify(tsk, group_dead);
```
After the resource cleanups, I skip some code and only look at `exit_notify()`.
It signals the process's parent about the death of this process. 
The process is now a zombie waiting for the parent process to reap.

From reading Love's book[1], I saw there should be a `schedule()` by the end of `do_exit()`, but I don't see it.
I do not know how the newer kernel code schedules another process after `do_exit()`.

[1] Linux Kernel Development Third Edition, Robert Love (2010)

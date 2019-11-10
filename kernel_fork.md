## Linux implementation of process creation

Note: task, thread, process are the same thing here.

Hi `forks`, here I have some study notes about the Linux process creation.
The older textbook[1] says the fork() in libc calls __clone(), which wraps the clone() syscall.
Seems the newer kernel directly exposes sys_fork(), sys_vfork(), etc.
The common thing among these versions is that when it switches to kernel mode, the syscalls call _do_fork().
I will skip the user land call chain, and starts from the `_do_fork()` in `kernel/fork.c`.

```c
/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 *
 * args->exit_signal is expected to be checked for sanity by the caller.
 */
long _do_fork(struct kernel_clone_args *args)
{
  /* Zephyr: variable decals */
  u64 clone_flags = args->flags;
	struct completion vfork;
	struct pid *pid;
  /* Zephyr: this is the new task struct */
	struct task_struct *p;
	int trace = 0;
	long nr;

  /* Zephyr: We won't be looking deep at ptrace here */
	/*
	 * Determine whether and which event to report to ptracer.  When
	 * called from kernel_thread or CLONE_UNTRACED is explicitly
	 * requested, no event is reported; otherwise, report if the event
	 * for the type of forking is enabled.
	 */
	if (!(clone_flags & CLONE_UNTRACED)) {
		if (clone_flags & CLONE_VFORK)
			trace = PTRACE_EVENT_VFORK;
		else if (args->exit_signal != SIGCHLD)
			trace = PTRACE_EVENT_CLONE;
		else
			trace = PTRACE_EVENT_FORK;

		if (likely(!ptrace_event_enabled(current, trace)))
			trace = 0;
	}

  p = copy_process(NULL, trace, NUMA_NO_NODE, args);
```

p is the pointer to the new process' task struct.
It is assigned as the return value of `copy_process()`.

`copy_process()` does a lot of task struct initialization. 
The comments in the function are very well written.
```c
/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
static __latent_entropy struct task_struct *copy_process(
					struct pid *pid,
					int trace,
					int node,
					struct kernel_clone_args *args)
```

After some sanity checks, it delays the signal delivery so that nothing is handled during the clone.
If the calling process has pending signals, the folk() will fail.

Then, `dup_task_struct()` is called, and the return value is the new task struct.
```c
	retval = -ENOMEM;
	p = dup_task_struct(current, node);
	if (!p)
		goto fork_out;
```

At this time, the new task struct is the same as the calling process.
If the clone flag is set to `CLONE_CHILD_SETTID` or `CLONE_CHILD_CLEARTID`, then the user pointer `child_tidptr` will be copied to the corresponding variables in the task struct.
Looks like this is for passing the tid to user space.
Then, it inits mutex, `rt_mutex_init_task(p)`.

If the number of threads is above the system's limit, it simply fails this folk().
`if (atomic_read(&p->real_cred->user->processes) >= task_rlimit(p, RLIMIT_NPROC))`
Another check,
`if (nr_threads >= max_threads)`

It then set some flags that are not inheritable from the calling process.
Spin lock, `spin_lock_init()`.
CPU timer, `posix_cpu_timers_init`.

It also resets the pending signals for the new process.
Sigpending is "the set of signals that are pending for delivery to the calling thread (i.e., the signals which have been raised while blocked)." [2]

Once the basic init is done, it calls `sched_fork(clone_flags, p)` to "Perform scheduler related setup".

Then, it does some copy.
```c
/* copy all the process information */
	shm_init_task(p);
	retval = security_task_alloc(p, clone_flags);
	if (retval)
		goto bad_fork_cleanup_audit;
	retval = copy_semundo(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_security;
	retval = copy_files(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_semundo;
	retval = copy_fs(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_files;
	retval = copy_sighand(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_fs;
	retval = copy_signal(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_sighand;
	retval = copy_mm(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_signal;
	retval = copy_namespaces(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_mm;
	retval = copy_io(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_namespaces;
	retval = copy_thread_tls(clone_flags, args->stack, args->stack_size, p,
				 args->tls);
	if (retval)
		goto bad_fork_cleanup_io;
    ```
This is essentially duplicating the calling parent, tls, io, mm, fs, etc.

Then, a new pid is given.
```c
	if (pid != &init_struct_pid) {
		pid = alloc_pid(p->nsproxy->pid_ns_for_children);
		if (IS_ERR(pid)) {
			retval = PTR_ERR(pid);
			goto bad_fork_cleanup_thread;
		}
	}
  ```
  
Afterward, there is some tracer related init and scheduling related stuff.
I don't have time to look into them.

It's like filling out a birth certificate. 
After the child's name, it's time to record its parents into the task struct.
```c
	/* CLONE_PARENT re-uses the old parent */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
		p->real_parent = current->real_parent;
		p->parent_exec_id = current->parent_exec_id;
	} else {
		p->real_parent = current;
		p->parent_exec_id = current->self_exec_id;
	}
```

"If CLONE_PARENT is set, then the parent of the new child (as returned by getppid(2)) will be the same as that of the calling process." [3]

It comes to the end of copy_process().
There are some bookkeeping functions, which I skip.

Now, let's go back to _do_fork().
```c
/*
	 * Do this prior waking up the new thread - the thread pointer
	 * might get invalid after that point, if the thread exits quickly.
	 */
	trace_sched_process_fork(current, p);

	pid = get_task_pid(p, PIDTYPE_PID);
	nr = pid_vnr(pid);

	if (clone_flags & CLONE_PARENT_SETTID)
		put_user(nr, args->parent_tid);

	if (clone_flags & CLONE_VFORK) {
		p->vfork_done = &vfork;
		init_completion(&vfork);
		get_task_struct(p);
	}

	wake_up_new_task(p);

	/* forking complete and child started to run, tell ptracer */
	if (unlikely(trace))
		ptrace_event_pid(trace, pid);

	if (clone_flags & CLONE_VFORK) {
		if (!wait_for_vfork_done(p, &vfork))
			ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
	}

	put_pid(pid);
	return nr;
}
```

There isn't much left in `_do_folk()`.
It gets the pid of the new task, does some checks (if it is vfork), and finalizes by calling `wake_up_new_task()`.
The new task is ready to be scheduled.

###References:

[1] Linux Kernel Development third Edition, Robert Love (2010) 

[2] sigpending(2) - Linux man page, http://man7.org/linux/man-pages/man2/sigpending.2.html

[3] clone(2) - Linux manual page, http://man7.org/linux/man-pages/man2/clone.2.html

[4]
```c
/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */
 ```

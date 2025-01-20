/*
 * Copyright (c) 2019-21,2024 Andrew G Morgan <morgan@kernel.org>
 *
 * This file contains a collection of routines that perform thread
 * synchronization to ensure that a whole process is running as a
 * single privilege entity - independent of the number of threads.
 *
 * The whole file would be unnecessary if glibc exported an explicit
 * psx_syscall()-like function that leveraged the nptl:setxid
 * mechanism to synchronize thread state over the whole process.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>  /* pthread_atfork() */
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* Not reliably defined by *libc so, alias the direct syscall. */
#define _psx_gettid() syscall(SYS_gettid)

#include "psx_syscall.h"

#ifdef _PSX_DEBUG_MEMORY

static void *_psx_calloc(const char *file, const int line,
			 size_t nmemb, size_t size) {
    void *ptr = calloc(nmemb, size);
    fprintf(stderr, "psx:%d:%s:%d: calloc(%ld, %ld) -> %p\n", _psx_gettid(),
	    file, line, (long int)nmemb, (long int)size, ptr);
    return ptr;
}

static void _psx_free(const char *file, const int line, void *ptr) {
    fprintf(stderr, "psx:%d:%s:%d: free(%p)\n", _psx_gettid(), file, line, ptr);
    return free(ptr);
}

#define calloc(a, b)  _psx_calloc(__FILE__, __LINE__, a, b)
#define free(a)       _psx_free(__FILE__, __LINE__, a)

#endif /* def _PSX_DEBUG_MEMORY */

/*
 * psx_load_syscalls() can be weakly defined in dependent libraries to
 * provide a mechanism for a library to optionally leverage this psx
 * mechanism. Specifically, when libcap calls psx_load_sycalls() it
 * provides a weakly declared default that maps its system calls to
 * the regular system call functions. However, when linked with psx,
 * this function here overrides the syscalls to be the psx ones.
 */
void psx_load_syscalls(long int (**syscall_fn)(long int,
					      long int, long int, long int),
		       long int (**syscall6_fn)(long int,
					       long int, long int, long int,
					       long int, long int, long int))
{
    *syscall_fn = psx_syscall3;
    *syscall6_fn = psx_syscall6;
}

/*
 * Since we no longer (libcap-2.72) operate at the pthreads
 * abstraction, we need our own mutex etc implementation.
 */

typedef uint8_t psx_mutex_t;
#define _psx_mu_blocked(x)					\
    __atomic_test_and_set((void *)(x), __ATOMIC_SEQ_CST)
#define _psx_mu_lock(x)             \
    while (_psx_mu_blocked(x)) sched_yield()
#define _psx_mu_unlock(x)           \
    __atomic_clear((void *)(x), __ATOMIC_SEQ_CST)
#define _psx_mu_unlock_return(x, y) \
    do { _psx_mu_unlock(x); return (y); } while (0)
#define _psx_mu_cond_wait(x)       \
    do {                           \
        _psx_mu_unlock(x);         \
        sched_yield();             \
        _psx_mu_lock(x);           \
    } while (0)

typedef enum {
    _PSX_IDLE = 0,
    _PSX_SETUP = 1,
    _PSX_SYSCALL = 2,
    _PSX_EXITING = 3,
} psx_tracker_state_t;

/*
 * Tracking threads is done via a hash map of these objects.
 */
typedef struct psx_thread_ref_s {
    long sweep;
    long pending;
    long tid;
    long retval;
} psx_thread_ref_t;

/*
 * This global structure holds the global coordination state for
 * libcap's psx_syscall() support.
 */
static struct psx_tracker_s {
    long pid;
    char *pid_path;

    psx_mutex_t state_mu;
    psx_tracker_state_t state;
    int initialized;
    int incomplete;
    int psx_sig;
    psx_sensitivity_t sensitivity;

    struct {
	long syscall_nr;
	long arg1, arg2, arg3, arg4, arg5, arg6;
	int six;
	int active;
    } cmd;

    struct sigaction sig_action;
    struct sigaction chained_action;

    int map_entries;
    long map_mask;
    psx_thread_ref_t *map;
} psx_tracker;

/* psx_mix is our trivial hash mixing for the thread reference map */
static long psx_mix(long value) {
    return value ^ (value >> 7) ^ (value >> 13) ^ (value >> 23);
}

static void psx_set_map(int size)
{
    psx_tracker.map_entries = size;
    psx_tracker.map_mask = size - 1;
    psx_tracker.map = calloc(psx_tracker.map_entries, sizeof(psx_thread_ref_t));
}

/*
 * Forward declaration
 */
static void _psx_cleanup(void);

#define taskdir_fmt "/proc/%ld/task"

/*
 * Every time we detect a new process, the first thread to recognize
 * this resets some of the psx_tracker fields.
 */
static void _psx_proc_start(void)
{
    long pid = getpid();
    psx_tracker.pid = pid;
    if (psx_tracker.pid_path == NULL) {
	psx_tracker.pid_path = malloc(3*sizeof(pid) + 13 /* strlen(taskdir_fmt) */);
    }
    sprintf(psx_tracker.pid_path, taskdir_fmt, pid);
    psx_tracker.state = _PSX_IDLE;
    psx_tracker.cmd.active = 0;
}

static void _psx_new_proc(void)
{
    _psx_mu_unlock(&psx_tracker.state_mu);
    _psx_proc_start();
}

/*
 * psx_syscall_start initializes the psx subsystem. It is called
 * once and while locked.
 */
static void psx_syscall_start(void)
{
    /*
     * All sorts of things are assumed by Linux and glibc and/or musl
     * about signal handlers and which can be blocked. Go has its own
     * idiosyncrasies too. We tried SIGRTMAX until
     *
     *   https://bugzilla.kernel.org/show_bug.cgi?id=210533
     *
     * Our current strategy is to aggressively intercept SIGSYS,
     * something that is confirmed to be the case each time _PSX_SETUP
     * state is entered.
     */
    psx_tracker.psx_sig = SIGSYS;
    psx_set_map(256);
    atexit(_psx_cleanup);
    pthread_atfork(NULL, NULL, _psx_new_proc);
    psx_tracker.initialized = 1;
}

/*
 * This is the only way this library globally locks. Note, this is not
 * to be confused with psx_sig (interrupt) blocking - which is
 * performed when the signal handler is being confirmed.
 */
static void psx_lock(void)
{
    _psx_mu_lock(&psx_tracker.state_mu);
    if (!psx_tracker.initialized) {
	_psx_proc_start();
	psx_syscall_start();
    }
}

/*
 * This is the only way this library unlocks.
 */
static void psx_unlock(void)
{
    _psx_mu_unlock(&psx_tracker.state_mu);
}

/*
 * psx_cond_wait unlocks and waits to obtain the lock again, allowing
 * other code to run that may require the lock. This is the only way
 * the psx code waits like this.
 */
static void psx_cond_wait(void)
{
    _psx_mu_cond_wait(&psx_tracker.state_mu);
}

/*
 * _psx_cleanup its called when the program exits. It is used to free
 * any memory used by the thread tracker.
 */
static void _psx_cleanup(void) {
    /*
     * We enter the exiting state and never exit that. This cleanup is
     * only done at program exit.
     */
    psx_lock();
    while (psx_tracker.state != _PSX_IDLE) {
	psx_cond_wait();
    }
    psx_tracker.state = _PSX_EXITING;
    free(psx_tracker.map);
    free(psx_tracker.pid_path);
    psx_unlock();
}

/*
 * psx_posix_syscall_actor performs the system call on the targeted
 * thread and signals it is no longer pending.
 */
static void psx_posix_syscall_actor(int signum, siginfo_t *info, void *ignore) {
    /* bail early to the next in the chain if not something we recognize */
    if (signum != psx_tracker.psx_sig || !psx_tracker.cmd.active ||
	info == NULL || info->si_code != SI_TKILL ||
	info->si_pid != psx_tracker.pid) {
	if (psx_tracker.chained_action.sa_sigaction != 0) {
	    psx_tracker.chained_action.sa_sigaction(signum, info, ignore);
	}
	return;
    }

    long int retval;
    if (!psx_tracker.cmd.six) {
	retval = syscall(psx_tracker.cmd.syscall_nr,
			 psx_tracker.cmd.arg1,
			 psx_tracker.cmd.arg2,
			 psx_tracker.cmd.arg3);
    } else {
	retval = syscall(psx_tracker.cmd.syscall_nr,
			 psx_tracker.cmd.arg1,
			 psx_tracker.cmd.arg2,
			 psx_tracker.cmd.arg3,
			 psx_tracker.cmd.arg4,
			 psx_tracker.cmd.arg5,
			 psx_tracker.cmd.arg6);
    }

    /*
     * communicate the result of the thread's attempt to perform the
     * syscall.
     */
    long tid = _psx_gettid();

    psx_lock();
    psx_thread_ref_t *ref = &psx_tracker.map[psx_mix(tid) & psx_tracker.map_mask];
    ref->retval = retval;
    ref->pending = 0;
    /*
     * Block this thread until all threads have been interrupted.
     * This prevents threads clone()ing after running the syscall and
     * confusing the psx mechanism into thinking they need to also run
     * the syscall. They wouldn't need to run it, because they would
     * inherit the thread state of a syscall that has already
     * happened. However, figuring that out for an unblocked thread is
     * hard, so we prevent it from happening.
     */
    while (psx_tracker.cmd.active) {
	psx_cond_wait();
    }
    psx_tracker.incomplete--;
    psx_unlock();
}

/*
 * psx_confirm_sigaction (re)confirms that the psx handler is the
 * first handler to respond to the psx signal. It assumes that
 * psx_tracker.psx_sig has been set.
 */
static void psx_confirm_sigaction(void) {
    sigset_t mask, orig;
    struct sigaction existing_sa;

    /*
     * Block interrupts while potentially rewriting the handler.
     */
    sigemptyset(&mask);
    sigaddset(&mask, psx_tracker.psx_sig);
    sigprocmask(SIG_BLOCK, &mask, &orig);

    sigaction(psx_tracker.psx_sig, NULL, &existing_sa);
    if (existing_sa.sa_sigaction != psx_posix_syscall_actor) {
	memcpy(&psx_tracker.chained_action, &existing_sa, sizeof(struct sigaction));
	psx_tracker.sig_action.sa_sigaction = psx_posix_syscall_actor;
	sigemptyset(&psx_tracker.sig_action.sa_mask);
	psx_tracker.sig_action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigaction(psx_tracker.psx_sig, &psx_tracker.sig_action, NULL);
    }

    sigprocmask(SIG_SETMASK, &orig, NULL);
}

/*
 * under lock perform a state transition. Changing state is generally
 * done via this function. However, there is a single exception in
 * _psx_cleanup().
 */
static void psx_new_state(psx_tracker_state_t was, psx_tracker_state_t is)
{
    psx_lock();
    while (psx_tracker.state != was) {
	psx_cond_wait();
    }
    psx_tracker.state = is;
    psx_unlock();
}

long int psx_syscall3(long int syscall_nr,
		      long int arg1, long int arg2, long int arg3) {
    return psx_syscall(syscall_nr, arg1, arg2, arg3);
}

long int psx_syscall6(long int syscall_nr,
		      long int arg1, long int arg2, long int arg3,
		      long int arg4, long int arg5, long int arg6) {
    return psx_syscall(syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6);
}

/*
 * __psx_immediate_syscall does one syscall using the current
 * process.
 */
static long int __psx_immediate_syscall(long int syscall_nr,
					int count, long int *arg) {
    psx_tracker.cmd.syscall_nr = syscall_nr;
    psx_tracker.cmd.arg1 = count > 0 ? arg[0] : 0;
    psx_tracker.cmd.arg2 = count > 1 ? arg[1] : 0;
    psx_tracker.cmd.arg3 = count > 2 ? arg[2] : 0;

    if (count > 3) {
	psx_tracker.cmd.six = 1;
	psx_tracker.cmd.arg4 = arg[3];
	psx_tracker.cmd.arg5 = count > 4 ? arg[4] : 0;
	psx_tracker.cmd.arg6 = count > 5 ? arg[5] : 0;
	return syscall(syscall_nr,
		      psx_tracker.cmd.arg1,
		      psx_tracker.cmd.arg2,
		      psx_tracker.cmd.arg3,
		      psx_tracker.cmd.arg4,
		      psx_tracker.cmd.arg5,
		      psx_tracker.cmd.arg6);
    }

    psx_tracker.cmd.six = 0;
    return syscall(syscall_nr, psx_tracker.cmd.arg1,
		   psx_tracker.cmd.arg2, psx_tracker.cmd.arg3);
}

/*
 * glibc diropen/readdir API uses malloc/free internally and
 * empirically employ some sort of private mutex. The fact that psx
 * interrupts threads in arbitrary places guarantees that occasionally
 * the code in __psx_syscall() will interrupt functions in the middle
 * of performing these calls from other threads. Thus (and observed
 * with the libcap_psx_test) it's inevitable that this will interrupt
 * those functions while they hold a private lock. The net effect is
 * that we will fall into a deadlock condition if __psx_syscall() uses
 * diropen/readdir. So, we have opted to use raw system calls to read
 * directories instead. The whole of the psx functionality is really
 * low level, and only aimed at supporting Linux with its non-POSIX
 * LWP threading model, so we're OK with that.
 */

#define BUF_SIZE 4096

struct psx_linux_dirent64 {
    long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/*
 * __psx_syscall performs the syscall on the current thread and if no
 * error is detected it ensures that the syscall is also performed on
 * all (other) registered threads. The return code is the value for
 * the first invocation. It uses a trick to figure out how many
 * arguments the user has supplied. The other half of the trick is
 * provided by the macro psx_syscall() in the <sys/psx_syscall.h>
 * file. The trick is the 7th optional argument (8th over all) to
 * __psx_syscall is the count of arguments supplied to psx_syscall.
 *
 * User:
 *                       psx_syscall(nr, a, b);
 * Expanded by macro to:
 *                       __psx_syscall(nr, a, b, 6, 5, 4, 3, 2, 1, 0);
 * The eighth arg is now ------------------------------------^
 */
long int __psx_syscall(long int syscall_nr, ...) {
    long int arg[7];
    long i;

    va_list aptr;
    va_start(aptr, syscall_nr);
    for (i = 0; i < 7; i++) {
	arg[i] = va_arg(aptr, long int);
    }
    va_end(aptr);

    int count = arg[6];
    if (count < 0 || count > 6) {
	errno = EINVAL;
	return -1;
    }

    psx_new_state(_PSX_IDLE, _PSX_SETUP);
    psx_confirm_sigaction();

    long int ret = __psx_immediate_syscall(syscall_nr, count, arg);
    if (ret == -1) {
	psx_new_state(_PSX_SETUP, _PSX_IDLE);
	goto defer;
    }

    int restore_errno = errno;
    psx_new_state(_PSX_SETUP, _PSX_SYSCALL);
    psx_tracker.cmd.active = 1;

    /*
     * cleaning up before we start helps a fork()ed child not inherit
     * confusion from its parent.
     */
    memset(psx_tracker.map, 0,
	   psx_tracker.map_entries*sizeof(psx_thread_ref_t));

    long self = _psx_gettid(), sweep = 1;
    int some, incomplete, mismatch = 0, verified = 0;
    do {
	incomplete = 0;  /* count threads to return from signal handler */
	some = 0;        /* count threads still pending */
	sweep++;

	int fd = open(psx_tracker.pid_path, O_RDONLY | O_DIRECTORY);
	if (fd == -1) {
	    psx_lock();
	    fprintf(stderr, "failed to read %s - aborting\n", psx_tracker.pid_path);
	    kill(psx_tracker.pid, SIGKILL);
	}

	for (;;) {
	    char buf[BUF_SIZE];
	    size_t nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
	    if (nread == 0) {
		break;
	    } else if (nread < 0) {
		perror("getdents64 failed");
		kill(psx_tracker.pid, SIGKILL);
	    }

	    size_t offset;
	    unsigned short reclen;
	    for (offset = 0; offset < nread; offset += reclen) {
		/* deal with potential unaligned reads */
		memcpy(&reclen, buf + offset +
		       offsetof(struct psx_linux_dirent64, d_reclen),
		       sizeof(reclen));
		char *dir = (buf + offset +
			     offsetof(struct psx_linux_dirent64, d_name));
		long tid = atoi(dir);
		if (tid == 0 || tid == self) {
		    continue;
		}
		long mix = psx_mix(tid);
		long hval = mix & psx_tracker.map_mask;
		psx_thread_ref_t *x = &psx_tracker.map[hval];
		if (x->tid != tid) {
		    if (x->tid != 0) {
			/* a collision */
			long entries = psx_tracker.map_entries;
			long oval;
			for (oval = psx_mix(x->tid); ; entries <<= 1) {
			    long mask = entries - 1;
			    if (((oval ^ hval) & mask) != 0) {
				/* no more collisions */
				break;
			    }
			}
			psx_thread_ref_t *old = psx_tracker.map;
			long old_entries = psx_tracker.map_entries;
			psx_lock();
			psx_set_map(entries);
			long ok_sweep = sweep - 1;
			for (i = 0; i < old_entries; i++) {
			    psx_thread_ref_t *y = &old[i];
			    if (y->sweep < ok_sweep) {
				/* no longer care about this entry */
				continue;
			    }
			    psx_thread_ref_t *z = &psx_tracker.map[psx_mix(y->tid) & psx_tracker.map_mask];
			    z->tid = y->tid;
			    z->pending = y->pending;
			    z->retval = y->retval;
			    z->sweep = y->sweep;
			}
			psx_unlock();
			free(old);
			x = &psx_tracker.map[mix & psx_tracker.map_mask];
		    }
		    /* a new entry */
		    x->pending = 1;
		    x->tid = tid;
		    syscall(SYS_tkill, tid, psx_tracker.psx_sig);
		}
		psx_lock();
		x->sweep = sweep;
		incomplete++;
		if (x->pending) {
		    some++;
		} else if (x->retval != ret) {
		    mismatch = 1;
		}
		psx_unlock();
	    }
	}
	close(fd);
	if (some) {
	    verified = 0;
	    sched_yield();
	} else {
	    verified++;
	}
    } while (verified < 2);

    psx_lock();
    psx_tracker.incomplete = incomplete;
    psx_tracker.cmd.active = 0;
    while (psx_tracker.incomplete != 0) {
	psx_cond_wait();
    }
    psx_unlock();

    if (mismatch) {
	psx_lock();
	switch (psx_tracker.sensitivity) {
	case PSX_IGNORE:
	    break;
	default:
	    fprintf(stderr, "psx_syscall result differs.\n");
	    if (psx_tracker.cmd.six) {
		fprintf(stderr, "trap:%ld a123456=[%ld,%ld,%ld,%ld,%ld,%ld]\n",
			psx_tracker.cmd.syscall_nr,
			psx_tracker.cmd.arg1,
			psx_tracker.cmd.arg2,
			psx_tracker.cmd.arg3,
			psx_tracker.cmd.arg4,
			psx_tracker.cmd.arg5,
			psx_tracker.cmd.arg6);
	    } else {
		fprintf(stderr, "trap:%ld a123=[%ld,%ld,%ld]\n",
			psx_tracker.cmd.syscall_nr,
			psx_tracker.cmd.arg1,
			psx_tracker.cmd.arg2,
			psx_tracker.cmd.arg3);
	    }
	    fprintf(stderr, "results:");
	    for (i=0; i < psx_tracker.map_entries; i++) {
		psx_thread_ref_t *ref = &psx_tracker.map[i];
		if (ref->sweep != sweep) {
		    continue;
		}
		if (ret != ref->retval) {
		    fprintf(stderr, " %ld={%ld}", ref->tid, ref->retval);
		}
	    }
	    fprintf(stderr, " wanted={%ld}\n", ret);
	    if (psx_tracker.sensitivity == PSX_WARNING) {
		break;
	    }
	    kill(psx_tracker.pid, SIGKILL);
	}
	psx_unlock();
    }
    errno = restore_errno;
    psx_new_state(_PSX_SYSCALL, _PSX_IDLE);

defer:
    return ret;
}

/*
 * Change the PSX sensitivity level. If the threads appear to have
 * diverged in behavior, this can cause the library to notify the
 * user.
 */
int psx_set_sensitivity(psx_sensitivity_t level) {
    if (level < PSX_IGNORE || level > PSX_ERROR) {
	errno = EINVAL;
	return -1;
    }
    psx_lock();
    psx_tracker.sensitivity = level;
    psx_unlock();
    return 0;
}

#ifdef _LIBPSX_PTHREAD_LINKAGE

/*
 * psx requires this function to be provided by the linkage wrapping.
 */
extern int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
				 void *(*start_routine) (void *), void *arg);

/*
 * forward declaration to keep the compiler happy.
 */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			  void *(*start_routine) (void *), void *arg);

/*
 * __wrap_pthread_create is defined for legacy reasons, since whether
 * or not you use this wrapper to reach the __real_ functionality or
 * not isn't important to the psx mechanism any longer (since
 * libpsx-2.72).
 */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                         void *(*start_routine) (void *), void *arg) {
    return __real_pthread_create(thread, attr, start_routine, arg);
}

#endif /* _LIBPSX_PTHREAD_LINKAGE def */

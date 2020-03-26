#include <seccomp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/shm.h>
#include <linux/random.h>
#include <linux/vt.h>

#define ALLOW_SYSCALL(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) goto out; }
#define ALLOW_SOCKET(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_A0 (SCMP_CMP_EQ, call)) < 0) goto out; }
#define ALLOW_IOCTL(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1 (SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int) call), 0) < 0) goto out; }
#define ALLOW_ARG(call, arg) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, arg, arg), 0) < 0) goto out; }

int main(int argc, char *argv[])
{
    int rc = -1;
    scmp_filter_ctx ctx;
    int filter_fd;
    char *filter_path = "seccomp-filter.bpf";
    int w_xor_x = 1;

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL)
        goto out;

    /* Whitelist of syscalls */
    ALLOW_SYSCALL (_llseek);
    ALLOW_SYSCALL (_newselect);
    ALLOW_SYSCALL (accept);
    ALLOW_SYSCALL (accept4);
    ALLOW_SYSCALL (access);
    ALLOW_SYSCALL (alarm);
    ALLOW_SYSCALL (arch_prctl);
    ALLOW_SYSCALL (bind);
    ALLOW_SYSCALL (brk);
    ALLOW_SYSCALL (cacheflush);
    ALLOW_SYSCALL (capget);
    ALLOW_SYSCALL (capset);
    ALLOW_SYSCALL (chdir);
    ALLOW_SYSCALL (chmod);
    ALLOW_SYSCALL (chown);
    ALLOW_SYSCALL (chown32);
    ALLOW_SYSCALL (clock_getres);
    ALLOW_SYSCALL (clock_gettime);
    ALLOW_SYSCALL (clock_nanosleep);
    ALLOW_SYSCALL (clone);
    ALLOW_SYSCALL (close);
    ALLOW_SYSCALL (connect);
    ALLOW_SYSCALL (copy_file_range);
    ALLOW_SYSCALL (creat);
    ALLOW_SYSCALL (dup);
    ALLOW_SYSCALL (dup2);
    ALLOW_SYSCALL (dup3);
    ALLOW_SYSCALL (epoll_create);
    ALLOW_SYSCALL (epoll_create1);
    ALLOW_SYSCALL (epoll_ctl);
    ALLOW_SYSCALL (epoll_pwait);
    ALLOW_SYSCALL (epoll_wait);
    ALLOW_SYSCALL (eventfd);
    ALLOW_SYSCALL (eventfd2);
    ALLOW_SYSCALL (execve);
    ALLOW_SYSCALL (execveat);
    ALLOW_SYSCALL (exit);
    ALLOW_SYSCALL (exit_group);
    ALLOW_SYSCALL (faccessat);
    ALLOW_SYSCALL (fadvise64);
    ALLOW_SYSCALL (fadvise64_64);
    ALLOW_SYSCALL (fallocate);
    ALLOW_SYSCALL (fanotify_mark);
    ALLOW_SYSCALL (fchdir);
    ALLOW_SYSCALL (fchmod);
    ALLOW_SYSCALL (fchmodat);
    ALLOW_SYSCALL (fchown);
    ALLOW_SYSCALL (fchown32);
    ALLOW_SYSCALL (fchownat);
    ALLOW_SYSCALL (fcntl);
    ALLOW_SYSCALL (fcntl64);
    ALLOW_SYSCALL (fdatasync);
    ALLOW_SYSCALL (fgetxattr);
    ALLOW_SYSCALL (flistxattr);
    ALLOW_SYSCALL (flock);
    ALLOW_SYSCALL (fork);
    ALLOW_SYSCALL (fremovexattr);
    ALLOW_SYSCALL (fsetxattr);
    ALLOW_SYSCALL (fstat);
    ALLOW_SYSCALL (fstat64);
    ALLOW_SYSCALL (fstatat64);
    ALLOW_SYSCALL (fstatfs);
    ALLOW_SYSCALL (fstatfs64);
    ALLOW_SYSCALL (fsync);
    ALLOW_SYSCALL (ftruncate);
    ALLOW_SYSCALL (ftruncate64);
    ALLOW_SYSCALL (futex);
    ALLOW_SYSCALL (futimesat);
    ALLOW_SYSCALL (get_robust_list);
    ALLOW_SYSCALL (get_thread_area);
    ALLOW_SYSCALL (getcpu);
    ALLOW_SYSCALL (getcwd);
    ALLOW_SYSCALL (getdents);
    ALLOW_SYSCALL (getdents64);
    ALLOW_SYSCALL (getegid);
    ALLOW_SYSCALL (getegid32);
    ALLOW_SYSCALL (geteuid);
    ALLOW_SYSCALL (geteuid32);
    ALLOW_SYSCALL (getgid);
    ALLOW_SYSCALL (getgid32);
    ALLOW_SYSCALL (getgroups);
    ALLOW_SYSCALL (getgroups32);
    ALLOW_SYSCALL (getitimer);
    ALLOW_SYSCALL (getpeername);
    ALLOW_SYSCALL (getpgid);
    ALLOW_SYSCALL (getpgrp);
    ALLOW_SYSCALL (getpid);
    ALLOW_SYSCALL (getppid);
    ALLOW_SYSCALL (getpriority);
    ALLOW_SYSCALL (getrandom);
    ALLOW_SYSCALL (getresgid);
    ALLOW_SYSCALL (getresgid32);
    ALLOW_SYSCALL (getresuid);
    ALLOW_SYSCALL (getresuid32);
    ALLOW_SYSCALL (getrlimit);
    ALLOW_SYSCALL (getrusage);
    ALLOW_SYSCALL (getsid);
    ALLOW_SYSCALL (getsockname);
    ALLOW_SYSCALL (getsockopt);
    ALLOW_SYSCALL (gettid);
    ALLOW_SYSCALL (gettimeofday);
    ALLOW_SYSCALL (getuid);
    ALLOW_SYSCALL (getuid32);
    ALLOW_SYSCALL (getxattr);
    ALLOW_SYSCALL (inotify_add_watch);
    ALLOW_SYSCALL (inotify_init);
    ALLOW_SYSCALL (inotify_init1);
    ALLOW_SYSCALL (inotify_rm_watch);
    ALLOW_SYSCALL (ioprio_get);
    ALLOW_SYSCALL (ipc);
    ALLOW_SYSCALL (kill);
    ALLOW_SYSCALL (lchown);
    ALLOW_SYSCALL (lchown32);
    ALLOW_SYSCALL (lgetxattr);
    ALLOW_SYSCALL (link);
    ALLOW_SYSCALL (linkat);
    ALLOW_SYSCALL (listen);
    ALLOW_SYSCALL (listxattr);
    ALLOW_SYSCALL (llistxattr);
    ALLOW_SYSCALL (lremovexattr);
    ALLOW_SYSCALL (lseek);
    ALLOW_SYSCALL (lsetxattr);
    ALLOW_SYSCALL (lstat);
    ALLOW_SYSCALL (lstat64);
    ALLOW_SYSCALL (madvise);
    ALLOW_SYSCALL (membarrier);
    ALLOW_SYSCALL (memfd_create);
    ALLOW_SYSCALL (mincore);
    ALLOW_SYSCALL (mkdir);
    ALLOW_SYSCALL (mkdirat);
    ALLOW_SYSCALL (mknod);
    ALLOW_SYSCALL (mknodat);
    ALLOW_SYSCALL (mlock);
    ALLOW_SYSCALL (mlock2);
    ALLOW_SYSCALL (mlockall);
    ALLOW_SYSCALL (mq_getsetattr);
    ALLOW_SYSCALL (mq_notify);
    ALLOW_SYSCALL (mq_open);
    ALLOW_SYSCALL (mq_timedreceive);
    ALLOW_SYSCALL (mq_timedsend);
    ALLOW_SYSCALL (mq_unlink);
    ALLOW_SYSCALL (mremap);
    ALLOW_SYSCALL (msgctl);
    ALLOW_SYSCALL (msgget);
    ALLOW_SYSCALL (msgrcv);
    ALLOW_SYSCALL (msgsnd);
    ALLOW_SYSCALL (msync);
    ALLOW_SYSCALL (munlock);
    ALLOW_SYSCALL (munlockall);
    ALLOW_SYSCALL (munmap);
    ALLOW_SYSCALL (nanosleep);
    ALLOW_SYSCALL (nice);
    ALLOW_SYSCALL (oldfstat);
    ALLOW_SYSCALL (oldlstat);
    ALLOW_SYSCALL (oldolduname);
    ALLOW_SYSCALL (oldstat);
    ALLOW_SYSCALL (olduname);
    ALLOW_SYSCALL (open);
    ALLOW_SYSCALL (openat);
    ALLOW_SYSCALL (pause);
    ALLOW_SYSCALL (pipe);
    ALLOW_SYSCALL (pipe2);
    ALLOW_SYSCALL (pkey_alloc);
    ALLOW_SYSCALL (pkey_free);
    ALLOW_SYSCALL (poll);
    ALLOW_SYSCALL (ppoll);
    ALLOW_SYSCALL (prctl);
    ALLOW_SYSCALL (pread64);
    ALLOW_SYSCALL (preadv);
    ALLOW_SYSCALL (preadv2);
    ALLOW_SYSCALL (prlimit64);
    ALLOW_SYSCALL (pselect6);
    ALLOW_SYSCALL (pwrite64);
    ALLOW_SYSCALL (pwritev);
    ALLOW_SYSCALL (pwritev2);
    ALLOW_SYSCALL (quotactl);
    ALLOW_SYSCALL (read);
    ALLOW_SYSCALL (readahead);
    ALLOW_SYSCALL (readdir);
    ALLOW_SYSCALL (readlink);
    ALLOW_SYSCALL (readlinkat);
    ALLOW_SYSCALL (readv);
    ALLOW_SYSCALL (recv);
    ALLOW_SYSCALL (recvfrom);
    ALLOW_SYSCALL (recvmsg);
    ALLOW_SYSCALL (recvmmsg);
    ALLOW_SYSCALL (removexattr);
    ALLOW_SYSCALL (rename);
    ALLOW_SYSCALL (renameat);
    ALLOW_SYSCALL (renameat2);
    ALLOW_SYSCALL (restart_syscall);
    ALLOW_SYSCALL (rmdir);
    ALLOW_SYSCALL (rt_sigaction);
    ALLOW_SYSCALL (rt_sigpending);
    ALLOW_SYSCALL (rt_sigprocmask);
    ALLOW_SYSCALL (rt_sigqueueinfo);
    ALLOW_SYSCALL (rt_sigreturn);
    ALLOW_SYSCALL (rt_sigsuspend);
    ALLOW_SYSCALL (rt_sigtimedwait);
    ALLOW_SYSCALL (rt_tgsigqueueinfo);
    ALLOW_SYSCALL (s390_pci_mmio_read);
    ALLOW_SYSCALL (s390_pci_mmio_write);
    ALLOW_SYSCALL (s390_sthyi);
    ALLOW_SYSCALL (sched_get_priority_max);
    ALLOW_SYSCALL (sched_get_priority_min);
    ALLOW_SYSCALL (sched_getaffinity);
    ALLOW_SYSCALL (sched_getattr);
    ALLOW_SYSCALL (sched_getparam);
    ALLOW_SYSCALL (sched_getscheduler);
    ALLOW_SYSCALL (sched_rr_get_interval);
    ALLOW_SYSCALL (sched_setaffinity);
    ALLOW_SYSCALL (sched_setattr);
    ALLOW_SYSCALL (sched_setparam);
    ALLOW_SYSCALL (sched_setscheduler);
    ALLOW_SYSCALL (sched_yield);
    ALLOW_SYSCALL (seccomp);
    ALLOW_SYSCALL (select);
    ALLOW_SYSCALL (semctl);
    ALLOW_SYSCALL (semget);
    ALLOW_SYSCALL (semop);
    ALLOW_SYSCALL (semtimedop);
    ALLOW_SYSCALL (send);
    ALLOW_SYSCALL (sendfile);
    ALLOW_SYSCALL (sendfile64);
    ALLOW_SYSCALL (sendmmsg);
    ALLOW_SYSCALL (sendmsg);
    ALLOW_SYSCALL (sendto);
    ALLOW_SYSCALL (set_robust_list);
    ALLOW_SYSCALL (set_thread_area);
    ALLOW_SYSCALL (set_tid_address);
    ALLOW_SYSCALL (setfsgid);
    ALLOW_SYSCALL (setfsgid32);
    ALLOW_SYSCALL (setfsuid);
    ALLOW_SYSCALL (setfsuid32);
    ALLOW_SYSCALL (setgid);
    ALLOW_SYSCALL (setgid32);
    ALLOW_SYSCALL (setgroups);
    ALLOW_SYSCALL (setgroups32);
    ALLOW_SYSCALL (setitimer);
    ALLOW_SYSCALL (setns);
    ALLOW_SYSCALL (setpgid);
    ALLOW_SYSCALL (setpriority);
    ALLOW_SYSCALL (setregid);
    ALLOW_SYSCALL (setregid32);
    ALLOW_SYSCALL (setresgid);
    ALLOW_SYSCALL (setresgid32);
    ALLOW_SYSCALL (setresuid);
    ALLOW_SYSCALL (setresuid32);
    ALLOW_SYSCALL (setreuid);
    ALLOW_SYSCALL (setreuid32);
    ALLOW_SYSCALL (setrlimit);
    ALLOW_SYSCALL (setsid);
    ALLOW_SYSCALL (setsockopt);
    ALLOW_SYSCALL (setuid);
    ALLOW_SYSCALL (setuid32);
    ALLOW_SYSCALL (setxattr);
    ALLOW_SYSCALL (shmctl);
    ALLOW_SYSCALL (shmdt);
    ALLOW_SYSCALL (shmget);
    ALLOW_SYSCALL (shutdown);
    ALLOW_SYSCALL (sigaction);
    ALLOW_SYSCALL (sigaltstack);
    ALLOW_SYSCALL (signal);
    ALLOW_SYSCALL (signalfd);
    ALLOW_SYSCALL (signalfd4);
    ALLOW_SYSCALL (sigpending);
    ALLOW_SYSCALL (sigprocmask);
    ALLOW_SYSCALL (sigreturn);
    ALLOW_SYSCALL (sigsuspend);
    ALLOW_SYSCALL (socketcall);
    ALLOW_SYSCALL (socketpair);
    ALLOW_SYSCALL (splice);
    ALLOW_SYSCALL (spu_create);
    ALLOW_SYSCALL (spu_run);
    ALLOW_SYSCALL (stat);
    ALLOW_SYSCALL (stat64);
    ALLOW_SYSCALL (statfs);
    ALLOW_SYSCALL (statfs64);
    ALLOW_SYSCALL (statx);
    ALLOW_SYSCALL (symlink);
    ALLOW_SYSCALL (symlinkat);
    ALLOW_SYSCALL (sync);
    ALLOW_SYSCALL (sync_file_range);
    ALLOW_SYSCALL (sync_file_range2);
    ALLOW_SYSCALL (syncfs);
    ALLOW_SYSCALL (sysinfo);
    ALLOW_SYSCALL (tee);
    ALLOW_SYSCALL (tgkill);
    ALLOW_SYSCALL (time);
    ALLOW_SYSCALL (timer_create);
    ALLOW_SYSCALL (timer_delete);
    ALLOW_SYSCALL (timer_getoverrun);
    ALLOW_SYSCALL (timer_gettime);
    ALLOW_SYSCALL (timer_settime);
    ALLOW_SYSCALL (timerfd_create);
    ALLOW_SYSCALL (timerfd_gettime);
    ALLOW_SYSCALL (timerfd_settime);
    ALLOW_SYSCALL (times);
    ALLOW_SYSCALL (tkill);
    ALLOW_SYSCALL (truncate);
    ALLOW_SYSCALL (truncate64);
    ALLOW_SYSCALL (ugetrlimit);
    ALLOW_SYSCALL (umask);
    ALLOW_SYSCALL (uname);
    ALLOW_SYSCALL (unlink);
    ALLOW_SYSCALL (unlinkat);
    ALLOW_SYSCALL (unshare);
    ALLOW_SYSCALL (utime);
    ALLOW_SYSCALL (utimensat);
    ALLOW_SYSCALL (utimes);
    ALLOW_SYSCALL (vfork);
    ALLOW_SYSCALL (wait4);
    ALLOW_SYSCALL (waitid);
    ALLOW_SYSCALL (waitpid);
    ALLOW_SYSCALL (write);
    ALLOW_SYSCALL (writev);

    /* Whitelist of socket families */
    ALLOW_SOCKET (AF_INET);
    ALLOW_SOCKET (AF_INET6);
    ALLOW_SOCKET (AF_LOCAL);
    ALLOW_SOCKET (AF_NETLINK);
    ALLOW_SOCKET (AF_UNIX);
    ALLOW_SOCKET (AF_UNSPEC);

    /* Whitelist of ioctls */
    ALLOW_IOCTL (FIOCLEX);
    ALLOW_IOCTL (FIONBIO);
    ALLOW_IOCTL (FIONREAD);
    ALLOW_IOCTL (RNDGETENTCNT);
    ALLOW_IOCTL (TCGETS);
    ALLOW_IOCTL (TCSETS);
    ALLOW_IOCTL (TCSETSW);
    ALLOW_IOCTL (TIOCGPGRP);
    ALLOW_IOCTL (TIOCGWINSZ);
    ALLOW_IOCTL (TIOCSPGRP);
    ALLOW_IOCTL (TIOCSWINSZ);
    ALLOW_IOCTL (VT_GETSTATE);

    /* W^X */
    if (w_xor_x) {
        /* Disallow creating PROT_EXEC|PROT_WRITE mappings */
        ALLOW_ARG (mmap, PROT_NONE);
        ALLOW_ARG (mmap, PROT_READ);
        ALLOW_ARG (mmap, PROT_WRITE);
        ALLOW_ARG (mmap, PROT_EXEC);
        ALLOW_ARG (mmap, PROT_READ|PROT_EXEC);
        ALLOW_ARG (mmap, PROT_READ|PROT_WRITE);
        ALLOW_ARG (mmap2, PROT_NONE);
        ALLOW_ARG (mmap2, PROT_READ);
        ALLOW_ARG (mmap2, PROT_WRITE);
        ALLOW_ARG (mmap2, PROT_EXEC);
        ALLOW_ARG (mmap2, PROT_READ|PROT_EXEC);
        ALLOW_ARG (mmap2, PROT_READ|PROT_WRITE);

        /* Disallow changing mappings to PROT_EXEC */
        ALLOW_ARG (mprotect, PROT_NONE);
        ALLOW_ARG (mprotect, PROT_READ);
        ALLOW_ARG (mprotect, PROT_WRITE);
        ALLOW_ARG (mprotect, PROT_READ|PROT_WRITE);
        ALLOW_ARG (pkey_mprotect, PROT_NONE);
        ALLOW_ARG (pkey_mprotect, PROT_READ);
        ALLOW_ARG (pkey_mprotect, PROT_WRITE);
        ALLOW_ARG (pkey_mprotect, PROT_READ|PROT_WRITE);

        /* Disallow mapping shared memory segments as executable */
        ALLOW_ARG (shmat, 0);
        ALLOW_ARG (shmat, SHM_RND);
        ALLOW_ARG (shmat, SHM_RDONLY);
        ALLOW_ARG (shmat, SHM_REMAP);
    } else {
        ALLOW_SYSCALL (mmap);
        ALLOW_SYSCALL (mmap2);
        ALLOW_SYSCALL (mprotect);
        ALLOW_SYSCALL (pkey_mprotect);
        ALLOW_SYSCALL (shmat);
    }

    filter_fd = open(filter_path, O_CREAT | O_WRONLY, 0644);
    if (filter_fd == -1) {
        rc = -errno;
        goto out;
    }

    rc = seccomp_export_bpf(ctx, filter_fd);
    if (rc < 0) {
        close(filter_fd);
        goto out;
    }
    close(filter_fd);


 out:
    seccomp_release(ctx);
    return -rc;
}

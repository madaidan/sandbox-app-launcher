#include <seccomp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/shm.h>

/* TODO: Use a whitelist */

#define DENY_SYSCALL(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(call), 0) < 0) goto out; }
#define DENY_SOCKET(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1, SCMP_A0 (SCMP_CMP_EQ, call)) < 0) goto out; }
#define DENY_IOCTL(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(ioctl), 1, SCMP_A1 (SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int) call), 0) < 0) goto out; }

int main(int argc, char *argv[])
{
    int rc = -1;
    scmp_filter_ctx ctx;
    int filter_fd;
    char *filter_path = "/usr/share/sandbox-app-launcher/seccomp-filter.bpf";
    int w_xor_x = 1;

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
         goto out;

    /* Blacklist unused syscalls */
    DENY_SYSCALL (_sysctl);
    DENY_SYSCALL (acct);
    DENY_SYSCALL (add_key);
    DENY_SYSCALL (adjtimex);
    DENY_SYSCALL (afs_syscall);
    DENY_SYSCALL (bdflush);
    DENY_SYSCALL (bpf);
    DENY_SYSCALL (break);
    DENY_SYSCALL (chroot);
    DENY_SYSCALL (clock_adjtime);
    DENY_SYSCALL (clock_settime);
    DENY_SYSCALL (create_module);
    DENY_SYSCALL (delete_module);
    DENY_SYSCALL (fanotify_init);
    DENY_SYSCALL (finit_module);
    DENY_SYSCALL (ftime);
    DENY_SYSCALL (get_kernel_syms);
    DENY_SYSCALL (get_mempolicy);
    DENY_SYSCALL (getpmsg);
    DENY_SYSCALL (gtty);
    DENY_SYSCALL (init_module);
    DENY_SYSCALL (io_cancel);
    DENY_SYSCALL (io_destroy);
    DENY_SYSCALL (io_getevents);
    DENY_SYSCALL (io_setup);
    DENY_SYSCALL (io_submit);
    DENY_SYSCALL (ioperm);
    DENY_SYSCALL (iopl);
    DENY_SYSCALL (ioprio_set);
    DENY_SYSCALL (kcmp);
    DENY_SYSCALL (kexec_file_load);
    DENY_SYSCALL (kexec_load);
    DENY_SYSCALL (keyctl);
    DENY_SYSCALL (lock);
    DENY_SYSCALL (lookup_dcookie);
    DENY_SYSCALL (mbind);
    DENY_SYSCALL (migrate_pages);
    DENY_SYSCALL (modify_ldt);
    DENY_SYSCALL (mount);
    DENY_SYSCALL (move_pages);
    DENY_SYSCALL (mpx);
    DENY_SYSCALL (name_to_handle_at);
    DENY_SYSCALL (nfsservctl);
    DENY_SYSCALL (open_by_handle_at);
    DENY_SYSCALL (pciconfig_iobase);
    DENY_SYSCALL (pciconfig_read);
    DENY_SYSCALL (pciconfig_write);
    DENY_SYSCALL (perf_event_open);
    DENY_SYSCALL (personality);
    DENY_SYSCALL (pivot_root);
    DENY_SYSCALL (process_vm_readv);
    DENY_SYSCALL (process_vm_writev);
    DENY_SYSCALL (prof);
    DENY_SYSCALL (profil);
    DENY_SYSCALL (ptrace);
    DENY_SYSCALL (putpmsg);
    DENY_SYSCALL (query_module);
    DENY_SYSCALL (reboot);
    DENY_SYSCALL (remap_file_pages);
    DENY_SYSCALL (request_key);
    DENY_SYSCALL (rtas);
    DENY_SYSCALL (s390_runtime_instr);
    DENY_SYSCALL (security);
    DENY_SYSCALL (set_mempolicy);
    DENY_SYSCALL (setdomainname);
    DENY_SYSCALL (sethostname);
    DENY_SYSCALL (settimeofday);
    DENY_SYSCALL (sgetmask);
    DENY_SYSCALL (ssetmask);
    DENY_SYSCALL (stime);
    DENY_SYSCALL (stty);
    DENY_SYSCALL (subpage_prot);
    DENY_SYSCALL (swapoff);
    DENY_SYSCALL (swapon);
    DENY_SYSCALL (switch_endian);
    DENY_SYSCALL (sys_debug_setcontext);
    DENY_SYSCALL (sysfs);
    DENY_SYSCALL (syslog);
    DENY_SYSCALL (tuxcall);
    DENY_SYSCALL (ulimit);
    DENY_SYSCALL (umount);
    DENY_SYSCALL (umount2);
    DENY_SYSCALL (uselib);
    DENY_SYSCALL (userfaultfd);
    DENY_SYSCALL (ustat);
    DENY_SYSCALL (vhangup);
    DENY_SYSCALL (vm86);
    DENY_SYSCALL (vm86old);
    DENY_SYSCALL (vmsplice);
    DENY_SYSCALL (vserver);

    /* Blacklist unused socket families */
    DENY_SOCKET (AF_AX25);
    DENY_SOCKET (AF_BLUETOOTH);
    DENY_SOCKET (AF_CAN);
    DENY_SOCKET (AF_DECnet);
    DENY_SOCKET (AF_ECONET);
    DENY_SOCKET (AF_IB);
    DENY_SOCKET (AF_IPX);
    DENY_SOCKET (AF_LLC);
    DENY_SOCKET (AF_NETROM);
    DENY_SOCKET (AF_PHONET);
    DENY_SOCKET (AF_RDS);
    DENY_SOCKET (AF_ROSE);
    DENY_SOCKET (AF_RXRPC);
    DENY_SOCKET (AF_TIPC);
    DENY_SOCKET (AF_VSOCK);
    DENY_SOCKET (AF_X25);

    /* Blacklist unused ioctls */
    /* TIOCSETD can load vulnerable line disciplines to increase kernel attack surface */
    DENY_IOCTL (TIOCSETD);
    /* TIOCSTI has been used in sandbox escapes before and is unneeded */
    DENY_IOCTL (TIOCSTI);

    /* W^X */
    if (w_xor_x) {
        /* Disallow creating PROT_EXEC|PROT_WRITE mappings */
        if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(mmap), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC|PROT_WRITE, PROT_EXEC|PROT_WRITE), 0) < 0) goto out;
        if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(mmap2), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC|PROT_WRITE, PROT_EXEC|PROT_WRITE), 0) < 0) goto out;

        /* Disallow changing mappings to PROT_EXEC */
        if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(mprotect), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC), 0) < 0) goto out;
        if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(pkey_mprotect), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC), 0) < 0) goto out;

        /* Disallow mapping shared memory segments as executable */
        if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(shmat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, SHM_EXEC, SHM_EXEC), 0) < 0) goto out;
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

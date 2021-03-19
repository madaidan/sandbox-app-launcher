/*

Some syscalls may be required for an application to run but are too risky for us to
allow it to actually utilise. This provides a way to stub specific syscalls without
crashing a specific application by intercepting them with LD_PRELOAD.

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <dirent.h>

/*

SIOCGIFHWADDR is an ioctl that retrieves the MAC address of a network interface.
Due to privacy concerns, it's not permitted in the seccomp filter but this can break
some applications (particularly those using Qt).

*/
int *(*real_ioctl)(int fd, unsigned long request, char *argp);
int *ioctl(int fd, unsigned long request, char *argp) {
  real_ioctl = dlsym(RTLD_NEXT, "ioctl");

  // 0x8927 == SIOCGIFHWADDR
  if (request == 0x8927) {
    return 0;
  } else {
    return real_ioctl(fd, request, argp);
  }
}

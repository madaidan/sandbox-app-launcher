/*

TIOCSTI is a common sandbox escape method. The following code attempts to call the TIOCSTI ioctl
and should be stopped by the seccomp filter. Even if the ioctl was allowed in the seccomp filter,
bubblewrap's "--new-session" flag would prevent it from being used to escape.

Expected output with seccomp:

Bad system call (core dumped)

Expected output without seccomp (with just --new-session):

normal TIOCSTI: -1 (Operation not permitted)
high-bit-set TIOCSTI: -1 (Operation not permitted)

https://www.exploit-db.com/exploits/46594

*/

#define _GNU_SOURCE
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <errno.h>

static int ioctl64(int fd, unsigned long nr, void *arg) {
  errno = 0;
  return syscall(__NR_ioctl, fd, nr, arg);
}

int main(void) {
  int res;
  char pushmeback = '#';
  res = ioctl64(0, TIOCSTI, &pushmeback);
  printf("normal TIOCSTI: %d (%m)\n", res);
  res = ioctl64(0, TIOCSTI | (1UL<<32), &pushmeback);
  printf("high-bit-set TIOCSTI: %d (%m)\n", res);
}

/*

W^X - shmat()

The shmat() syscall can be used to map shared memory segments as executable.

The seccomp filter enforces strict W^X restrictions that should prevent this.

Expected output:

Bad system call (core dumped)

*/

#include <sys/types.h>
#include <sys/shm.h>
#include <stddef.h>

int main() {
  shmat(1, NULL, SHM_EXEC);
}

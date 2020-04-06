/*

W^X - mmap(), mmap2()

A memory mapping that is both writable and executable at the same time (PROT_WRITE|PROT_EXEC)
is dangerous because an attacker can write arbitrary code there to be executed.

This tries to create a memory mapping that is both writable and executable.
This also tests for mmap2() (an alternative to mmap()).

The seccomp filter enforces strict W^X restrictions that should prevent this.

Expected output:

Bad system call (core dumped)

*/

#include <sys/syscall.h>
#include <sys/mman.h>
#include <stddef.h>

int main() {
  mmap(NULL, 128, PROT_WRITE|PROT_EXEC, MAP_PRIVATE, -1, 0);
  mmap2(NULL, 128, PROT_WRITE|PROT_EXEC, MAP_PRIVATE, -1, 0);
}

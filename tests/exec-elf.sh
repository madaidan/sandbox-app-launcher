#!/bin/bash

## Test executing an ELF binary. This will be stopped by AppArmor's execution restrictions.
##
## Expected output:
##
## bash: ~/exec-elf: Permission denied
##
echo "#include <stdio.h>
int main () {
  printf(\"test\");
}" > ~/exec-elf.c
gcc ~/exec-elf.c -o ~/exec-elf
~/exec-elf

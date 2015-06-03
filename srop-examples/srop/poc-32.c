#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

void make_syscall(void) {
  asm(".intel_syntax noprefix\n");
  asm("int 0x80\n");
  asm("ret\n");
}

void set_stackptr(void) {
  asm(".intel_syntax noprefix\n");
  asm("pop esp\n");
}

void set_eax(void) {
  asm(".intel_syntax noprefix\n");
  asm("pop eax\n");
}

int read_input() {
  char buffer[512];
  printf("Buffer = %p\n", buffer);
  read(0, buffer, 600);
  return 0;
}

int main(int argc, char const *argv[])
{
  read_input();
	return 0;
}


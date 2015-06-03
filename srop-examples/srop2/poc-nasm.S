section .text

global _start

_test:
  sub esp, 0x100

  ; Leak the buffer address
  mov eax, 4
  mov ebx, 1
  push esp
  mov ecx, esp
  mov edx, 4
  int 0x80

  ; Read input that causes the buffer overflow
  mov eax, 3
  mov ebx, 0
  mov ecx, esp
  mov edx, 0x400
  int 0x80
  add esp, 0x104
  ret

open:
  mov eax, 5
  mov ebx, [esp+4]
  mov ecx, [esp+8]
  mov edx, [esp+0xc]
  int 0x80
  ret


_gadgets:
  pop esp
  ret
  pop eax
  ret
  mov eax, 0x77
  int 0x80
  ret
  add esp, 0x10
  ret

_printaddress:
  mov eax, 4
  mov ebx, 1
  call $+5
  pop ecx
  sub ecx, 31
  push ecx
  mov ecx, esp
  mov edx, 0x4
  int 0x80
  pop edx
  ret

_start:
  call _printaddress
  call _test
  mov eax, 1
  int 0x80


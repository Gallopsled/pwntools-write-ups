# Vortex 7

If you can satisfy a CRC requirement, you get stack buffer overflow.

Stack is executable, so we just replace the return address with a pointer to our buffer.

Uses hellman's excellent `r.sh` to make the stack layout consistent between normal execution, `gdb`, `strace`, etc.

```
int main(int argc, char **argv)
{
        char buf[58];
        u_int32_t hi;
        if((hi = crc32(0, argv[1], strlen(argv[1]))) == 0xe1ca95ee) {
                strcpy(buf, argv[1]);
        } else {
                printf("0x%08x\n", hi);
        }
}
```
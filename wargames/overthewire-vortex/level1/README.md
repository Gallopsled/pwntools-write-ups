# Vortex 1

Simple buffer underflow.  Decrement 'ptr' until it points at itself,
overwrite the high byte.

```c
int
main
(
)
{
    unsigned char   buf[512];
    unsigned char   *ptr = buf + (sizeof(buf) / 2);
    unsigned int    x;

    while ((x = getchar()) != EOF)
    {
        switch (x)
        {
         case '\n': print(buf, sizeof(buf));
             continue;
             break;

         case '\\':
             ptr--;
             break;

         default:

             if (((unsigned int)ptr & 0xff000000) == 0xca000000)
             {
                 setresuid(geteuid(), geteuid(), geteuid());
                 execlp("/bin/sh", "sh", "-i", NULL);
             }

             if (ptr > buf + sizeof(buf))
             {
                 continue;
             }

             ptr++[0] = x;
             break;
        }
    }
    printf("All done\n");
}
```
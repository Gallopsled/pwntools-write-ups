#include <sys/times.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int
main
(
)
{
    int i, j;
    unsigned int    seed;
    struct tms      tms;
    clock_t         num_ticks = 0;

    // from IDA
    num_ticks   = times(&tms);
    num_ticks   = tms.tms_cutime + tms.tms_stime + tms.tms_utime + tms.tms_cstime + num_ticks;
    num_ticks   += clock();
    num_ticks   += time(NULL);
    num_ticks   = 128
                  - ((unsigned char)(((unsigned int)(num_ticks >> 31) >> 24) + num_ticks)
                     - ((unsigned int)(num_ticks >> 31) >> 24));
    seed        = num_ticks + time(0);

    printf("seed=%#x\nticks=%#x\n", seed, num_ticks & 0x7fffffff);
    return 0;


}

#include <stdio.h>

void xprintf(char* format, ...)
{
    printf("arg0  = %p\n", &format);
    printf("format= %p\n", format);
    printf("sc    = %#x\n", getenv("sc"));
}

int main(int argc, char** argv) {
    if(argc) {
        printf("argc is nonzero\n");
        return 0;
    };
    xprintf(argv[3]);
    return 0;
}

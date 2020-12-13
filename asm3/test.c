#include <stdio.h>
extern int asm3(int, int, int);

//gcc test.c test.S -m32

int main()
{
        int a = asm3(0xd46c9935,0xdfe28722,0xb335450f);
        printf("%x", a);
}
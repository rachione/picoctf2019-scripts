#include <stdio.h>
extern int asm4(char*);

//gcc test.c test.S -m32

int main()
{
    int ans = asm4("picoCTF_c1373");

    printf("0x%x", ans);
}
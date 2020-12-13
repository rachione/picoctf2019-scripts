#include <stdio.h>
#include <time.h>

int main()
{

    srand(time(0));
    for (int i = 0; i < 10; i++)
    {
        printf("%d ", rand() & 0xF);
    }
}
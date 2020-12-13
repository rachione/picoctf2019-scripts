#include<stdio.h>

int main(){
    char *a = malloc(20);     
    char *b = malloc(20);     
    char *c = malloc(20);     
    char *d = malloc(20);     
    printf("%x\n",a);
    printf("%x\n",b);
    printf("%x\n",c);
    printf("%x\n",d);
    /*
        ff4e8160
        ff4e8180
        ff4e81a0
        ff4e81c0
    */

    free(a);
    free(c);

    char *e = malloc(10);           
    char *f = malloc(20);  
    printf("%x\n",e);
    printf("%x\n",f);  
    /*
        ff4e83f0
        ff4e81a0
    */       
            
}
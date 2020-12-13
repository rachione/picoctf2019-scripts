#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUF_SIZE 32
#define FLAG_LEN 64
#define KEY_LEN 4

void display_flag() {
  char buf[FLAG_LEN];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }
  fgets(buf,FLAG_LEN,f);
  puts(buf);
  fflush(stdout);
}

char key[KEY_LEN];
void read_canary() {
  FILE *f = fopen("/problems/canary_4_221260def5087dde9326fb0649b434a7/canary.txt","r");
  if (f == NULL) {
    printf("[ERROR]: Trying to Read Canary\n");
    exit(0);
  }
  fread(key,sizeof(char),KEY_LEN,f);
  fclose(f);
}

void vuln(){
   char canary[KEY_LEN]; //var_10   
   char buf[BUF_SIZE]; //var_30
   char user_len[BUF_SIZE]; //var_50  

   int count; //var_54
   int x = 0;
   memcpy(canary,key,KEY_LEN);
   printf("Please enter the length of the entry:\n> ");

   while (x<BUF_SIZE) {
      read(0,user_len+x,1);
      if (user_len[x]=='\n') break;
      x++;
   }
   sscanf(user_len,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,key,KEY_LEN)) {
      printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  int i;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  read_canary();
  vuln();

  return 0;
}
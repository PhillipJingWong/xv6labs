#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"
#include "kernel/riscv.h"

int
main(int argc, char *argv[])
{
  // your code here.  you should write the secret to fd 2 using write
  // (e.g., write(2, secret, 8)
  //char full

  /*
  char *end = sbrk(PGSIZE*32);
  end = end + 9 * PGSIZE;
  strcpy(end, "my very very very secret pw is:   ");
  strcpy(end+32, argv[1]);
  */

  char *end = sbrk(PGSIZE*32);
  end= end + 8*PGSIZE;
  //end-=9*PGSIZE;

  //strcpy(end, end+32);


  //char secret[8];

  //try read the memory that was copied into *end
  //strcpy(secret,*end);
  //everything written here is piped to output in attacktest
  //write(2, secret, 8);

  //printf("Value: %s \n",secret);

  printf("Values:");
  //printf("%s", end+32);
  //printf("%s ", end+16);
  fprintf(2, end+16,8);
  printf("\n");
  exit(0);
  //exit(1);
}

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{

  if(argc>2){
    printf("Invalid Input\n");
    exit(1);
  }

  int val = atoi(argv[1]);

  if(val>0){
  sleep(val);
    //sleep(argc);

  exit(0);
  }
  else{
    printf("Invalid Input\n");
    exit(1);
  }

}

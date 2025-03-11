#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

void primes(int *fd){
  int value;
  read(*fd, &value, 4);
  printf("prime %d\n", value);

  int temp=-1;

  int p[2];
  pipe(p);

  while(1){
    int n= read(*fd, &temp, 4);
    if(n<=0){
      break;
    }
    if(temp%value >0){
      write(p[1],&temp,4);}

  }

  if(temp==-1){
    close(*fd);
    close(p[1]);
    close(p[0]);
    return;
  }

  int pid=fork();
  if(pid==0){
  close(*fd);
  close(p[1]);
  primes(&p[0]);
  close(p[0]);
}else{
  close(*fd);
  close(p[1]);
  close(p[0]);
  wait(0);
}

}

int
main(int argc, char *argv[])
{

  int p[2];
  pipe(p);

  printf("prime 2\n");

  for(int i=3; i<36;i++){

    if(i%2 >0){
    write(p[1],&i,4);}

  }

  close(p[1]);
  primes(&p[0]);
  //close(p[0]);

  exit(0);
}

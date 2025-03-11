#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{

  char buf[5];

  int p[2];
  pipe(p);
  int pid = fork();
  //pid=getpid();


  if (pid>0){
    //dup(p[0]);
    //close(p[0]);
    write(p[1], "ping", 4);
    close(p[1]);

  }
  if(pid==0){

    read(p[0], buf,4);
    printf("%d: received %s\n", pid, buf);
    write(p[1], "pong", 4);
    close(p[0]);
    close(p[1]);

    exit(0);
  }
  if (pid>0){
    wait((int *)0);
    //close(p[1]);
    read(p[0], buf, 4);
    printf("%d: received %s\n", pid, buf);
    close(p[0]);
    exit(0);
  }

  exit(0);

}

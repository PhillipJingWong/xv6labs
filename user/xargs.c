#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/param.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"

void execute(char *line, char *args[], int skip){
  int ws=1;
  char **a, *l;

  a=&args[skip];
  l=line;
  while(*l != '\0'){

    if(*l == ' '){
      if(!ws){
        *l='\0';
        a++;
      }
      ws=1;
    }
    else{
      if(ws){
        *a=l;
      }
      ws=0;
    }

    l++;
  }


int pid=fork();
if(pid==0){
  exec(args[0], args);
}else{
  wait((int *)0);

}


}

int
main(int argc, char *argv[])
{
  char *args[MAXARG];
  char buf[512], *b;
  b=buf;

  //copy cmdline into args array for exec
  for(int i=1;i<argc;i++){
    args[i-1]=argv[i];
  }

  //read in input
  while(read(0, b, 1)>0){
    if(*b=='\n'){
      *b='\0';
      execute(buf, args, argc -1);
      b=buf; //no need to clear because its null terminated anyway
    }else{
      b++;
    }

  }

  //no newline after it (final command)
  //check if anything has been written to the buffer
  if(b!=buf){
    *b='\0';
    execute(buf, args, argc-1);
  }

  exit(0);
}

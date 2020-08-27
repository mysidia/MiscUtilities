/*
  C Mysidia 2008
  Get cluster summary data
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

struct {
  const char * community,  *host, *oid;
}
 entry[] =
 {
       { "acluster", "a-pixfirewall", "1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6" },
       { "bcluster", "b-pixfirewall", "1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6" },
       { "cluster",  "c-pixfirewall", "1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6" }
 };


int do_spawn(int q)
{
   int p = fork();
   int status;  
   int j;

   switch(p) {
      case -1:
             perror("fork");
             return -1;

      case 0:
             execl("/usr/bin/snmpwalk","snmpwalk", "-t", "2", "-Ov", "-v1", "-c", entry[q].community,  entry[q].host, entry[q].oid);
             perror("exec");
             exit(1);
      default:
            j=wait(&status);

            if ( WIFEXITED(status) ) {
                 if ( WEXITSTATUS(status) != 0 ) {
                       exit(1);
                 }
            }
            break;
   }
}


int main()
{
    do_spawn(0);
    do_spawn(1);
    do_spawn(2);
}

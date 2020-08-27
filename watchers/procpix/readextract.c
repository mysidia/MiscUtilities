// Copyright (C) 2006 Mysidia 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char**argv)
{
   char buf[8192] = "";
   char destbuf[512] = "";
   char proj[50] = "";
   char *s, *t;
   char tempbuf[512];
   FILE *fp;
   int fd;

   if (argc > 1 && argv[1] && argv[1][0]) {
       sprintf(proj, "-%.20s", argv[1]);
   }

   if ( umask( S_IWGRP | S_IWOTH ) < 0 ) {
        perror("umask");
        return 1;
   }
 
  
   sprintf(tempbuf, "/var/www/html/tmp/tail.extract%.20s.XXXXXX", proj);
   sprintf(destbuf, "/var/www/html/tmp/tail.extract%.20s", proj);

   fd = mkstemp(tempbuf);   
   if (fd == -1) {
       perror("mkstemp");

       return 1;
   }

   fchmod(fd, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH );


   fp = fdopen(fd, "w");


   if (!fp) {
         perror("fopen");
         abort();
   }

   while ( fgets(buf, 512, stdin) ) {
           s = strchr(buf, '%');

           if (!s)
                 continue;

           t = strchr(s, ' ');

           if (!t)
                 continue;

           if ( fprintf(fp, "- %s", t+1) == -1 ) {
                  perror("fprintf");
           }

          /* new code to handle long lines - jh (02/01/2008) */
           if (!strchr(buf, '\n')) {
               fprintf(fp, "___lp_Truncated___\n");

               while ( fgets(buf, 512, stdin) ) {
                    //  fprintf(fp, "%s", buf);
                      if (strchr(buf, '\n'))
                          break;
               }
           } /* jh */
   }

   if (fclose(fp)) {
       perror("fclose");

       return 0;
   }

   if ( rename(tempbuf, destbuf) < 0 ) {
       perror("rename");

       return 2;
   }
        

   return 0;
}

// Copyright (C) Mysidia, 2013, All Rights Reserved

// Monitors a directory at an interval; triggers a script to process new items.

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>

#define QUEUE_PATH "/home/weeklyprod/queue"
#define QUEUE_WORKER_SCRIPT "/home/weeklyprod/queue_process.pl"
#define QUEUE_WORKER_CMD    "queue_process"

int access(const char *pathname, int mode);

int main()
{ 
     DIR *queuedir;
     char buf[2048];
     struct dirent * de;
     pid_t cproc;

#if 0
     if ( fork() ) {
         setpgrp();
         
         exit(0);
     }
     close(0);
     close(1);
#endif

     if ( chdir(QUEUE_PATH)  == -1 ) { 
          perror("chdir");
          exit(2);
     }

     while ( 1 ) {
            queuedir = opendir(QUEUE_PATH);
            if (!queuedir) {
                 perror("opendir("QUEUE_PATH")");
                 sleep(300);
            }
            while ( de = readdir(queuedir) ) {
                 if (!de->d_name || 
                      !strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")
                       || *de->d_name != 'w' )
                      continue;
                 printf("%s\n", de->d_name);
                 sprintf(buf, "%.512s", de->d_name);
                 buf[0] = 'a';

                 cproc = fork();
                 if (cproc == -1) {
                      perror("fork");
                      sleep(600);
                 } else if (cproc == 0) {
                       if ( rename(de->d_name, buf) == 0 ) {
                            int retcode = execl(QUEUE_WORKER_SCRIPT, QUEUE_WORKER_CMD, buf, NULL);

                            if (retcode == -1) {
                                   perror("exec");
                                   rename(buf, de->d_name);
                                   sleep(15);
                                   exit(2);
                            }
                       } else { 
                            perror("rename"); 
                       }
                       exit(1);
                 } else {
                       int status;
                       waitpid(cproc, &status, 0);
                       if (WIFEXITED(status) && ( WEXITSTATUS(status) !=0  || WEXITSTATUS(status) == 255)) {
                            rename(buf, de->d_name);
                            sleep(10);
                       } else if (WIFEXITED(status) && WEXITSTATUS(status)!=0) { printf("%d\n", WEXITSTATUS(status)); }
                       sleep(5);
                 }
            }
            closedir(queuedir);
            sleep(25);
     }      
}


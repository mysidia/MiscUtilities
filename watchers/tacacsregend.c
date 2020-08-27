// Copyright (C) Mysidia, 2013, 2015, All Rights Reserved

// Requestwatcher updated for specifics of tacplusregend

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>

#include <sys/types.h>
#include <pwd.h>

#define DEFAULT_AU_UID 507
#define DEFAULT_AU_GID 507


int access(const char *pathname, int mode);

int main(int argc, char **argv)
{ 
     char buf[2048];
     struct dirent * de;
     pid_t cproc;
     uid_t   authmanuid = DEFAULT_AU_UID;
     gid_t   authmangid = DEFAULT_AU_GID;
     struct passwd *pw;
     int     secondary_server = 0;

     fprintf(stderr, "Startup (stderr)\n");
     printf("S-\n");


     if ( argc < 2 || !argv[1] || !strcmp(argv[1], "PRIMARY") || !strcmp(argv[1], "MASTER") ) {
          secondary_server  = 0;
     } else if ( argc >= 1 && argv[1] && (!strcmp(argv[1],"SECONDARY") || !strcmp(argv[1], "SLAVE")) ) {
          secondary_server = 1;
     }

     if (pw = getpwnam("authman")) {
            if (pw->pw_uid != DEFAULT_AU_UID) 
                 authmanuid = pw->pw_uid;
            if (pw->pw_gid != DEFAULT_AU_GID)
                 authmangid = pw->pw_gid;
     } else { 
            perror("getpwnam: defaulting to uid<DEFAULT_AU_UID>");
     }

     if (setgid(authmangid) == -1) {
        perror("setgid"); 
     }

     if (setuid(authmanuid) == -1) {
        perror("setuid");
     }

     setenv("RAILS_ENV", "production", 1);

     if (!secondary_server) 
     {
         if ( chdir("/var/webapps/authman")  == -1 ) { 
              perror("chdir");
              exit(2);
         }
     } else {
         if ( chdir("/var/db/authman")  == -1 ) {
              perror("chdir");
              exit(2);
         }
     }

     while ( 1 ) {
            if (access("/var/db/authman/upd_config.m", (R_OK|W_OK)) == 0) {
                cproc = fork();
                if (cproc == -1) {
                    perror("fork");
                    sleep(120);
                } else if (cproc == 0) {
                    int retcode = execlp("/bin/sh","sh", "/usr/local/bin/tacacs_check_restart.sh", NULL);
                    if (retcode == -1) {
                         perror("exec");
                         sleep(30);
                         exit(2);
                     } else {
                          perror("check");
                     }
                     exit(1);
//
                } else {
                 int status;
                 waitpid(cproc, &status, 0);

                 if (WIFEXITED(status) && ( WEXITSTATUS(status) !=0  || WEXITSTATUS(status) == 255)) {
                      sleep(30);
                 } else if (WIFEXITED(status) && WEXITSTATUS(status)!=0) { printf("%d\n", WEXITSTATUS(status)); }
                 else if (WIFEXITED(status) && ( WEXITSTATUS(status)==0 )) {
                      printf("CHECK SUCCESS\n");
                      unlink("/var/db/authman/upd_config.m");
                 }
                 sleep(20);

                }
                continue;
            }

            if (access("/var/db/authman/upd_users.m", (R_OK|W_OK) ) != 0) {
                sleep(13);
                continue;
            }

            if (!secondary_server)
            {
            cproc = fork();
            if (cproc == -1) {
                perror("fork");
                sleep(120);
             } else if (cproc == 0 && !secondary_server) {
                int retcode = execlp("rake","rake", "generate_tacacs_config", NULL);

                if (retcode == -1) {
                     perror("exec");
                     sleep(30);
                     exit(2);
                 } else { 
                      perror("rename"); 
                 }
                 exit(1);
             } else if (cproc == 0) {
                 exit(0);
             } else {
                 int status;
                 waitpid(cproc, &status, 0);

                 if (WIFEXITED(status) && ( WEXITSTATUS(status) !=0  || WEXITSTATUS(status) == 255)) {
                      sleep(30);
                 } else if (WIFEXITED(status) && WEXITSTATUS(status)!=0) { printf("%d\n", WEXITSTATUS(status)); }
                 else if (WIFEXITED(status) && ( WEXITSTATUS(status)==0 )) {
                      printf("RAKE SUCCESS\n");
                      unlink("/var/db/authman/upd_users.m");
                 }
              }   

             }
              sleep(30);   
     }
}


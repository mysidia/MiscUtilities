/*
# Copyright (C) 2007 Mysidia 
*/
#include <unistd.h>
#include <stdlib.h>
int access(const char *pathname, int mode);


int main()
{ 
     if ( fork() ) {
         setpgrp();
         
         exit(0);
     }

     close(0);
     close(1);


     while ( 1 ) {
            if ( access("/home/errorparse/errorparse.cmdbuf", R_OK) == 0 ) {
                 system("/home/errorparse/error_read.work.pl");
                 sleep(25);
            }
            sleep(15);
     }      
}

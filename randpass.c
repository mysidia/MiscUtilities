/*
 * Copyright (C) Mysidia 2010,  All Rights Reserved
 *  
 * Create a random password of requested length  using /dev/random as a source
 * of randomness
 *
 * Command-line Tool:
 *    ./randpass <LENGTH>
 *  For example:   ./randpass 24
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(argc,argv) 
  int argc;  char *argv[];
{ 
   char buf[1024] = "";   /* Buffer to read file data into */

                 /* Buffer size, default password length */ 
   int bufsize = sizeof(buf), passlen = 15;

                 /* Repeat read this many times per password character */
   int repeats = 30;

   /*  List of characters to use in passwords */
//   char maptop[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-.,/~!#$%^&*()+=[]{}|;:\"<>/";
   //char maptop[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
   char maptop[]   = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-.,#%^&+=:;<>";

   unsigned char random_byteval;
   int i, j, k;

   /* Open /dev/random */
   FILE* fp = fopen("/dev/random","r");

   if (argv && argc > 1 && argv[1] && (j = atoi(argv[1])) && 0 < passlen  ) 
       passlen = j;

   if (fp) { 
     for(i = 0; i < passlen; i++) {

       /* Read in that a buffer full of random bytes,  and XOR each byte together */
       /* repeat 'repeats'  time, for each  password character to be generated  */

       /* The entropy of a XOR result, is the same as the byte with highest entropy being XORed.   */
       for(k = 0; k < repeats; k++) {
          if (  fread(buf, bufsize, 1, fp)  >= 1 ) {
              for(j = 0 ; j < bufsize ; j++) {
                  random_byteval ^= buf[j];
              }
           } else {
              perror("fread");
	      exit(0);
          }
       }

       /* pick a password character in the chosen character set. */
       printf("%c", maptop[ random_byteval %  strlen(maptop) ]  );

     }
   } else  perror("fopen");

   puts("");
}

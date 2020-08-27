// Copyright (C) Mysidia 2016
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MULX  500

void *  my_memmove(void* dest,  void* source,   size_t n)
{
  char x[n];
  for( int i = 0 ; i < n ;  (x[i] =  *(char *)(source + i)) , i++ ) ;
  for( int i = 0 ; i < n ;  (*(char *)(dest + i) = x[i]) , i++ )  ;
  return dest;
}

void memmove_test(char*pre, char*d, char*a, char*b, int c, char* note) {
    char aeq[512*(MULX+1)]="", beq[512*(MULX+1)]="", *ares, *bres;

    strcpy(d, pre);
    ares = my_memmove(a, b, c);
    strcpy(aeq, d);

    strcpy(d, pre);
    bres = memmove(a, b, c);
    strcpy (beq, d);

    if ((bres && !ares) || (ares && !bres)) {
        fprintf(stderr, "Test Failed:  Return code disagrees!!\n");
        abort();
    }

    if ( ares != bres ) {
        fprintf(stderr, "Test Failed:  Return code disagrees!!\n");
        abort();
    }

    if (memcmp(aeq,beq, c)) {
        fprintf(stderr, "Test Failed:  Answers were not equal!\n");
        abort();
    }
}


int main(){
       FILE* fp = fopen("/dev/urandom", "r");
       char pre[512*(MULX+1)]="";
       char buf[512*(MULX+1)]="";
	   int m,n,o;

       if (!fp) { 
           perror("Test fails: No functional random device");
           abort();
       }
	   
       strcpy(pre, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghhijklmnopqrstuvwxyz!@#$%^&*()_-=+=\\|__________________________");
     if ( fread(pre + 100,   512, (MULX-1),   fp) < 20 ) {
          perror("Test fails: No functional random device");
          abort();
     }
     fclose(fp);
	   
     for(m = 0; m < 200; m += 10) {
          for(n = 0 ; n < 200 ; n += 10) {
              for(o = 256*(MULX/10); o < 256*(MULX-1); o+= (MULX*2) ) {
                  memmove_test(pre,buf,buf+m, buf+n, o, "");
              }
          }
       }
   puts("Congratulations.");
}	   	   
	

   

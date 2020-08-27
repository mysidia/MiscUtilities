// Copyright (C) Mysidia 2016
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void *  my_memmove(void* dest,  void* source,   size_t n)
{
return dest;
      char *ps = (char*)source, *pd = (char*)dest;   int j;
      if (dest == source || n < 1)
          return dest;

      if (  dest <= source && (dest + n ) >= source) {
            while ( pd < (char*)source ) {
			       *(pd++) = *(ps++);
			        n--;
            }
          my_memmove(pd, ps, n);
          return dest;
      }

      if ( dest > source  &&  (source + n) > dest  ) {
           j =  (source + n) - dest  ;
           my_memmove(  dest + j,  source  + j,  n - j );
           n -= (n-j);
      }
      for( j = n-1 ; j >= 0 ; j-- ) {	  
          pd[ j ] =  ps [ j ];	  
      } 	   

      return dest;
}

void memmove_test(char*pre, char*d, char*a, char*b, int c, char* note) {
    char aeq[512]="", beq[512]="", *ares, *bres;

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
       char pre[512]="";
       char buf[512]="";
	   int m,n,o;

       if (!fp) { 
           perror("Test fails: No functional random device");
           abort();
       }
	   
       strcpy(pre, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghhijklmnopqrstuvwxyz!@#$%^&*()_-=+=\\|__________________________");
     if ( fread(pre + 100,   10, 20,   fp) < 20 ) {
          perror("Test fails: No functional random device");
          abort();
     }
     fclose(fp);
	   
     for(m = 0; m < 200; m++) {
          for(n = 0 ; n < 200 ; n++) {
              for(o = 1; o < 256; o++) {
                  memmove_test(pre,buf,buf+m, buf+n, o, "");
              }
          }
       }
   puts("Congratulations.");
}	   	   
	

   

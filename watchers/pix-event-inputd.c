/*
  Copyright (C) 2007, Mysidia  All Rights Reserved
201009
*/
#include <stdio.h>
#include <string.h>
#include <pcre.h>
#define SENDMAIL "/usr/lib/sendmail -t"
#define ALARM2_FROM_ADDRESS "root@local"
#define ALARM2_TO_ADDRESS = "example@local"

struct       _hook;
void         do_nothing( struct _hook*,  char *, int );
void         do_count  ( struct _hook*,  char *, int );
void         do_alarm2 ( struct _hook*,  char *, int );

struct _hook {
    /* expression to match against */ char *   match_on;
    /* map   predicate:  match(trigger)  ->  action */ void (* trigger_map_h)( struct _hook*, char*, int   match_type);
    /* map   predicate:  !match(trigger) -> action */  void (* trigger_map_m)( struct _hook*, char*, int  match_type);

    /* human-readable description */  char* description;

    /* regular expression */          pcre *   regex; 

    /* counters */ int      hitcount,   hitcount_recent,  misscount,  misses_recent;
                   time_t   firsttime, firsthit,   lasthit,  lastalert;
}
 hooks [ ] = {
      /*                                        HIT Action        MISS action */
      {    "^\\S+ \\S+ \\S+ \\S+ %PIX-.-201009:.*",  do_alarm2,         do_count,      "PIX 201009 Alert"       },
      {    (char*) 0,                           do_nothing,       0              },
 };


void
do_nothing  (struct _hook* h,  char *b, int c) { }


int main()
{
     FILE * fp = fopen("/var/log/pix.pipe", "r");
     char buf[1024] = "";
     char const* errptr;
     int  erroffset, i, result, ovector[25] = {}, found=0;

     if (!fp) {
          perror("fopen");
          sleep(1);
          exit(1);
     }

     for ( i = 0; hooks[i].match_on != NULL;  i++ ) {
           hooks[i].regex  = pcre_compile (  hooks[i].match_on, 0,  &errptr, &erroffset, NULL  ) ;
           hooks[i].hitcount = hooks[i].hitcount_recent = hooks[i].misses_recent = hooks[i].firsthit = hooks[i].lasthit = 0;
   
           if ( hooks[i].regex == NULL ) {
                 sleep(1);
                 abort();
           }
     }

     while ( fgets(buf, 512, fp) ) 
     {
            found = 0;
            for ( i = 0; hooks[i].match_on != NULL;  i++ ) {
                   result = pcre_exec(hooks[i].regex, NULL, buf, strlen(buf), 0, /*options*/0,
                                    ovector, sizeof(ovector)/sizeof(ovector[0]));
                   if ( result >= 0 ) {
                        found = 1; 
                        break;
                   } else {
                        if (hooks[i].trigger_map_m != 0)
                            (* hooks[i].trigger_map_m)(&hooks[i], buf, 0);
                        /* hooks[i].misses_recent++; */
                   }
            } 

            if ( found == 1 )  {
                  (* hooks[i].trigger_map_h)(&hooks[i], buf, 1);
            }
     }
}



void
do_count(  struct _hook*  h,   char * buf,    int  match_type )
{
       if ( h->misscount == 0 &&  h->hitcount == 0 )
            h->firsttime = time(0);

       if  (match_type == 1 )
       {
           if (  h->hitcount == 0 ) {
                h->firsthit = time(0);
           }
           h->hitcount++;
           h->hitcount_recent++;
           h->lasthit = time(0);
      } else {
           h->misses_recent++;
           h->misscount++;
      }
}



#define MATCH_MISS 0
#define MATCH_HIT  1

void
do_alarm2(  struct _hook* h,  char* buf,  int  match_type) 
{ 
      FILE * mail_pipe;

      if ( time(0) >  h->lasthit + 800 ) {
            h->hitcount_recent = 0;
            h->misses_recent = 0;
      }
      do_count(h, buf, match_type);

      if (match_type == MATCH_MISS)
           return;


      if ( h->hitcount_recent ==  2  ||
           ( h->hitcount_recent > 2  &&  ((h->hitcount_recent % 10) == 0) &&  (h->lastalert + /*120*/ 240) < time(0)  ) )
      {
           printf("SEND_MAIL [%s] [rh=%d,h=%d,rm=%d,m=%d,ft=%d,fh=%d,lh=%d,la=%d] \n", h->description,
                                           h->hitcount_recent, h->hitcount, h->misses_recent, h->misscount,
                                           h->firsttime, h->firsthit, h->lasthit, h->lastalert); 
           mail_pipe = popen(SENDMAIL, "w");
           if (mail_pipe == NULL)   return;

           fprintf(mail_pipe, "From: %s\n"
                      "To: %s\n"
                      "Subject: %s\n",    ALARM2_FROM_ADDRESS,  ALARM2_TO_ADDRESS,  h->description);

          fprintf(mail_pipe, "\n\nAlert message: [%s]\n",  h->description);
          fprintf(mail_pipe, "\n\nPattern:  match-on %s\n", h->match_on);
          fprintf(mail_pipe, "Recent Hits: %d,  Total hits: %d\n", h->hitcount_recent, h->hitcount);
          fprintf(mail_pipe, "Recent Misses: %d, Total misses: %d\n",  h->misses_recent, h->misscount);
          fprintf(mail_pipe, "Firsttime: %d, Firsthit: %d, Lasthit: %d, Lastalert: %d\n\nText: ",
                              h->firsttime, h->firsthit, h->lasthit, h->lastalert);
          fputs(buf, mail_pipe);
          fputs("\n\n.\n", mail_pipe);

          fflush(mail_pipe);
          pclose(mail_pipe);

          h->lastalert = time(0);
     }

}






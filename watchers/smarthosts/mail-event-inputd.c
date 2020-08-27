/*!
   mail-event-inputd.c:   Adapted from pix-event-inputd.c
   Copyright (C) 2008 Mysidia 
*/
#include <stdio.h>
#include <string.h>
#include <pcre.h>
#include <math.h>

#define SENDMAIL "/usr/lib/sendmail -t"
#define ALARM2_FROM_ADDRESS "<mailalarm@localhost>"
#define ALARM2_TO_ADDRESS "<devnull@localhost>"

#define GEN_NOTES "\n\nAlarm was triggered by mail-event-inputd  while reading syslog output named pipe.\n"

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

struct       _hook;
/*! No actions to be taken */
void         do_nothing( struct _hook*,  char *, int );    

/*! Increment the counters;  The standard pattern `Miss' action */ 
void         do_count  ( struct _hook*,  char *, int );   

/*! do_alarm2
 *
 * This `Hit' action sends e-mails like do_alarm();   However,
 * the `Miss' action must be do_count(), and;  instead of sending a message
 * for every hit,  sp_threshold must be crossed.
 *
 * After sp_threshold is crossed: the notice entry will latch.  A new e-mail 
 * is not sent until we reboot, count increases by a factor of 10,   2 hours, 
 * Or  no more hits for 800 seconds.
 */
void         do_alarm2 ( struct _hook*,  char *, int );
void         do_okmail ( struct _hook*,  char *, int );

struct _patternexemption {
    char * label;
    char * exempt_pattern;
    char * and_label;
    pcre * exempt_regex;
    long long label_id;
    long long and_label_id;
} exemption_patterns[ ] = {

  /*  This is a list of pattern exceptions to ignore/skip a match found in the log entry */

  /*  An exception is bound to an alert rule by setting the  exemption_label in  the rule. */
  /*  If any pattern with the same label matches, then this log line will be suppressed, */
  /*  Unless the and_Label is also populated,  and none of the entries under the AND label also match. */

  /* Label                       Pattern          AND_LABEL                   */
  { "QUOTA_REJECT_EXCEPTIONS",   "",              "SMTP_REJECT_EXCEPTIONS",   0  },

  { "SMTP_REJECT_EXCEPTIONS",    "example.net", 0,                    0  },
  { "SMTP_REJECT_EXCEPTIONS",    "@example.com",     0,                    0  },
  { "SMTP_REJECT_EXCEPTIONS",    "from=<>",       "REPEAT_BOUNCERS",    0  }, 
  { "SMTP_REJECT_EXCEPTIONS",    "from=,",       "REPEAT_BOUNCERS",    0  },


  { "REPEAT_BOUNCERS",           "helo=imail.example.org",    0,             0  },
  { "REPEAT_BOUNCERS",           "helo=\<imail.example.org\>",  0,             0  }, 
  {          (char*)0,           (char*)0 ,       0,                    0  }
};



struct _hook {
    /* expression to match against */ char *   match_on;
    /* map   predicate:  match(trigger)  ->  action */ void (* trigger_map_h)( struct _hook*, char*, int   match_type);
    /* map   predicate:  !match(trigger) -> action */  void (* trigger_map_m)( struct _hook*, char*, int  match_type);

    /* human-readable description */  char* description;

    int sp_threshold;              /*  Wait until log entry appears this many times before invoking HIT Action   */
    int severity;                  /*  Severity Level of Hit Entry,  for Trigger actions that require it */
	
	char * exemption_label;        /*  Exception label, in case we don't want an alert to fire off based on other text in the log entry */


	long long exemption_label_id;

    /* regular expression */          pcre *   regex; 

    /* counters */ int      hitcount,   hitcount_recent,  misscount,  misses_recent;
                   time_t   firsttime, firsthit,   lasthit,  lastalert; 
}
 hooks [ ] = {
      /*  Match Pattern                                                       */
      /*                                        HIT Action        MISS action               SP_Threshold      Severity */
      /* Feb 22 00:43:58 smtp cbpolicyd[21797]: module=Quotas, action=defer ... */


	{    "A process serving application pool '[^']+' failed to respond to a ping. The process id was",  do_alarm2, do_count, "IIS Ping Fail",1, 10 },
	{    "DsGetSiteName failed with error 0x51F.", do_alarm2, do_count, "Cannot get AD Site Name", 1, 10 },


        {    "module=Quotas, action=reject",  do_alarm2, do_count, "SMTP Relay: quota rejects", 0, 4,  "SMTP_REJECT_EXCEPTIONS" },
        {    "This domains mailbox's are full", do_alarm2, do_count, "Mail server: domain is over quota", 0, 6},
        /* {    "possible SYN flooding on port 25. Sending cookies.",     do_alarm2,  do_count,  "Mail server syncookies", 0, 0}, */
        {    "write queue file:"        ,                do_alarm2,         do_count,      "Mail server alert", 0, 10 },
        {    ": No space left on device",                do_alarm2,         do_count,      "Mail server space alert", 0, 10 },
        {   "Delivery Delayed",                         do_alarm2,         do_count,      "Delivery Delayed", 0, 5 },
        {   "Delivery delayed",                         do_alarm2,         do_count,      "Delivery Delayed", 0, 5 },
        {   "Warning: message delayed",                 do_alarm2,         do_count,      "Warning: Message Delayed", 0, 5 },
        {  "Messages from \\S+ temporarily deferred due to user complaints",  do_alarm2,  do_count,  "Messages delayed due to user complaints", 0, 3 },
        /*    "reject: RCPT from blah",              do_alarm2,         do_count,       "Warning: reject at input", 0 }, */
        {   "reject: RCPT from mail\\.example\\.com",      do_alarm2,         do_count,       "Warning: reject at input", 0, 4 },
        {   "reject: RCPT from [a-z]+\\.example\\.org", do_alarm2,         do_count,       "Warning: reject at input", 0, 4 },
        {   "reject: RCPT from [a-z]+\\.example\\.org",   do_alarm2,         do_count,       "Warning: reject at input", 0, 4 },
        {   "reject: RCPT from [a-z]+\\.example\\.xx\\.xx\\.us", do_alarm2,      do_count,       "Warning: reject at input", 0, 4 },
        {   "reject: RCPT from [a-z]+\\.example\\.org",         do_alarm2,         do_count,       "Warning: reject at input", 0, 4 },
        {   "All Domain Controller Servers in use are not responding", do_alarm2, do_count,      "Warning: DC server not responding", 0, 10 },
        { "All Global Catalog Servers in forest DC=rsdla,DC=local are not responding:", do_alarm2, do_count, "Warning: GC servers not responding", 0, 10},

        {   "postfix/postfix-script: stopping the Postfix mail system", do_alarm2, do_count,     "Postfix shutting down", 0, 7 },
        {   "shutdown: shutting down ",          do_alarm2,      do_count,      "Server shutting down", 1, 7 },


        {  "Watson report about to be sent for process", do_alarm2, do_count, "Watson report", 2, 3 },

        {  "A request to write to the file", do_alarm2, do_count, "Possible hung task", 1, 10 },
        {  "task \\S+ blocked for more than [0-9]+ seconds.", do_alarm2, do_count, "Possible hung task", 1, 10 },
        {  "JBD2: Detected IO errors while flushing file data", do_alarm2, do_count, "Possible hung task", 1, 10},

         { "Available disk space for the database logs",                         do_alarm2,         do_count,     "Exchange Transaction Logs", 0, 10 },

         { "Information Store.*rejecting update operations",  do_alarm2, do_count, "Exchange Information Store", 0, 10 },
         { "database copy .* appears to have run out of disk space",  do_alarm2, do_count, "Exchange Information Store", 0, 10 },

         { "the copy of database .* on this server encountered an error during the mount operation. For more information",  do_alarm2, do_count, "ExchangeDB", 0, 10 },
         { "Exchange Search Indexer failed to enable the Mailbox Database", do_alarm2, do_count, "ExchangeIndexer", 0, 5},

        {   "^\\S+\\s+\\S+ \\S+ \\S+ postfix\\S+ table .* has changed -- restarting",        do_alarm2,      do_count,      "Postfix reloading", 1 },

        {   "^\\S+\\s+\\S+ \\S+ \\S+ postfix\\S+ starting the Postfix mail system",  do_alarm2,  do_count,   "Postfix starting", 1, 3 },

       /*Dec 10 14:04:07 smtp postfix/smtpd[1535]: table hash:/etc/postfix/senders has changed -- restarting
Dec 10 14:04:17 smtp postfix/postfix-script: starting the Postfix mail system
*/

      {    (char*) 0,                           do_nothing,       0              },
 };


/*!
 * Find an  enumerated ID number that was assigned to a specific  exception Label
 */
long long
get_exemption_label_id( char* label ) {
     int i;

     if (!label || !*label) 
          return 0;


     for(i = 0;  exemption_patterns[i].label != NULL ; i++) {
          if (  strcmp(exemption_patterns[i].label, label) )
              continue;

          return exemption_patterns[i].label_id;
     }

    return 0;
}
 
 


/*!
 * Evaluate potential exceptions against this pattern.
 *
 * If an exemption matches, then the pattern rule will be overridden and not match.
 */
int
is_this_hit_exempt ( struct _hook*  h, int label_id,  char *logged_buf,  int logged_buf_len,  int*  result1_vector,   int result1_len) {
     int i, result;
     int ovector[25];

     /* When the alerter has no exceptions: */
     if (!h ||  !h->exemption_label ) {
          return 0;
     }

     for(i = 0;  exemption_patterns[i].label != NULL ; i++) {
          /* if (  strcmp(exemption_patterns[i].label, label) ) */

          if ( label_id == 0 ||  exemption_patterns[i].label_id != label_id )
               continue; 

          result = -1;

          if ( exemption_patterns[i].exempt_regex != NULL )
              result = pcre_exec(exemption_patterns[i].exempt_regex, NULL, logged_buf, logged_buf_len, 0, /*options*/0,
                       ovector, sizeof(ovector)/sizeof(ovector[0]));
          else if ( exemption_patterns[i].exempt_pattern == '\0' && exemption_patterns[i].and_label != NULL &&  exemption_patterns[i].and_label[0] != '\0' ) 
              result = 0;
 
           if ( result >= 0 ) {
               /*  
                *  If we found a match in the exception list,  then this is an exception,  As long as any
                *  AND condition is true  (if this exception pattern has any logical AND conditions on it)
                */
			   
                    if (exemption_patterns[i].and_label == NULL || exemption_patterns[i].and_label[0] == '\0')
                        return 1;

                    return is_this_hit_exempt(  h,  exemption_patterns[i].and_label_id,  logged_buf, logged_buf_len,  ovector,  sizeof(ovector)/sizeof(ovector[0])  );
           }
       
     }

     return 0;   /* No exception found */
}





void
do_nothing  (struct _hook* h,  char *b, int c) { 

  /* Take no actions */

}


int main()
{
     FILE * fp = fopen("/var/log/mailwatch.pipe", "r");
     char buf[1024] = "";
     char const* errptr;
     int  erroffset, i, result, ovector[25] = {}, found=0, j;
     long long x = 0;

     if (!fp) {
          perror("fopen");
          sleep(1);
          exit(1);
     }

     for( i = 0 ; exemption_patterns[i].label != NULL ; i++ )
         exemption_patterns[i].label_id = 0;

     for( i = 0, x = 20000; exemption_patterns[i].label != NULL ; i++) {
          if ( exemption_patterns[i].exempt_pattern[0] == '\0' )
                exemption_patterns[i].exempt_regex  = 0;
          else  {
                exemption_patterns[i].exempt_regex = pcre_compile( exemption_patterns[i].exempt_pattern, 0, &errptr, &erroffset, NULL  );

                if (exemption_patterns[i].exempt_regex == NULL) {
                    fprintf(stderr, "Error compiling pcre exemption%d - %s\n", i, exempt_pattern);
                    sleep(1);
                    abort();
                }
          }
          j = get_exemption_label_id( exemption_patterns[i].label);

          if ( j == 0 )
              exemption_patterns[i].label_id = x++;
          exemption_patterns[i].and_label_id = 0;
     }

     for( i = 0; exemption_patterns[i].label != NULL ; i++) { 
         if (exemption_patterns[i].and_label == 0 || exemption_patterns[i].and_label[0] == '\0')
             continue;

         exemption_patterns[i].and_label_id = get_exemption_label_id( exemption_patterns[i].and_label  );
     }

     for ( i = 0; hooks[i].match_on != NULL;  i++ ) {
           hooks[i].regex  = pcre_compile (  hooks[i].match_on, 0,  &errptr, &erroffset, NULL  ) ;
           hooks[i].hitcount = hooks[i].hitcount_recent = hooks[i].misses_recent = hooks[i].firsthit = hooks[i].lasthit = 0;
           hooks[i].exemption_label_id = get_exemption_label_id( hooks[i].exemption_label  );
   
           if ( hooks[i].regex == NULL ) {
                 fprintf(stderr, "Error compiling pcre hook%d - %s\n", i, hooks[i].match_on);
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
                   if ( result >= 0 &&
				        is_this_hit_exempt( &hooks[i], hooks[i].exemption_label_id, buf, strlen(buf),  ovector,  sizeof(ovector)/sizeof(ovector[i]) ) == 0 ) 
				   {
					   /* Found a non-excepted match! */ 
                        found = 1; 
                        break;
                   } else {
                        if (hooks[i].trigger_map_m != 0)
                            (* hooks[i].trigger_map_m)(&hooks[i], buf, 0);
                        /* hooks[i].misses_recent++; */
                   }
            } 

            if ( found == 1 )  {
				  /* One or more non-excepted matches means this log line is a Hit! */
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
do_okmail(  struct _hook* h,  char* buf,  int  match_type)
{
      if ( time(0) >  h->lasthit + 800 ) {
            h->hitcount_recent = 0;
            h->misses_recent = 0;
      }

     do_count(h, buf, match_type);
     if (match_type == MATCH_MISS)
          return;
}

void
do_alarm2(  struct _hook* h,  char* buf,  int  match_type) 
{ 
      FILE * mail_pipe;
      int     i_threshold = 2;
      int     i_alert_denom = 10;
      time_t  current_timestamp = time(0);

      if ( current_timestamp >  h->lasthit + 800 ) { /* Reset recent hits, if last hit was longer than 13.3 mins ago. */
            h->hitcount_recent = 0;
            h->misses_recent = 0;
      }
      do_count(h, buf, match_type);  /* update counters */

      if (match_type == MATCH_MISS)  /* don't alert on a log line that didn't match */
           return;

      if (h->sp_threshold > 0 && h->sp_threshold != 2)
            i_threshold = h->sp_threshold;

      if ( h->hitcount_recent >= 99 && (h->lastalert + 7200)  >= current_timestamp ) {
           i_alert_denom *= 10;   /* if 100 hits,  then backoff alert rate 1/10 for this pattern 2 hours, or until the burst stops */

           if ( h->hitcount_recent >= 999 && (h->lastalert + 3600)  >= current_timestamp ) {
                              /* if 999 hits, then backoff alert rate 1/100 for this pattern 1 hour, or until the burst stops  */
               i_alert_denom *= 10; 

               if ( h->hitcount_recent >= 9999 ) {
                   int i_temporary =  MIN(8, MAX(0, (int) log10(h->hitcount_recent)  - 1));

                   i_alert_denom =  MAX(10000, (int) pow(10, i_temporary));
               }
           }
      } 


      if ( h->hitcount_recent ==  i_threshold  ||
           ( h->hitcount_recent > i_threshold  &&  ((h->hitcount_recent % i_alert_denom) == 0) &&  (h->lastalert + /*120*/ 240) < time(0)  ) )
      {
           printf("SEND_MAIL [%s] [rh=%d,h=%d,rm=%d,m=%d,ft=%d,fh=%d,lh=%d,la=%d] \n", h->description,
                                           h->hitcount_recent, h->hitcount, h->misses_recent, h->misscount,
                                           h->firsttime, h->firsthit, h->lasthit, h->lastalert); 
           mail_pipe = popen(SENDMAIL, "w");
           if (mail_pipe == NULL)   return;

           fprintf(mail_pipe, "From: %s\n"
                      "To: %s\n"
                      "Subject: [maileventd] %s\n",    ALARM2_FROM_ADDRESS,  ALARM2_TO_ADDRESS,  h->description);

          fprintf(mail_pipe, "\n\nAlert message: [%s]\n",  h->description);
          fprintf(mail_pipe, "\n\nPattern:  match-on %s\n", h->match_on);
          fprintf(mail_pipe, "Recent Hits: %d,  Total hits: %d\n", h->hitcount_recent, h->hitcount);
          fprintf(mail_pipe, "Recent Misses: %d, Total misses: %d\n",  h->misses_recent, h->misscount);
          fprintf(mail_pipe, "Event severity class: %d\n", h->severity );
          fprintf(mail_pipe, "Firsttime: %d, Firsthit: %d, Lasthit: %d, Lastalert: %d\n\nText: ",
                              h->firsttime, h->firsthit, h->lasthit, h->lastalert);
          fputs(buf, mail_pipe);
          fprintf(mail_pipe, GEN_NOTES);
          fputs("\n\n.\n", mail_pipe);

          fflush(mail_pipe);
          pclose(mail_pipe);

          h->lastalert = time(0);
     }

}






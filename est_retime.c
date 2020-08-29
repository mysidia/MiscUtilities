/* (C) 2005 Mysidia */
/*

  Estimates the time retention period of data that can be retained for a rolling queue
  where the queue is allowed to utilize the specified amount of disk space.

  The calculation is based on "samples"  of the rate of new data arriving over time that
  begins to fill the queue.

*/
#define _BSD_SOURCE

#include<stdio.h>
#define _XOPEN_SOURCE 
#include<time.h>
#include<locale.h>
#include<stdlib.h>
#include<string.h>

extern  char *strptime(const char *s, const char *format, struct tm *tm);

/*const char start[] = "03-04-2005 09:00:00";*/
const   char start[] = "03-04-2005 09:00:00";
/*const int  megabytes_retention = 205927;*/
const int    megabytes_retention = 460000  + 50000 + 25000; 

struct  usage_fifo_entry {
        time_t at_time;
        int usage_value;
        int delta_value;
        int retained;
        int cumulative_retained;
};

static struct usage_fifo_entry * usage_fifo_buffer = 0;
static int  usage_fifo_count = 0 ;
static int  usage_fifo_allocated = 0 ;
static time_t cal_start_s_v=0;

void initialize_usage_buffer() {
     if (usage_fifo_buffer != NULL)
          return;

     usage_fifo_buffer = calloc( 1,  sizeof(struct usage_fifo_entry) *   (usage_fifo_count + 10)  );
     if (usage_fifo_buffer == NULL) {
        perror("Out of memory: unable to allocate initial buffer");
        abort();
     }
     usage_fifo_allocated  = (usage_fifo_count + 10);
}

/* Garbage collect after Retained Megabytes is exceeded */
void cleanup_usage_buffer() {
  int x = 0;

  while(usage_fifo_count > x &&   usage_fifo_buffer[x].retained <= 0) {
        x = x + 1;
  }

  if (x >= usage_fifo_count) {
      usage_fifo_count = 0;
      return;
  }

  if ( x > 0 ) {
     //fprintf(stderr,"memmove(%d)\n",x);
       memmove(usage_fifo_buffer,  &usage_fifo_buffer[x],   (usage_fifo_count - x) * sizeof(struct usage_fifo_entry));

       usage_fifo_count = usage_fifo_count - x;

  }
}



void do_usage_record( time_t at_time,   int delta_value,   int usage_value ) {
   void * result;
   int i, excess, cumulative = 0;

   if (  usage_fifo_count + 2   >=  usage_fifo_allocated  ) {
         result = realloc( usage_fifo_buffer,   sizeof(struct usage_fifo_entry) *   (usage_fifo_count + 32) );

         if (result == NULL) {
             perror("realloc(): Unable to allocate memory");
             abort();
         }

         usage_fifo_buffer = result;
         usage_fifo_allocated  = (usage_fifo_count + 30);
   }

   usage_fifo_buffer[usage_fifo_count].at_time = at_time;
   usage_fifo_buffer[usage_fifo_count].delta_value = delta_value;
   usage_fifo_buffer[usage_fifo_count].usage_value = usage_value;
   usage_fifo_buffer[usage_fifo_count].retained = usage_value;

   usage_fifo_buffer[usage_fifo_count].cumulative_retained = abs(usage_value);
   if ( usage_fifo_count > 0 &&  usage_fifo_buffer[usage_fifo_count-1].cumulative_retained > 0 ) { 
   usage_fifo_buffer[usage_fifo_count].cumulative_retained = abs(usage_fifo_buffer[usage_fifo_count-1].cumulative_retained) + abs(usage_value);
   }

   if (  usage_fifo_buffer[usage_fifo_count].cumulative_retained < 0 || usage_value < 0 )
           abort();

   if ( usage_fifo_buffer[usage_fifo_count].cumulative_retained >= megabytes_retention  ) {

       excess = abs(usage_fifo_buffer[usage_fifo_count-1].cumulative_retained) + abs(usage_value);
       excess = excess - megabytes_retention;

       for(i = 0; i <= usage_fifo_count; i++) {
 
            if (usage_fifo_buffer[i].retained > 0 ) {

                if (usage_fifo_buffer[i].retained <= excess) {
                     excess = excess - usage_fifo_buffer[i].retained;
                     usage_fifo_buffer[i].retained = 0;
                } else {
                     usage_fifo_buffer[i].retained = usage_fifo_buffer[i].retained - excess;
                     excess = 0;
                     break;
                }

            }
       }

       cumulative = 0;
       for(i = 0; i <= usage_fifo_count; i++) {
                 cumulative = cumulative + usage_fifo_buffer[i].retained ;
                 usage_fifo_buffer[i].cumulative_retained  =  cumulative;
       }
   }
  usage_fifo_count = usage_fifo_count + 1;

  /* printf("RAW[%d]: %d %d %d  Retained=%d Cum=%d\n", usage_fifo_count, at_time, delta_value, usage_value, usage_fifo_buffer[i].retained, usage_fifo_buffer[i].cumulative_retained); */


  cleanup_usage_buffer();


  if (usage_fifo_count > 0 ) {
#if 0
      printf("At %ld - earliest retention is:  %ld minutes ago   %ld   \n", at_time, (usage_fifo_buffer[0].at_time, at_time - usage_fifo_buffer[0].at_time)/60, usage_fifo_buffer[0].at_time);
#endif

      {  char timebuf[1024]={'\0'};
         struct tm *tm1 = localtime(&at_time);
         strftime(timebuf, 256, "%m/%d/%y %H:%M", tm1);

         if ( at_time > (cal_start_s_v+86400)  ) { 
         printf("%s\t%Lf\n", timebuf,  (usage_fifo_buffer[0].at_time, at_time - usage_fifo_buffer[0].at_time)/60.0L/60.0L );
         }
      }
  }
}









main() {
   FILE     *              sample_file;
   char                    sample_buffer[1024] = {'\0'};
   char                    rtp_path[1024] = {'\0'};
   char                    parse_buffer[1024] = {'\0'};

   char  *p      = NULL;
   time_t   cal_current = time(NULL);   
   time_t   cal_start, cal_at,  time_delta;   
   struct tm    parsed_timestamp;


   initialize_usage_buffer();
   setenv("TZ", "US/Central", 1);
   tzset();

   fprintf(stderr, "#megabytes_retention = %d\n#start_time = %s\n#tz: US/Central\n#Tgt retention VS est actual\n#Date     Time      Hours_Retained\n", megabytes_retention, start);
   
   memset( &parsed_timestamp, '\0', sizeof parsed_timestamp );
   
   p = strptime(start, "%m-%d-%Y %H:%M:%S",  &parsed_timestamp);
   
   if (!p || *p) {
       abort();
   }  
   
   cal_start = mktime(&parsed_timestamp);
   cal_start_s_v = cal_start;
   
   
   if (cal_start == (time_t)-1) {
       abort();
   }


   for (time_t i = cal_start;  i <  cal_current ;   i +=  86400 ) {
        char  filename[ 100 ];     		
		struct tm    *check_time;
		int    check_year,  check_month,  check_day;
                int    usage_value;
		
		check_time = localtime(&i);
		if (check_time == NULL) {
		    abort();
		}
		
		check_year  =  check_time->tm_year + 1900;
		check_month =  check_time->tm_mon + 1;
		check_day   =  check_time->tm_mday; 
   
        sprintf(filename, "/root/vos/sample_rtpusage%d_%.2d_%.2d",  check_year, check_month, check_day);
		
		
		sample_file = fopen(filename, "r");
		if ( sample_file == NULL) {
		    perror("fopen");
			continue;
		}
		
		while(fgets( sample_buffer,  512,    sample_file  )) { 
		      char *token0 = sample_buffer, *token1 = 0, *token2 = 0;
                      char *tokenlist[512];
                      char **next_token = &token0;
                      int counter = 0;

                      sample_buffer[513] = '\0';
		      token1 = strsep(next_token, "\n\t ");
                      token2 = strsep(next_token, "\n\t ");
                      if (token2 == NULL)
                           continue;
			  
                       usage_value = strtol(token1, 0, 10);

                       memcpy(rtp_path, token2, strlen(token2));

                       /* Find what Date and Time this directory corresponds to */
                       counter = 0;
                       token0 = rtp_path;
                       next_token = &token0;

                       while ( 1 ) {
                           tokenlist[counter] = strsep(next_token, "/");

                           if (tokenlist[counter] == NULL)
                               break;
                           counter = counter + 1;
                       }

                       if ( counter < 4  || tokenlist[counter - 1] == NULL  || strcmp(tokenlist[counter-1], "RTP") )
                       {
                           fprintf(stderr, "Invalid line: %s\n", sample_buffer);
                           continue;  /* Not found */
                       }

                       /* Parse the timestamp */
                       sprintf(parse_buffer, "%s %s:%s:00",  tokenlist[counter-4], tokenlist[counter-3],  tokenlist[counter-2] );


                       memset( &parsed_timestamp, '\0', sizeof parsed_timestamp );
                       p = strptime(parse_buffer, "%Y-%m-%d %H:%M:%S",  &parsed_timestamp);
                       if (!p || *p) {
                             fprintf(stderr, "Invalid timestamp in line: %s\n", sample_buffer);
                             continue;
                       }


                       cal_at= mktime(&parsed_timestamp);
                       if (cal_at == (time_t)-1) {
                             fprintf(stderr, "mktime() Invalid timestamp in line: %s\n", sample_buffer);
                             continue;
                       }

                       if (cal_at < cal_start)
                            continue;


                       time_delta = cal_at - cal_start;


                       do_usage_record( cal_at, time_delta, usage_value);



                       /*cal_at - cal_start */



                         
		
		}		
		fclose(sample_file);
		
   
        //printf("%s\n", filename);

       
   }
   
   
}



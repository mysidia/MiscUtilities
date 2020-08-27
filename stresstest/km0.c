//  (C) Mysidia 1997

/*!
 * @file        mthrash.c
 * @brief       Memory page dirtier / RAM Thrasher   - mthrash.c     
 * @detail Memory manager stress test
 *   * Similar to  CPU stress test.
 *   * Our performance metric will be  'Average number of writes to RAM per second'  over the simulation period
 *
 *   * The idea is to allocate a large block of virtual memory.   This should be about 95% of available RAM.
 *
 *   * Set a lock on the big block of virtual memory
 *
 *   * Write  2-bytes to each memory page  within the block, as quickly as possible,
 *     so we dirty all the system memory pages at a high speed.
 *
 *     In order to achieve this,  we will map the block as anonymous shared memory,  and use a large pool
 *     of child processes.   Each range of memory pages will be assigned to 4 children.
 *
 *         numChildren = 4 * ((MEMORY_TO_USE / PAGE_SIZE) / PAGES_PER_CHILD);
 *
 * In order to  compile  and use:
 *
 *    gcc -o mthrash mthrash.c -O2 -Wall -D'MEMORY_TO_USE=(PAGE_SIZE*262191)' -DPAGES_PER_CHILD=2500  
 *
 * To run program:
 *    ./mthrash <number of seconds>
 *
 *  @desc        Program simulates memory I/O thrashing, by intentionally creating memory thrashing
 *               for a specified number of seconds,  with the specified amount of memory.
 *
 *  @author      mysid
 *  @copyright   Copyright (C) 1997-2003,  Mysidia,  All Rights Reserved.
 *  @license       Software Available  under the OSL version 2.1.
 *  @licenseURL    http://opensource.org/licenses/osl-2.1.php
 *                 This License shall terminate automatically and You may no longer exercise any of the rights granted
 *                 to You by this License as of the date You commence an action, including a cross-claim or counterclaim,
 *                 against Licensor. And the same should you do so against any licensee alleging that original work infringes any patent. 
 *  @date        7/20/2003
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static char* memoryRegion  =  0;
static void *childReport   = 0;
static int* alarmClock     = 0;

/*! Time server to refer IP address to */
#define TIME_SERVER "x.x.x.x"

/* 262191 pages =  1 Gigabyte of memory;  intended for a VM with 1.2GB of RAM;  Increase as desired */

/* To really create extreme memory thrashing, use a big VM,
 * scale up MEMORY_TO_USE in order to thrash with 32GB of RAM,
 * and scale up vCPUs,  increase PAGES_PER_CHILD appropriately.
 *
 * Keep a margin of system memory unused by this, unless you want to simulate memory swap thrashing as well.
 */
#ifndef MEMORY_TO_USE
#define MEMORY_TO_USE (PAGE_SIZE * 262191)
#endif

/*! Ratio of memory pages that each child process is going to mess with.
 * For we divide the number of pages memory  by  PAGES_PER_CHILD, to decide how
 * many children threads to spawn.
 */
#ifndef PAGES_PER_CHILD
#define PAGES_PER_CHILD (10000/4)
#endif


/*! @brief Check NTP server
 *  @param clockErr            NULL, or pointer to an integer  that will be loaded with the system clock timestamp delta.
 *  @pre                       Application running on LAN connected to  the TIME_SERVER
 *  @return                    0 if simulation should continue, 1 if we are done,  2 or >1 on fatal error
 *  @details This function is used to Check external time server to see if the simulation stop time has been exceeded.   This will be used once per second. 
 */
int ntpcheck(int *clockErr);


/*!  Amount of shared virtual memory that we will allocate and LOCK into RAM, 
 *   to prevent swapping */
static const int memorySize = MEMORY_TO_USE ;

/*!  We will create a child process,  for every  'pagesPerChild'   PAGES of memory  */
static const int pagesPerChild = PAGES_PER_CHILD;

/*! UTC Calendar time at which the memory thrashing will stop */
static       time_t stopTime = 0;
static struct timeval stopTimeval;
static struct timeval actualEndTimeval;

/*! UTC Calendar time at which we started */
static       time_t startTime = 0;
static struct timeval startTimeval;


/*! Number of child processes to create */
static const int numChildren = 4 * ((MEMORY_TO_USE / PAGE_SIZE) / PAGES_PER_CHILD);

int forked_child(int, time_t, int, int, int, int);

/*! @desc Flip a coin
 *  @return  The answer; HEADS=0 or  TAILS=1
 */
enum { HEADS, TAILS }  
cointoss(void) {
     double  r =  random();

     if (  (r / RAND_MAX)  < 0.50000000L    )
         return HEADS;
     else if ((r / RAND_MAX) > 0.50000000L  )
         return TAILS;
     else
         return cointoss();
}

void alarmclock() {
	exit(0);
}


/*! @brief  Function run for each  memory thrashing iteration within a child worker process 
 *  @post   The childreport shared memory area has been updated to reflect the number of writes performed by this iteration
 *  @param  childID   Integer offset of this child process, between 0 and  numChildren.
 *  @param  stopat    UTC calendar time at which this child will be force killed with an Alarm Clock signal.
 *  @param  start_page  Array Offset * PAGE_SIZE of  memoryRegion[]  this child starts at
 *  @param  end_page    Array Offset * PAGE_SIZE of  memoryRegion[]  this child ends at
 *  @param  offset      Integral offset within the memory page, to write our bytes out at.
 *  @param  write       What to flip bit to?  1 or 0?
 *  @return 0 on iteration complete,  -1 on stop due to time condition.
 */
int forked_child(childId,  stopat,  start_page, end_page, offset,  write)
      int childId;         /*  Number between 0 and  numChildren */
      time_t stopat;       /*  Stop running at this timestamp. */
      int start_page;      /*  Memory page to start at */
      int end_page;        /*  Memory page to end at */
      int offset;          /*  offset within the page, to scribble on */
      int write;           /*  what to write */
{


    int i;  /*   i   will be the memory address */
    char before1, before2, after1, after2;

	//printf("%3d   start_page=%d   end_page=%d    offset=%d    write=%d\n", childId, start_page, end_page, offset, write);

    for (i = start_page * PAGE_SIZE  ;  i < end_page * PAGE_SIZE  ; i = i + PAGE_SIZE ) {
          before1 = memoryRegion[i + offset];
          before2 = memoryRegion[i + offset + 1];

          after1 = write | ( memoryRegion[i + offset] ^  0x7f );
          after2 = before2 ^ (1 << cointoss());

          memoryRegion[i + offset] = after1;
          memoryRegion[i + offset + 1] = after2;
          ((int (*)[2])childReport)[childId][0]++;

          if (before1 != after1) {
              ((int (*)[2])childReport)[childId][1]++;
          }
		  
		  if (   *((int*)alarmClock) != 0 ) {
		  	  return -1;
		  }

          //printf("[C%3d]  @(%7d): %.2X -> %.2X,   @(%7d):   %.2X -> %.2X\n", childId, i+offset, before1, after1, i+offset+1, before2, after2);
          /*if( (i/PAGE_SIZE) % 100000 ) {
                if (time(0) > stopat+0)
                      return -1;
          }*/
        
    }

    if ( childId <= 2 && (time(0) < stopat) ) {
        if (fork() == 0) {
            memset(memoryRegion, 0xff ^ (1 << (childId % 31)),  memorySize);
            exit(0);
        }
    }

    return 0;
}

/* Cleanup mappings before exiting */
void unmap_memory(void)
{
	if (memoryRegion != 0)
        munmap(memoryRegion, memorySize);
	
	if (childReport != 0)
        munmap(childReport, (numChildren+1) * 2 * sizeof(int));	
	
	if (alarmClock != 0)
	    munmap(alarmClock, 2 * sizeof(int));
}


/**
 *  Wait until the start time arrives.
 */
void wait_until_start(void)
{
    static struct timeval   timenow;
    static struct timespec wait_time;
	
	gettimeofday(&timenow, NULL);
	if (timenow.tv_sec > startTimeval.tv_sec || (timenow.tv_sec == startTimeval.tv_sec && timenow.tv_usec > startTimeval.tv_usec)) {
		printf("ERROR: Oops! We missed starting at the right time :(\n)");
		*((int *)alarmClock) = 1;
		exit(1);
	}

	wait_time.tv_sec = startTimeval.tv_sec - timenow.tv_sec;
	if (startTimeval.tv_usec >= timenow.tv_usec)
		//1 microsecond = 1000 nanoseconds
		wait_time.tv_nsec =  (startTimeval.tv_usec -  timenow.tv_usec) * 1000;
	else {
		wait_time.tv_sec--;
		wait_time.tv_nsec =  (1000000 + startTimeval.tv_usec -  timenow.tv_usec) * 1000;
	}
		
	if ( nanosleep(&wait_time, 0) == -1) {
		perror("nanosleep");
	}
}


/**
 *  @brief Main program procedure
 *
 *  1.  Parse input from user:  number of seconds for simulation to run
 *  2.  Map a region of shared memory   memoryRegion
 *  3.  Map a region of memory for child processes to report their statistics to.
 *  4.  Lock in all pages, so all mapped memory is in RAM.
 *  5.  Setup startTime and stopTime according to the simulation start and end times.
 *  6.  Begin simulation, fork  numChildren  child processes,  to begin thrashing the memory.
 *  7.  Setup alarm clock handler to kill child processes at the end time of the simulation.
 *  8.  Wait until simulation end time is reached.
 *  9.  Trigger the alarm clocks;  wait for child processes to die.
 * 10.  Report child process statistics
 */
int main(argc, argv)
  int argc;
  char *argv[];
{
   int duration, v;
   long long reported_total_write_count = 0;

   if ( ntpcheck(&v) > 1 ) {
	   printf("No answer from time server.\n");
	   unmap_memory();
	   exit(1);
   }
   
   if (abs(v) > 0) {
   	   printf("Please try again, or correct the system time first;\n[NTP] ERROR: answer from %s  disagrees with system clock by %d second(s)\n", TIME_SERVER, v);
	   unmap_memory();
	   exit(1);
   }
   

   if (argc < 2 || !*argv[1] || ( duration = strtol(argv[1],  (char **)0, 10) )  <  1  ) {
        printf("Usage: %s (number of seconds to run)\n", argv[0]);
		unmap_memory();
        exit(1);
   }

   srandom(time(0));

   time(&startTime);
   gettimeofday(&startTimeval, NULL);

   startTimeval.tv_sec = startTimeval.tv_sec + 5;
   startTimeval.tv_usec = 0;
   startTime = startTime + 5;      
  
   stopTime = startTime + duration;   
   stopTimeval.tv_sec = startTimeval.tv_sec + duration;
   stopTimeval.tv_usec = 0;
   

   mlockall(MCL_CURRENT | MCL_FUTURE);  // lock all pages in RAM

   memoryRegion = mmap(NULL, memorySize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   if (memoryRegion == 0) {
        perror("mmap: failed to map memory region:");
		unmap_memory();
        exit(1);
   }

   alarmClock = mmap(NULL, 2 * sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   if (alarmClock == 0) {
        perror("mmap: failed to map memory region:");
		unmap_memory();
        exit(1);
   }

   /* Set to 0.   As soon as a '1' is written:  all child processes will stop where they are. */
   *((int*)alarmClock) = 0;
   *((int*)alarmClock + 1) = 0;   

   childReport = mmap(NULL, (numChildren+1) * 2 * sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   if (childReport == 0) {
        perror("mmap: failed to map memory region:");
		unmap_memory();
        exit(1);
   }

   printf("Successfully allocated: %lf gigabytes of memory\n",  ((double) memorySize) / 1024  / 1024 / 1024  );
   printf("Memory bus I/O thrashing stress test will begin shortly.\n\n");
   printf("Stop time: %s\n", (char*)ctime(&stopTime) );

   printf("Will spawn: %d children threats,  to simulate memory thrashing\n", numChildren);
   
   /* */
   {
     pid_t  pidList[numChildren];
     int    i,j,h;

     printf("Running preparation to gather memory write operation statistics.\n");	 
     memset(pidList, 0, sizeof(pidList));
     for(i = 0; i < numChildren; i++) {
             ((int (*)[2])childReport ) [i] [0]  = 0;
             ((int (*)[2])childReport ) [i] [1]  = 0;
     }
     printf("Done. Ready to gather statistics.\n");
	 
	 signal(SIGALRM, SIG_IGN);

     for(i = 0; i < numChildren-1; i = i+1 )
     {
         j = fork();

         if (j < 0) {
             perror("fork");
             abort();
         }

         if (j == 0) { 
			signal(SIGALRM, alarmclock);
		    while ( *((int*)alarmClock + 1) == 0   && (time(0) < startTime + 2)  ) {
		    	usleep(1000);
		    }
			if ( *((int*)alarmClock + 1) == 0) {
				printf("Worker process timed out waiting for simulation to begin.\n");
				exit(1);
			}

			
            while(*((int*)alarmClock) == 0 && time(0) < stopTime) {
                for(h = 0; h < (PAGES_PER_CHILD / 2); h++) {
                    forked_child( i, stopTime,  (i/4) * pagesPerChild,  ( (i+4)/4)*pagesPerChild  ,  h + 10 * (i%4),  (i+h)%2 == 0 );

                    if (time(0) > stopTime)
                        exit(0);
                }
             }
             exit(0);
         }

         pidList[i] = j;
     }

 	printf("Spawned children are ready.\n");	 
	printf("Start time has been scheduled.\n");
	printf("Waiting for start time to arrive.\n\n"); 
	wait_until_start();

	*((int*)alarmClock + 1) = 1;	
	printf("Start now!\n\n");	 
	 while(time(0) < stopTime)  {
		 if (ntpcheck(0))
			 break;
		 if ( duration <= 30 )
		     usleep(500000 );
		 else
			 sleep(1);
	 }
	*((int*)alarmClock) = 1;
	
	printf("TIMES UP!  Results locked.  Ringing the alarm clock!\n\n");	 
	printf("Collecting the child process statistics...\n\n");	 
    gettimeofday(&actualEndTimeval, NULL);
	sleep(1);

     for(i = 0; i < numChildren; i++) {
		    /* If a child process hung, we will forcibly kill it now. */
		     kill(pidList[i], SIGALRM);

             /* Wait until the child actually exits */
             waitpid(pidList[i], NULL, 0);
             printf("PARENT: Child: %d exited After reporting %d  memory writes  %d unique,   with exit status %d\n", i,
                              ((int (*)[2])childReport)[i][0],  ((int (*)[2])childReport)[i][1]   , WEXITSTATUS(pidList[i]));

             if ( ((int (*)[2])childReport)[i][1]  > 0  ) {

                 reported_total_write_count = reported_total_write_count + ((int (*)[2])childReport)[i][1];
             }
     }
   }

   unmap_memory();
	
   printf("Runtime: %d milliseconds   (Of requested %d milliseconds)\n", 
                  (int)((actualEndTimeval.tv_sec-startTimeval.tv_sec)*1000+(actualEndTimeval.tv_usec - startTimeval.tv_usec)/1000),  duration*1000);

   printf("Total: Logged %lld writes\n", reported_total_write_count);
   printf("Total: Approximate average %lld writes per second\n", reported_total_write_count / duration);
   
   return 0;
}



/**
 *  Check NTP server
 */
int ntpcheck(int *clockErr)
{
     unsigned char sendbuf[48]={010,0,0,0,0,0,0,0,0};
	 
	 unsigned long  buffer[1024];
	 struct protoent *proto;
	 struct sockaddr_in addr;
	 int s;
	 time_t inval,tscal;

	 printf("[SNTP]:  Sending NTP query to %s\n", TIME_SERVER);
	 proto = getprotobyname("udp");
	 s = socket(PF_INET, SOCK_DGRAM, proto->p_proto);
	 
	 if ( s < 0 ) {
		 perror("socket");
		 printf("[NTP] Cannot verify time with time server\n");
		 return 2;
	 }
	 
	 memset( &addr, 0, sizeof(struct sockaddr_in));
	 
	 addr.sin_family = AF_INET;
	 if ( inet_pton(AF_INET, TIME_SERVER, (struct in_addr*)&(addr.sin_addr.s_addr)) < 0 ) {
		 perror("inet_pton");
		 printf("[NTP] Cannot verify time with time server\n");		 
		 return 2;
	 }

     addr.sin_port = htons(123);
	 
	 if ( sendto(s, sendbuf, sizeof(sendbuf), 0, (struct sockaddr *)&addr,sizeof(addr)) < 0 ) {
		 perror("sendto");
		 printf("[NTP] Cannot verify time with time server\n");
		 return 2;
	 }
	 
	 if ( recv(s,   buffer,sizeof(buffer),0)  < 11 ) {
		 perror("recv");
		 printf("[NTP] Cannot verify time with time server\n");
		 return 2;
	 }
	 
     inval = ntohl(((int*)buffer)[10]);
	 inval -= 2208988800U; 
	 
	 tscal = time(0);
	 
	 printf("[SNTP]:  Time: %s",ctime(&inval));
	 printf("[SNTP]:  System time is %d seconds off\n", (int)(tscal- inval));
	 
	 if (clockErr != 0)
	     *clockErr = tscal - inval;

	 if (stopTime == 0 || stopTime >  tscal+86400)
		 return 1;
	 
	 if (inval > stopTime) {
		 printf("[SNTP]:  NTP time >= stopTime\n");
		 return 1;
	 } else {
		 if (abs(tscal - inval) > 2) {
		 	 printf("[NTP] Time does not agree with time server\n");
			 return 2;
		 }
		 printf("[SNTP]:  NTP time < stopTime\n");		 
		 return 0;
	 }
 }


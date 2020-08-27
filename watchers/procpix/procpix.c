//
// Copyright (C) 2006 Mysidia 
//
//

#define _LARGEFILE64_SOURCE  /*  Required to enable 64-bit file offsets, 32 bits isn't enough for /var/log/pix525-1 */
#undef DEBUG
#undef DEBUG_PRINT
#define PRUNE_LESS_OFTEN
#define DEBUG_UNKNOWN

#define PROCPIX_DAT "/var/pos/procpix.dat"


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <string.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <signal.h>
#include <ares.h>

#include <sys/select.h>
#include <arpa/nameser.h>

#include "tree.h"

//#define MAX(a,b) ((a) > (b) ? (a) : (b))
//#define MIN(a,b) ((a) < (b) ? (a) : (b))


ares_channel  dns_channel;

/* Is this address one of the web servers?   Macro returns 1=Yes 0=No */
/* Input should be the address integer value  pre-converted to network byte order. */

/* *****************************************************************************************  */

enum MonitoredProjectT { PROJ_NONE, PROJ_A, PROJ_B, PROJ_C, PROJ_SIZE };
enum LoggableInterfaceT  { INTF_INSIDE, INTF_OUTSIDE };

struct _CounterData {
       int total;
       int recent;
       int count;

       time_t first;
       time_t last;
       int printed;

       int proj_total[ PROJ_SIZE ];
       int proj_recent[ PROJ_SIZE ];
       int proj_count[ PROJ_SIZE ];
       time_t proj_first[ PROJ_SIZE ];
       time_t proj_last[ PROJ_SIZE ];
};




struct _ReversalTreeNode {
    int do_reverse;
    int is_posted;
    int resolved;
    int refcnt;

    struct in_addr  addr;

    char name[80];
    time_t attime;

    SPLAY_ENTRY(_ReversalTreeNode)  tree_ent;
};
typedef struct _ReversalTreeNode ReversalNode;



struct _IPCounterTreeNode {

       struct in_addr addr;
       struct _CounterData data;
       ReversalNode* rdns;

       int has_changed;
       int is_new;
       int is_except;
       int is_deleted;

       SPLAY_ENTRY(_IPCounterTreeNode)  tree_ent;
};

typedef struct _IPCounterTreeNode IPCounterNode;



struct _DomainCounterTreeNode {

       char domain[256];
       struct _CounterData data;

       int has_changed;
       int is_new;
       int is_except;
       int is_deleted;

       SPLAY_ENTRY(_DomainCounterTreeNode)  tree_ent;
};

typedef struct _DomainCounterTreeNode DomainCounterNode;




/* ****************************************************************************************** */

#define PRETTY_ADDR(x,y,z,w) ((x) << 24 | (y) << 16 | (z) << 8 | (w))
void ProcessDNSQueries(int oneshot);
void MakeRDNSCandidate( struct _IPCounterTreeNode *ent );
void PostDNSQuery( ReversalNode* rdns );


inline char* strncpyzt( char * dst, char * src, int nbytes )
{
    if ( !dst || !src || nbytes < 1 ) {
        abort();
    }

    strncpy(dst,src,nbytes);

    dst[nbytes - 1] = '\0';
}



static const long webServerBitMask[] = { /* PROJ_NONE */ PRETTY_ADDR(255,255,255,255), 
                                         /* PROJ_A  */ PRETTY_ADDR(255,255,255,0), 
                                         /* PROJ_B */  PRETTY_ADDR(255,255,255,0),
                                         /* PROJ_C */  PRETTY_ADDR(255,255,255,0) };

static const long webServerNetAddr[] = { /* PROJ_NONE */ PRETTY_ADDR(0,0,0,0), 
                                         /* PROJ_A  */ PRETTY_ADDR(10,0,226,0),
                                         /* PROJ_B */  PRETTY_ADDR(10,0,228,0),
                                         /* PROJ_C */  PRETTY_ADDR(10,0,228,0) };


//inline  __attribute__((always_inline))
int IsWebServer(u_int32_t qipv4HostAddress, enum MonitoredProjectT qProjectId)
{
    //printf("IsWebServer(%X,%d)\n", qipv4HostAddress, qProjectId);

    switch((int)qProjectId) { case PROJ_NONE: return 0;
                              case PROJ_A: 
                                        /* if ((qipv4HostAddress & 0x000000ff) < 101 ||
                                               (qipv4HostAddress & 0x000000ff) > 129 ) return 0; */

                              case PROJ_B:
                              case PROJ_C:
                              default:
                                        return  ( (qipv4HostAddress & webServerBitMask[qProjectId])
                                                   == ( webServerNetAddr[qProjectId] & webServerBitMask[qProjectId]  )  );

    }
    return 0;
}

//#define IsWebServer(qipv4HostAddress, qProjectId) \
//                   (  ( (qipv4HostAddress) & webServerBitMask_v1A )   == \
//                      (    ( (69 << 24)  | (46 << 16) | (226 << 8) | (101) )  & webServerBitMask_v1A ) && \
//                    \
//                      ( ( (qipv4HostAddress) & (0x000000ff) ) >= 101  ) && \
//                      ( ( (qipv4HostAddress) & (0x000000ff) ) <= 129  ) \
//                   )

/* */



/* How big of a memory block to map from disk per read()? */
#define LOGBUF (8192*4)

#define PTON_INET4 AF_INET

const char *MonthNames[ ] = { "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", NULL };


enum RequestCategoryT {
    REQ_CAT_UNKNOWN,
    REQ_CAT_TOWEBSERVER,
    REQ_CAT_FROMWEBSERVER
};



struct _place_part {
    enum LoggableInterfaceT interface;
    struct in_addr addr;
    int port;
};


typedef struct _pix_line_log_data {
 int prio,code,day,month,hour,minute,second,timestamp;
 int protocol;
 enum MonitoredProjectT project;

 struct _place_part  src,dst;

 struct in_addr from_ipaddr, to_ipaddr;
 enum RequestCategoryT  requestCategory;

 char tstext[ 80 ];  /* Timestamp text */
 char facility [ 256 ];
 char host1[ 256 ];
 char host2[ 256 ];
 char messg [ 1024 ];
 char uri [ 512 ];
} PIX_LOG_LINE;

typedef enum t_decode_result {
   GOODTOKEN,
   BADTOKEN
} DECODE_1_RESULT;


const int pixcodes_to_pass_through[] =
{
   302013,  /* "A TCP connection slot between two hosts was created" <- Many, many of these */
   106023,  /* "An IP packet was denied by the ACL." */
   106015,  /* "Firewall discards a TCP packet that has no associated connection" */
   401004,  /* "Shunned packet" <- Not currently counted as anything */

   304001,  /* "Specified host attempts to access the specified URL" */
/*   302014, */ /* "A TCP connection between two hosts was deleted" */
   407002
};


/* ****************************************************************************************************** */




SPLAY_HEAD(_IPCounterTree_Head,_IPCounterTreeNode)  IPDenyCounterRoot, *IPDenyCounterRootPtr =&IPDenyCounterRoot,
                                        IPRequestorCounterRoot, *IPRequestorCounterRootPtr = &IPRequestorCounterRoot,
                                        IPConnectorCounterRoot, *IPConnectorCounterRootPtr = &IPConnectorCounterRoot;

SPLAY_HEAD(_DomainCounterTree_Head,_DomainCounterTreeNode) DomainCounterRoot, *DomainCounterRootPtr = &DomainCounterRoot;


SPLAY_HEAD(_ReversalTreeHead,_ReversalTreeNode)    ReversalRoot,  *ReversalRootPtr = &ReversalRoot;




int IPCounterNodeCmp( struct _IPCounterTreeNode* a,  struct _IPCounterTreeNode* b )
{
  int ax,bx;

  ax = (a->addr.s_addr);
  bx = (b->addr.s_addr);

  if (ax == bx) return 0;
  if (ax < bx) return -1;

  return 1; 
}

int DomainCounterNodeCmp( struct _DomainCounterTreeNode* a,  struct _DomainCounterTreeNode* b )
{
  return strcasecmp(a->domain, b->domain);
}

int ReversalNodeCmp( ReversalNode* a, ReversalNode* b )
{
   int ax,bx;

   ax = a->addr.s_addr;
   bx = b->addr.s_addr;

   if (ax==bx) return 0;
   if (ax<bx) return -1;

   return 1;
    //return ( b->addr.s_addr - a->addr.s_addr  );
}



SPLAY_PROTOTYPE(_IPCounterTree_Head, _IPCounterTreeNode, tree_ent, IPCounterNodeCmp);
SPLAY_GENERATE(_IPCounterTree_Head, _IPCounterTreeNode, tree_ent, IPCounterNodeCmp);


SPLAY_PROTOTYPE(_DomainCounterTree_Head, _DomainCounterTreeNode, tree_ent, DomainCounterNodeCmp);
SPLAY_GENERATE(_DomainCounterTree_Head, _DomainCounterTreeNode, tree_ent, DomainCounterNodeCmp);


SPLAY_PROTOTYPE(_ReversalTreeHead, _ReversalTreeNode, tree_ent, ReversalNodeCmp);
SPLAY_GENERATE(_ReversalTreeHead, _ReversalTreeNode, tree_ent, ReversalNodeCmp);


struct _Top20_List_DS {

      int topitems[250];
      int repeatcount[250];
      int topind;
      int topmax;
};


int TopList_IsMember( struct _Top20_List_DS* topList, int num ) {
    int j;
    int pos = 0;

    for(j = topList->topind; j >= 0; j--) {
          pos += topList->repeatcount[j];

          if ( pos >= topList->topmax )
               break;

          if ( topList->topitems[j] == num )
               return 1;
    }

    return 0;
}

/* */

void TopList_Push( struct _Top20_List_DS* toplist, int nextitem )
{
   int j,k,k2,found, foundIdx=-1;

   if ( toplist->topmax < 2 || toplist->topmax >= 250 ) {
        abort();
   }


   for(j = 0, found = 0; j < toplist->topind; j++) {
          if ( nextitem == toplist->topitems[j] ) {
                found = 1; 
                foundIdx = j;
                break;
          }
   }


   if ( found ) {
          toplist->repeatcount[ foundIdx ]++;
   }

   


   if ( found == 0 ) 
   {
       if ( nextitem > toplist->topitems [ toplist->topind ] ) {
              if (toplist->topind >= toplist->topmax) {
                   for(j = 1; j < toplist->topind; j++ ) {
                       toplist->topitems[j - 1] = toplist->topitems[j];
                       toplist->repeatcount[j - 1] = toplist->repeatcount[j];
                   }

                   toplist->topind--;
              }

              toplist->topitems [ toplist->topind + 1 ] = nextitem;
              toplist->repeatcount [ toplist->topind + 1 ] = 1;
              

              toplist->topind++;

              if (toplist->topind > 245)
                    abort();
       }
       else {
              toplist->topitems [ toplist->topind + 1 ] = toplist->topitems [ toplist->topind ];
              toplist->repeatcount [ toplist->topind + 1] = toplist->repeatcount[ toplist->topind ];

              toplist->topitems [ toplist->topind ]     = nextitem;
              toplist->repeatcount[ toplist->topind ]   = 1;

              toplist->topind++;


              for( j = 0 ; j < toplist->topind; j++ ) {
                  if ( toplist->topitems[ j ] > toplist->topitems[ j + 1 ] ) {
                      k = toplist->topitems[ j ];  
                      toplist->topitems[ j ] = toplist->topitems[ j + 1 ];
                      toplist->topitems[ j + 1] = k;

                      k = toplist->repeatcount[ j ];
                      toplist->repeatcount[ j ] = toplist->repeatcount[ j + 1];
                      toplist->repeatcount[ j + 1 ] = k;
                  }
              }


              if (toplist->topind >= toplist->topmax) {
                   for(j = 1; j < toplist->topind; j++ ) {
                       toplist->topitems[j - 1] = toplist->topitems[j];
                       toplist->repeatcount[j - 1] = toplist->repeatcount[ j ];
                   }

                   toplist->topind--;
              } 
       }
   }
}


void PrintData( struct _CounterData* data, FILE *fp )
{
     int j;

          fprintf(fp, " %d %d %ld %ld ",
                        data->total, data->recent, data->first, data->last);


          for(j = 0; j < PROJ_SIZE; j++) {

               fprintf(fp, ":%d,%d,%ld,%ld ", data->proj_total[j],  data->proj_recent[j], data->proj_first[j],
                                             data->proj_last[j]);
          }

           data->printed = 1;
}


void PrepareStats( int project, int top20only )
{
       /* */
     struct _DomainCounterTreeNode* iter_d;
     struct _IPCounterTreeNode* ipTreeItem;
     ReversalNode* rdns;
     char tempfilename[255];
     FILE *fp; 
     int i;

     sprintf(tempfilename, PROCPIX_DAT".new.%d", getpid());
     fp = fopen(tempfilename, "w");


     time_t cutoff1 = time(0) - 240 - 3600;
     time_t cutoff2 = time(0) - 3600 * 24;
     enum MonitoredProjectT proj;
     char prettyIpAddr[48];
     int j, found, k; 
     int shown=0;


     struct _Top20_List_DS  topRequestors, topDenies, topDomains, topConnectors;

     topConnectors.topmax = topRequestors.topmax = topDenies.topmax = topDomains.topmax = 200;


     SPLAY_FOREACH(iter_d, _DomainCounterTree_Head, &DomainCounterRoot) {
          iter_d->data.printed = 0;
     }

     SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPDenyCounterRoot) {
          ipTreeItem->data.printed = 0;
     }


     SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPRequestorCounterRoot) {
          ipTreeItem->data.printed = 0;
     }

     SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPConnectorCounterRoot) {
          ipTreeItem->data.printed = 0;
     }



     for(proj = 0 ; proj < PROJ_SIZE; proj++ )
     { 

        printf("STATS FOR PROJ #%d\n", proj);


        topRequestors.topind = topDenies.topind = topDomains.topind = 0;
        topDomains.topmax = 200;
        topRequestors.topitems[0] = topDenies.topitems[0] = topDomains.topitems[0] = 0;
        topRequestors.repeatcount[0] = topDenies.repeatcount[0] = topDomains.repeatcount[0] = 0;
        topConnectors.repeatcount[0] = 0;


        SPLAY_FOREACH(iter_d, _DomainCounterTree_Head, &DomainCounterRoot)
        {
           if (!iter_d->data.proj_total[proj])
                continue;
            TopList_Push( &topDomains, iter_d->data.proj_total[proj]  );
        }


        shown = 0;
        SPLAY_FOREACH(iter_d, _DomainCounterTree_Head, &DomainCounterRoot)
        {
           if (!iter_d->data.proj_total[proj])
                continue;
            if (top20only && ( !TopList_IsMember( &topDomains, iter_d->data.proj_total[proj] ) 
                              || shown++ > 200 )) 
                continue;


            if (fp != NULL && !iter_d->data.printed) {
               fprintf(fp, ".DOMAIN %s ", iter_d->domain);
                 PrintData( &(iter_d->data), fp );
               fprintf(fp, "\n");
            }


            if ( shown <= 20 ) {
                printf("DOMAIN %-10s   %d %d\n", iter_d->domain,
                                           iter_d->data.proj_total[proj],
                                           iter_d->data.proj_recent[proj] );   
            }
        }


        SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPDenyCounterRoot)
        {  
           if (!ipTreeItem->data.proj_total[proj])
                continue;
           TopList_Push( &topDenies, ipTreeItem->data.proj_total[proj] );
        }


        shown = 0;

        SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPDenyCounterRoot)
        {
           if (!ipTreeItem->data.proj_total[proj])
               continue;

           if (top20only && ( !TopList_IsMember(&topDenies, ipTreeItem->data.proj_total[proj]) ||
                              shown++ > 200))
               continue; 


           if ( inet_ntop( AF_INET, &(ipTreeItem->addr), prettyIpAddr, sizeof(prettyIpAddr) ) == NULL )
                 continue;


           if (fp != NULL && !ipTreeItem->data.printed) {
               fprintf(fp, ".DENY   %s", prettyIpAddr);
                  PrintData( &(ipTreeItem->data), fp );
               fprintf(fp, "\n");
           }

           if (shown <= 30) {
               MakeRDNSCandidate( ipTreeItem );
           }


           if (shown <= 20) {
               printf("DENY %-20s %d %d\n", prettyIpAddr, ipTreeItem->data.proj_total[proj], ipTreeItem->data.proj_recent[proj]);
           }
        }



        SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPRequestorCounterRoot)
        {
           if (!ipTreeItem->data.proj_total[proj])
                continue;
           TopList_Push( &topRequestors, ipTreeItem->data.proj_total[proj] );
        }



        SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPConnectorCounterRoot)
        {
           if (!ipTreeItem->data.proj_total[proj])
                continue;
           TopList_Push( &topConnectors, ipTreeItem->data.proj_total[proj] );
        }



        shown = 0;

        SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPRequestorCounterRoot)
        {
           if (!ipTreeItem->data.proj_total[proj])
                continue;

              /* Enumerate the IPV4Address Entries from the pix log: perform the  top 20 list membership classification */
           if (top20only && (!TopList_IsMember( &topRequestors, ipTreeItem->data.proj_total[proj] )
                             || shown++ > 200))
                continue;

               /* Translate IP address to human-readable notation */
           if ( inet_ntop( AF_INET, &(ipTreeItem->addr), prettyIpAddr, sizeof(prettyIpAddr) ) == NULL ) 
                 continue;

           if (fp != NULL && !ipTreeItem->data.printed) {
               fprintf(fp, ".REQ    %s", prettyIpAddr);
                  PrintData( &(ipTreeItem->data), fp );
               fprintf(fp, "\n");
           }

           if ( shown <= 100 ) {
               /* Mark this IP as eligible to have its reversal record looked up  (We will bulk-process these later) */
               MakeRDNSCandidate( ipTreeItem );
           }

           if ( shown <= 20 ) {
                printf("CON %-20s %d %d\n", prettyIpAddr, ipTreeItem->data.proj_total[proj], ipTreeItem->data.proj_recent[proj]);
           }
        }

        /* */
        shown = 0;

        SPLAY_FOREACH(ipTreeItem, _IPCounterTree_Head, &IPConnectorCounterRoot)
        {
           if (!ipTreeItem->data.proj_total[proj])
                continue;

           if (top20only && (!TopList_IsMember( &topConnectors, ipTreeItem->data.proj_total[proj] )
                             || shown++ > 200))
                continue;

           if ( inet_ntop( AF_INET, &(ipTreeItem->addr), prettyIpAddr, sizeof(prettyIpAddr) ) == NULL )
                 continue;

           if (fp != NULL && !ipTreeItem->data.printed) {
               fprintf(fp, ".CON    %s", prettyIpAddr);
                  PrintData( &(ipTreeItem->data), fp );
               fprintf(fp, "\n");
           }

           if ( shown <= 100 ) {
                MakeRDNSCandidate( ipTreeItem );
           }

           if ( shown <= 20 ) {
                printf("CON %-20s %d %d\n", prettyIpAddr, ipTreeItem->data.proj_total[proj], ipTreeItem->data.proj_recent[proj]);
           }
        }
        /* */

     }


    SPLAY_FOREACH(rdns, _ReversalTreeHead, &ReversalRoot)
    {  
          if ( rdns->do_reverse && !rdns->resolved && !rdns->is_posted )
              PostDNSQuery( rdns );
    }


    ProcessDNSQueries( 0 );


     if (fp != NULL)
     {  
        ReversalNode* rdns;
        time_t cutOffWrite = time(0) - 1500;
        struct _IPCounterTreeNode *tnc;

        shown = 0;
        SPLAY_FOREACH(rdns, _ReversalTreeHead, &ReversalRoot)
        {   
            if (rdns->name[0] == '\0')
                  continue;

            if (rdns->attime < cutOffWrite)
                continue;

             fprintf(fp, ".REVERSAL %d %d %X %d %s\n", rdns->resolved, rdns->refcnt,
                                                       htonl(rdns->addr.s_addr),
                                                       rdns->attime, rdns->name );

        }
     }


     if ( fp ) {
        fclose(fp);
        rename(tempfilename, PROCPIX_DAT);
     }
}

void AllStats( int sig )
{
     int projId;

     printf("DEBUG: Received Signal SIGUSR1\n" );

     for(projId = 0 ; projId < PROJ_SIZE ; projId++ ) {
         PrepareStats( projId, 1 );
     }

     signal(SIGUSR1, AllStats);
}


/* ************************************************************** */

struct _IPCounterTreeNode* LookupIPDenyCounter( struct in_addr );
struct _IPCounterTreeNode* LookupIPRequestorCounter( struct in_addr );
struct _IPCounterTreeNode* LookupIPConnectorCounter( struct in_addr );

ReversalNode* LookupReversal( struct in_addr );

ReversalNode* MakeReversalNode( struct in_addr addr ) 
{
     ReversalNode* rdns = malloc(sizeof(ReversalNode)); // calloc(0,sizeof(ReversalNode));

     if ( rdns == NULL ) {
         abort();
     }

     memset(rdns,0,sizeof(ReversalNode));

     rdns->addr = addr;
     SPLAY_LEFT(rdns,tree_ent) = NULL;
     SPLAY_RIGHT(rdns,tree_ent) = NULL;
     rdns->refcnt = 0;

     return rdns;
}

void FreeReversalNode( ReversalNode* obj ) {
     free(obj);
}

void AddReversalNode( ReversalNode * iter )
{
 //rdns = SPLAY_MIN(_ReversalTreeHead, & ReversalRoot);
 //if (rdns != NULL) {
 //for(i = 0; i < sizeof( rdns->_buffer0 ); i++)
 //   printf("%.2X", rdns->_buffer0[i]);

 //for(i = 0; i < sizeof( rdns->_buffer1 ); i++)
 //   printf("%.2X", rdns->_buffer1[i]);

 //puts("");
 //}


  _ReversalTreeHead_SPLAY_INSERT(&ReversalRoot, iter);
}


void RemoveReversalNode( ReversalNode * iter )
{
  _ReversalTreeHead_SPLAY_REMOVE(&ReversalRoot, iter);
}



/* ************************************************************** */

struct _IPCounterTreeNode* MakeIPCounterObj( struct in_addr addr ) {
       struct _IPCounterTreeNode* cobj = malloc(sizeof(struct _IPCounterTreeNode));
       struct _IPCounterTreeNode* fobj;

       memset(cobj, 0, sizeof(struct _IPCounterTreeNode));
       cobj->addr = addr;

       SPLAY_LEFT(cobj, tree_ent) = NULL;
       SPLAY_RIGHT(cobj, tree_ent) = NULL;

         
       /*if ( (fobj = LookupIPDenyCounter( addr )) && fobj->rdns ) {
           cobj->rdns = fobj->rdns;
           cobj->rdns->refcnt++;
       }*/

       cobj->rdns = NULL;

       /*if ( (cobj->rdns = LookupReversal( addr )) ) {
           cobj->rdns->refcnt++;
       } else {
           cobj->rdns = MakeReversalNode( addr );
           cobj->rdns->refcnt = 1;

           AddReversalNode( cobj->rdns );
       }*/

       return cobj;
}

struct _DomainCounterTreeNode* MakeDomainCounterObj( const char* domain ) {
       struct _DomainCounterTreeNode* cobj = malloc(sizeof(struct _DomainCounterTreeNode));

       memset(cobj, 0, sizeof(struct _DomainCounterTreeNode));

       strncpy(cobj->domain, domain, sizeof(cobj->domain));
       cobj->domain[sizeof(cobj->domain) - 1] = '\0';

       SPLAY_LEFT(cobj, tree_ent) = NULL;
       SPLAY_RIGHT(cobj, tree_ent) = NULL;

       return cobj;
}



ReversalNode* LookupReversal( struct in_addr addr ) {
    ReversalNode search[ ] = {
         {
             resolved : 0,
             addr     : addr,
             refcnt   : 0,
             name     : "",
             attime   : 0
         }

    };

    //SPLAY_LEFT(search, tree_ent) = SPLAY_RIGHT(search,tree_ent) = NULL;
    return _ReversalTreeHead_SPLAY_FIND(&ReversalRoot, search);

}

struct _IPCounterTreeNode* LookupIPDenyCounter( struct in_addr addr ) {
    struct _IPCounterTreeNode iter, *p;

    p = &iter;

    SPLAY_LEFT(p, tree_ent) = NULL;
    SPLAY_RIGHT(p, tree_ent) = NULL;
    p->addr = addr;    

    return  _IPCounterTree_Head_SPLAY_FIND(&IPDenyCounterRoot, &iter);

}

struct _IPCounterTreeNode* LookupIPRequestorCounter( struct in_addr addr ) {
     struct _IPCounterTreeNode iter, *p;

     p = &iter;

     SPLAY_LEFT(p, tree_ent) = NULL;
     SPLAY_RIGHT(p, tree_ent) = NULL;
     p->addr = addr;

    return  _IPCounterTree_Head_SPLAY_FIND(&IPRequestorCounterRoot, &iter);

}



struct _IPCounterTreeNode* LookupIPConnectorCounter( struct in_addr addr ) {
     struct _IPCounterTreeNode iter, *p;

     p = &iter;

     SPLAY_LEFT(p, tree_ent) = NULL;
     SPLAY_RIGHT(p, tree_ent) = NULL;
     p->addr = addr;

    return  _IPCounterTree_Head_SPLAY_FIND(&IPConnectorCounterRoot, &iter);

}




struct _DomainCounterTreeNode* LookupDomainCounter( char* domain ) {
     struct _DomainCounterTreeNode iter, *p;

     p = &iter;

     SPLAY_LEFT(p, tree_ent) = NULL;
     SPLAY_RIGHT(p, tree_ent) = NULL;
     strncpy( p->domain, domain, sizeof(p->domain));
     p->domain[sizeof(p->domain) - 1] = '\0';

    return  _DomainCounterTree_Head_SPLAY_FIND(&DomainCounterRoot, &iter);

}



void AddIPDenyCounter( struct _IPCounterTreeNode * iter ) 
{
  _IPCounterTree_Head_SPLAY_INSERT(&IPDenyCounterRoot, iter);
}

void AddIPRequestorCounter( struct _IPCounterTreeNode * iter )
{
  _IPCounterTree_Head_SPLAY_INSERT(&IPRequestorCounterRoot, iter);
}

void AddIPConnectorCounter( struct _IPCounterTreeNode * iter )
{
  _IPCounterTree_Head_SPLAY_INSERT(&IPConnectorCounterRoot, iter);
}


void AddDomainCounter( struct _DomainCounterTreeNode * iter )
{
  _DomainCounterTree_Head_SPLAY_INSERT(&DomainCounterRoot, iter);
}


void RemoveIPDenyCounter( struct _IPCounterTreeNode * iter )
{
  _IPCounterTree_Head_SPLAY_REMOVE(&IPDenyCounterRoot, iter);
}

void RemoveIPRequestorCounter( struct _IPCounterTreeNode * iter )
{
  _IPCounterTree_Head_SPLAY_REMOVE(&IPRequestorCounterRoot, iter);
}


void RemoveIPConnectorCounter( struct _IPCounterTreeNode * iter )
{
  _IPCounterTree_Head_SPLAY_REMOVE(&IPConnectorCounterRoot, iter);
}


void RemoveDomainCounter( struct _DomainCounterTreeNode * iter )
{
  _DomainCounterTree_Head_SPLAY_REMOVE(&DomainCounterRoot, iter);
}


void FreeIPCounter( struct _IPCounterTreeNode * iter )
{
    if ( iter->rdns )  {
         if ( --iter->rdns->refcnt <= 0 )  {
             RemoveReversalNode( iter->rdns );
             FreeReversalNode(iter->rdns);
         }
         iter->rdns = NULL;
    }
    free(iter);
}

void FreeDomainCounter( struct _DomainCounterTreeNode * iter )
{ 
    free(iter);
}


void BurnIPDenyCounter( struct _IPCounterTreeNode ** iter ) 
{
 if (!iter || !*iter) {
     abort();
 }

 RemoveIPDenyCounter( *iter );
 FreeIPCounter( *iter );
 *iter = NULL;
}

void BurnIPRequestorCounter( struct _IPCounterTreeNode ** iter )
{
   if (!iter || !*iter ) {
       abort();
   }

   RemoveIPRequestorCounter( * iter );
   FreeIPCounter( * iter );
   * iter = NULL;
}



void BurnIPConnectorCounter( struct _IPCounterTreeNode ** iter )
{
   if (!iter || !*iter ) {
       abort();
   }

   RemoveIPConnectorCounter( * iter );
   FreeIPCounter( * iter );
   * iter = NULL;
}


void BurnDomainCounter( struct _DomainCounterTreeNode ** iter )
{
  if (!iter || !*iter) {
      abort();
  }

  RemoveDomainCounter( *iter );
  FreeDomainCounter( *iter );
  *iter = NULL;
}


/* *************************************************************** */


/*
 *
 */

void PruneDomainCounter( )
{
     struct _DomainCounterTreeNode* iter, *iter_next;
     int i;

     time_t cutoff1 = time(0) - 240 - 3600*2;
     time_t cutoff2 = time(0) - 3600 * 24;
     int pruned = 0;

return;
#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneDomainCounter:  Scanning Splay tree...\n");
#endif

     SPLAY_FOREACH(iter, _DomainCounterTree_Head, &DomainCounterRoot) 
     {
        /*
         * Enumerate splay tree, look for stale entries to nuke.
         */

            if ( iter->is_deleted )
                   continue; /* Already marked as deleted */


            if ( iter->data.last > cutoff1  ) {
                 continue;
            }

            if ( iter->data.total >= 3000 && iter->data.last > cutoff2 ) {
                 continue;
            }


            iter->is_deleted = 1;
     }

     for ( iter = SPLAY_MIN(_DomainCounterTree_Head, &DomainCounterRoot);
           iter != NULL;
           iter = iter_next )
     {

           iter_next = SPLAY_NEXT(_DomainCounterTree_Head, &DomainCounterRoot, iter);


            if ( iter->is_deleted ) {
                RemoveDomainCounter( iter );
                FreeDomainCounter( iter );
                pruned++;
            }

     }

#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneDomainCounter:  %d old entries removed from tree, memory released\n", pruned);
#endif
}




/* *************************************************************** */

/*
 *
 */

void PruneDenyIPCounterTable(  struct in_addr  *specific,   int specific_count,
                             struct in_addr  *exceptions, int exceptions_count )
{
     struct _IPCounterTreeNode* iter, *iter_next;
     int i;

     time_t cutoff1 = time(0) - 240 - 3600;
     time_t cutoff2 = time(0) - 3600 * 24;
     int pruned = 0;


#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneDenyIPCounterTable:  Scanning Splay tree...\n");
#endif

     SPLAY_FOREACH(iter, _IPCounterTree_Head, &IPDenyCounterRoot) 
     {
        /*
         * Enumerate splay tree, look for stale entries to nuke.
         */

            if ( iter->is_deleted )
                   continue; /* Already marked as deleted */


            if ( iter->data.last > cutoff1  ) {
                 continue;
            }

            if ( iter->data.total >= 3000 && iter->data.last > cutoff2 ) {
                 continue;
            }



            for(i = 0; i < specific_count; i++) {
                   if ( specific[i].s_addr == iter->addr.s_addr ) {
                        iter->is_deleted = 1;
                        break;
                   }
            }

            if ( iter->is_deleted ) 
                continue;

            iter->is_except = 0;

            


            for(i = 0; i < exceptions_count; i++) {
                   if ( exceptions[i].s_addr == iter->addr.s_addr ) {
                        iter->is_except = 1;
                        break;
                   }
            }

            if ( iter->is_except )
                 continue;

     }

     for ( iter = SPLAY_MIN(_IPCounterTree_Head, &IPDenyCounterRoot);
           iter != NULL;
           iter = iter_next )
     {

           iter_next = SPLAY_NEXT(_IPCounterTree_Head, &IPDenyCounterRoot, iter);


            if ( iter->is_deleted ) {
                RemoveIPDenyCounter( iter );
                FreeIPCounter( iter );
                pruned++;
            }

     }

#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneDenyIPCounterTable:  %d old entries removed from search tree, memory released.\n", pruned);
#endif
}


void DNSQueryFinished( void* arg, int status,  unsigned char *abuf,  int alen )
{
  int i;
  ReversalNode *rdns = (ReversalNode*)arg;
  char *p;

  struct hostent *he = NULL;

  rdns->name[0] = '\0';

  if ( status == ARES_SUCCESS && rdns ) {

      if ( rdns->refcnt-- <= 0 ) {
            RemoveReversalNode( rdns );
            FreeReversalNode( rdns );
      }

      if ( ares_parse_ptr_reply(abuf,alen, &(rdns->addr), sizeof(rdns->addr), AF_INET, &he) == ARES_SUCCESS ) {

          for(p = he->h_name; *p; p++) {
               if (!isascii(*p) || (!isalnum(*p) && !ispunct(*p))) 
                    *p = '_';
          }

          strncpy( rdns->name, he->h_name, sizeof(rdns->name) );
          rdns->name[sizeof(rdns->name) - 1] = '\0';

          rdns->resolved = 1; 
          rdns->attime = time(0);

           //printf ("{%s}\n", he->h_name);
          if (he->h_addr_list) free(he->h_addr_list);
          if (he->h_aliases)   free(he->h_aliases);
          if (he->h_name)      free(he->h_name);

          free(he);


          if ( *rdns->name == '\0' ) {
              strcpy(rdns->name, "[NOTFOUND]");
          }
      }
  } else if ( status == ARES_ETIMEOUT ) {
          strcpy(rdns->name, "[DNS_Timed_Out]");
  } else {

     rdns->attime = time(0);

     switch(status) {
         case ARES_EREFUSED: strcpy(rdns->name, "[REFUSED]"); break;
         case ARES_ENODATA: strcpy(rdns->name, "[No_answers]"); break;
         case ARES_EFORMERR: strcpy(rdns->name, "[Malformed_Query]"); break;
         case ARES_ESERVFAIL: strcpy(rdns->name, "[SERVFAIL]"); break;
         case ARES_ENOTFOUND: strcpy(rdns->name, "[NXDOMAIN]"); break;
         case ARES_ENOTIMP:  strcpy(rdns->name, "[Not_Implemented]"); break;
         case ARES_EBADNAME: strcpy(rdns->name, "[Invalid_Name]"); break;
         case ARES_ENOMEM: strcpy(rdns->name, "[Memory Exhausted]"); break;
         default: strcpy(rdns->name, "[Unknown_DNS_ERROR]");
     }

  }

  //printf("DNSQueryFinished  %d [%d:%s]\n", status, alen, rdns->name);
}


void ProcessDNSQueries(int oneshot)
{
     int nfds, count, i = 0;
     fd_set rfd, wfd;
     struct timeval tv, *tvp;


     while ( !oneshot || i++ == 0)
     {
         FD_ZERO(&rfd);
         FD_ZERO(&wfd);
         nfds = ares_fds(dns_channel, &rfd, &wfd);

         if (nfds == 0)
             break;
         tvp = ares_timeout(dns_channel, NULL, &tv);
         count = select(nfds, &rfd, &wfd, NULL, tvp);
         ares_process(dns_channel, &rfd, &wfd);
     }
}


/*
 *  Make the  ip address  a candidate for being reverse resolved
 */
void MakeRDNSCandidate( struct _IPCounterTreeNode *ent ) 
{
    if (!ent->rdns) 
    { 
       if ( (ent->rdns = LookupReversal( ent->addr )) ) {
          printf("DEBUG: MakeRDNSCandidate: OLD ENT\n");
           ent->rdns->refcnt++;
       } else {

          printf("DEBUG: MakeRDNSCandidate: NEW ENT\n");
           ent->rdns = MakeReversalNode( ent->addr );
           ent->rdns->refcnt = 1;

           AddReversalNode( ent->rdns );

           ent->rdns->do_reverse = 1;
           ent->rdns->is_posted = 0;
       }
    }

}


void PostDNSQuery( ReversalNode* rdns )
{ 
    struct in_addr x = {
                         s_addr : __bswap_32(rdns->addr.s_addr) 
                     };
    char prettyIpAddr[42+20] = "";


    if ( inet_ntop(AF_INET, &x, prettyIpAddr, sizeof(prettyIpAddr) - 15) >= 0) {
        strcat(prettyIpAddr, ".in-addr.arpa");

        printf("DEBUG: Posting %s for RDNS\n", prettyIpAddr);


       //printf("[%s]\n", prettyIpAddr);
       ares_query(dns_channel, prettyIpAddr, C_IN, T_PTR, DNSQueryFinished, (void *)(rdns));

       rdns->refcnt++;
    }
}


/*
 *
 */
void AddDenyToIPCounter( struct in_addr*       denied_address,
                       time_t                timestamp,
                       int                   proj,
                       int                   count,
                       int                   is_recent )
{

    IPCounterNode *ctr = LookupIPDenyCounter( *denied_address );
    char prettyIpAddr[42 + 20];
    struct in_addr x;


   if ( ctr == NULL ) {
       ctr = MakeIPCounterObj( *denied_address );

       ctr->data.last = ctr->data.first = timestamp;
       ctr->data.total = count;
       ctr->data.recent = (is_recent ? count : 0);
       ctr->data.count = count;

       ctr->data.proj_total[ PROJ_NONE ] = count;
       ctr->data.proj_recent[ PROJ_NONE ] = ctr->data.recent;
       ctr->data.proj_count[ PROJ_NONE ] = count;
       ctr->data.proj_first[ PROJ_NONE ] = timestamp;

       ctr->data.proj_total[ proj ] = count;
       ctr->data.proj_recent[ proj ] = ctr->data.recent;
       ctr->data.proj_count[ proj ] = count;
       ctr->data.proj_first[ proj ] = timestamp;

       ctr->is_new = 1;
       ctr->has_changed = 1;

       _IPCounterTree_Head_SPLAY_INSERT(&IPDenyCounterRoot, ctr);

       //if ( ctr->rdns->do_reverse  && !ctr->rdns->resolved && !ctr->dns->is_posted ) { 
       //    PostDNSQuery(ctr->rdns);
       //}
   }
   else {
       ctr->has_changed = 1;
       ctr->data.last = MAX(timestamp, ctr->data.last);
       ctr->data.first = MIN(ctr->data.first, timestamp);

       ctr->data.proj_last[PROJ_NONE] = ctr->data.last;
       ctr->data.proj_first[PROJ_NONE] = ctr->data.first;



       ctr->data.proj_last[proj] = MAX(timestamp, ctr->data.proj_last[proj]);

       if (ctr->data.proj_first[proj] > 0) {
         ctr->data.proj_first[proj] = MIN(ctr->data.proj_first[proj], timestamp);
       } else {
         ctr->data.proj_first[proj] = timestamp;
         ctr->has_changed = 1;
       }   


       ctr->data.total += count;
       if ( is_recent ) {
           ctr->data.recent += count;
           ctr->data.proj_recent[ PROJ_NONE ] += count;
           ctr->data.proj_recent[ proj ] += count;
       }

       ctr->data.count += count;

       ctr->data.proj_total[ PROJ_NONE  ] += count;
       ctr->data.proj_count[ PROJ_NONE  ] += count;

       ctr->data.proj_total[ proj ] += count;
       ctr->data.proj_count[ proj ] += count;
   }


#ifdef DEBUG
printf("DEBUG [Project ID=%d]    IPDenyCounterSplayTreeNODE->denies_count == %d  IP ADDRESS %s\n", proj, ctr->data.proj_count[proj],
                 inet_ntop(AF_INET, &(ctr->addr), prettyIpAddr, sizeof(prettyIpAddr)));
#endif

//inet_ntop(AF_INET, &(pll->src.addr), prettyIpAddr, sizeof(prettyIpAddr)), pll->src.port
}



/* Prune the splay tree */
void PruneIPConnectorCounter(   /*IPV4AddressPtr*/ struct in_addr  *specific,   int specific_count,
                                /*IPV4AddressPtr*/ struct in_addr  *exceptions, int exceptions_count )
{
     struct _IPCounterTreeNode* iter, *iter_next;
     int i, pruned = 0;
     time_t cutoff1 = (time(0) - 240),  cutoff2 = (time(0) - 3600 * 24);

#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneIPConnectorCounter: Scanning splay tree...\n");
#endif

     SPLAY_FOREACH(iter, _IPCounterTree_Head, &IPConnectorCounterRoot)
     {
        /*
         * Enumerate splay tree, look for stale entries to nuke.
         */

            if ( iter->is_deleted )
                   continue; /* Already marked as deleted */

            if ( iter->data.last > cutoff1  ) {
                 continue;
            }

            if ( iter->data.total >= 3000 && iter->data.last > cutoff2 ) {
                 continue;
            }

            for(i = 0; i < specific_count; i++) {
                   if ( specific[i].s_addr == iter->addr.s_addr ) {
                        iter->is_deleted = 1;
                        break;
                   }
            }

            if ( iter->is_deleted )
                continue;

            iter->is_except = 0;




            for(i = 0; i < exceptions_count; i++) {
                   if ( exceptions[i].s_addr == iter->addr.s_addr ) {
                        iter->is_except = 1;
                        break;
                   }
            }

            if ( iter->is_except )
                 continue;
     }



     for ( iter = SPLAY_MIN(_IPCounterTree_Head, &IPConnectorCounterRoot);
           iter != NULL;
           iter = iter_next )
     {
           iter_next = SPLAY_NEXT(_IPCounterTree_Head, &IPConnectorCounterRoot, iter);

           if ( iter->is_deleted ) {
               RemoveIPConnectorCounter( iter );
               FreeIPCounter( iter );
               pruned++;
           }
     }

#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneConnectorIPCounterTable:  %d old entries freed from search tree, memory released.\n", pruned);
#endif
}


void AddToIPConnectorCounter( /*IPV4AddressPtr*/ struct in_addr*       source,
                              /*ts*/                time_t             timestamp,
                              /*       project#*/  int                proj,
                              /* count to add */    int                count,
                              /*added this run?*/   int                is_recent )
{
    IPCounterNode *ctr = LookupIPConnectorCounter( *source );
    char prettyIpAddr[42];


   if ( ctr == NULL ) {

/*{
 FILE *fp = fopen("/root/debug_file.tmp", "a");
 char buf[512];

 if (fp) {
 fprintf(fp, "AddIPConnectorCounter(): %d\n", source->s_addr);
 fclose(fp);
 }
}*/
       ctr = MakeIPCounterObj( *source );

       ctr->data.last = ctr->data.first = timestamp;
       ctr->data.total = count;
       ctr->data.recent = (is_recent ? count : 0);
       ctr->data.count = count;

       ctr->data.proj_total[ PROJ_NONE ] = count;
       ctr->data.proj_recent[ PROJ_NONE ] = ctr->data.recent;
       ctr->data.proj_count[ PROJ_NONE ] = count;
       ctr->data.proj_first[ PROJ_NONE ] = timestamp;

       ctr->data.proj_total[ proj ] = count;
       ctr->data.proj_recent[ proj ] = ctr->data.count;
       ctr->data.proj_count[ proj ] = count;
       ctr->data.proj_first[ proj ] = timestamp;
       ctr->is_new = 1;
       ctr->has_changed = 1;

       _IPCounterTree_Head_SPLAY_INSERT(&IPConnectorCounterRoot, ctr);
       //if ( ctr->rdns->do_reverse  && !ctr->rdns->resolved && !ctr->dns->is_posted ) { //    PostDNSQuery(ctr->rdns); //}
   }
   else {
       ctr->has_changed = 1;
       ctr->data.last = MAX(timestamp, ctr->data.last);
       ctr->data.first = MIN(ctr->data.first, timestamp);
       ctr->data.proj_last[PROJ_NONE] = ctr->data.last;
       ctr->data.proj_first[PROJ_NONE] = ctr->data.first;

       ctr->data.proj_last[proj] = MAX(timestamp, ctr->data.proj_last[proj]);

       if (ctr->data.proj_first[proj] > 0) {
         ctr->data.proj_first[proj] = MIN(ctr->data.proj_first[proj], timestamp);
       } else {
         ctr->data.proj_first[proj] = timestamp;
         ctr->has_changed = 1;
       }  

       ctr->data.total += count;
       ctr->data.count += count;

       if ( is_recent ) {
           ctr->data.recent += count;
           ctr->data.proj_recent[ PROJ_NONE ] += count;
           ctr->data.proj_recent[ proj ] += count;
       }

       ctr->data.proj_total[ PROJ_NONE  ] += count;
       ctr->data.proj_count[ PROJ_NONE  ] += count;
       ctr->data.proj_total[ proj ] += count;
       ctr->data.proj_count[ proj ] += count;
   }
}

/*
 *
 */
void PruneIPRequestorCounter(       struct in_addr  *specific,   int specific_count,
                                    struct in_addr  *exceptions, int exceptions_count )
{
     struct _IPCounterTreeNode* iter, *iter_next;
     int i;
     time_t cutoff1 = time(0) - 240 - 3600;
     time_t cutoff2 = time(0) - 3600 * 24;
     int pruned = 0;

#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneIPRequestorCounter: Scanning splay tree...\n");
#endif

     SPLAY_FOREACH(iter, _IPCounterTree_Head, &IPRequestorCounterRoot) 
     {
        /*
         * Enumerate splay tree, look for stale entries to nuke.
         */

            if ( iter->is_deleted )
                   continue; /* Already marked as deleted */


            if ( iter->data.last > cutoff1  ) {
                 continue;
            }

            if ( iter->data.total >= 3000 && iter->data.last > cutoff2 ) {
                 continue;
            }

            for(i = 0; i < specific_count; i++) {
                   if ( specific[i].s_addr == iter->addr.s_addr ) {
                        iter->is_deleted = 1;
                        break;
                   }
            }

            if ( iter->is_deleted ) 
                continue;

            iter->is_except = 0;

            


            for(i = 0; i < exceptions_count; i++) {
                   if ( exceptions[i].s_addr == iter->addr.s_addr ) {
                        iter->is_except = 1;
                        break;
                   }
            }

            if ( iter->is_except )
                 continue;

     }

     for ( iter = SPLAY_MIN(_IPCounterTree_Head, &IPRequestorCounterRoot);
           iter != NULL;
           iter = iter_next )
     {

           iter_next = SPLAY_NEXT(_IPCounterTree_Head, &IPRequestorCounterRoot, iter);


            if ( iter->is_deleted ) {
                RemoveIPRequestorCounter( iter );
                FreeIPCounter( iter );
                pruned++;
            }

     }

#ifdef DEBUG_PRUNE
     printf("DEBUG: PruneRequestorsIPCounterTable:  %d old entries freed from search tree, memory released.\n", pruned);
#endif
}



/*
 *
 */
void AddToIPRequestorCounter( struct in_addr*       source,
                            time_t                timestamp,
                            int                   proj,
                            int                   count,
                            int                   is_recent )
{

    IPCounterNode *ctr = LookupIPRequestorCounter( *source );
    char prettyIpAddr[42];


   if ( ctr == NULL ) {
       ctr = MakeIPCounterObj( *source );

       ctr->data.last = ctr->data.first = timestamp;
       ctr->data.total = count;
       ctr->data.recent = (is_recent ? count : 0);
       ctr->data.count = count;

       ctr->data.proj_total[ PROJ_NONE ] = count; 
       ctr->data.proj_recent[ PROJ_NONE ] = ctr->data.recent;
       ctr->data.proj_count[ PROJ_NONE ] = count;
       ctr->data.proj_first[ PROJ_NONE ] = timestamp;

       ctr->data.proj_total[ proj ] = count;
       ctr->data.proj_recent[ proj ] = ctr->data.count;
       ctr->data.proj_count[ proj ] = count;
       ctr->data.proj_first[ proj ] = timestamp;
       ctr->is_new = 1;
       ctr->has_changed = 1;

       _IPCounterTree_Head_SPLAY_INSERT(&IPRequestorCounterRoot, ctr);
       //if ( ctr->rdns->do_reverse  && !ctr->rdns->resolved && !ctr->dns->is_posted ) { //    PostDNSQuery(ctr->rdns); //}
   }
   else {
       ctr->has_changed = 1;
       ctr->data.last = MAX(timestamp, ctr->data.last);
       ctr->data.first = MIN(ctr->data.first, timestamp);
       ctr->data.proj_last[PROJ_NONE] = ctr->data.last;
       ctr->data.proj_first[PROJ_NONE] = ctr->data.first;

       ctr->data.proj_last[proj] = MAX(timestamp, ctr->data.proj_last[proj]);

       if (ctr->data.proj_first[proj] > 0) {
         ctr->data.proj_first[proj] = MIN(ctr->data.proj_first[proj], timestamp);
       } else {
         ctr->data.proj_first[proj] = timestamp;
         ctr->has_changed = 1;
       }   

       ctr->data.total += count;
       ctr->data.count += count;

       if ( is_recent ) {
           ctr->data.recent += count;
           ctr->data.proj_recent[ PROJ_NONE ] += count;
           ctr->data.proj_recent[ proj ] += count;
       }

       ctr->data.proj_total[ PROJ_NONE  ] += count;
       ctr->data.proj_count[ PROJ_NONE  ] += count;
       ctr->data.proj_total[ proj ] += count;
       ctr->data.proj_count[ proj ] += count;
   }


#ifdef DEBUG
printf("DEBUG [Project ID=%d]    IPRequestorCounterSplayTreeNODE->count == %d  IP ADDRESS %s\n", proj, ctr->data.proj_count[proj],
                 inet_ntop(AF_INET, &(ctr->addr), prettyIpAddr, sizeof(prettyIpAddr)));
#endif


//inet_ntop(AF_INET, &(pll->src.addr), prettyIpAddr, sizeof(prettyIpAddr)), pll->src.port
}





/*
 *
 */
void TriggerDomainCounter ( char     *            domain_name,
                            time_t                timestamp,
                            int                   proj,
                            int                   count,
                            int                   is_recent )
{

    DomainCounterNode *ctr = LookupDomainCounter( domain_name );

fprintf(stderr, "TriggerDomainCounter [%s]\n", domain_name);


   if ( ctr == NULL ) {
       ctr = MakeDomainCounterObj( domain_name );

       ctr->data.last = ctr->data.first = timestamp;
       ctr->data.total = count;
       ctr->data.recent = (is_recent ? count : 0);
       ctr->data.count = count;

       ctr->data.proj_total[ PROJ_NONE ] = count; 
       ctr->data.proj_recent[ PROJ_NONE ] = ctr->data.recent;
       ctr->data.proj_count[ PROJ_NONE ] = count;
       ctr->data.proj_first[ PROJ_NONE ] = timestamp;
       ctr->data.proj_last [ PROJ_NONE ] = timestamp;


       ctr->data.proj_total[ proj ] = count;
       ctr->data.proj_recent[ proj ] = ctr->data.count;
       ctr->data.proj_count[ proj ] = count;
       ctr->data.proj_first[ proj ] = timestamp;
       ctr->data.proj_last[ proj ] = timestamp;

       ctr->is_new = 1;
       ctr->has_changed = 1;

       _DomainCounterTree_Head_SPLAY_INSERT(&DomainCounterRoot, ctr);
   }
   else {
       ctr->has_changed = 1;
       ctr->data.last = MAX(timestamp, ctr->data.last);
       ctr->data.first = MIN(ctr->data.first, timestamp);
       ctr->data.proj_last[PROJ_NONE] = ctr->data.last;
       ctr->data.proj_first[PROJ_NONE] = ctr->data.first;

       ctr->data.proj_last[proj] = MAX(timestamp, ctr->data.proj_last[proj]);

       if (ctr->data.proj_first[proj] > 0) {
         ctr->data.proj_first[proj] = MIN(ctr->data.proj_first[proj], timestamp);
       } else {
         ctr->data.proj_first[proj] = timestamp;
         ctr->has_changed = 1;
       }   


       ctr->data.total += count;
       ctr->data.count += count;
       if ( is_recent ) {
           ctr->data.recent += count;
           ctr->data.proj_recent[ PROJ_NONE ] += count;
           ctr->data.proj_recent[ proj ] += count;
       }

       ctr->data.proj_total[ PROJ_NONE  ] += count;
       ctr->data.proj_count[ PROJ_NONE  ] += count;

       ctr->data.proj_total[ proj ] += count;
       ctr->data.proj_count[ proj ] += count;
   }


#ifdef DEBUG
printf("DEBUG [Project ID=%d]    DomainCounterSplayTreeNODE->access_count == %d  DOMAIN NAME %s\n", proj,
       ctr->data.proj_count[proj], ctr->domain  );
#endif

}








/* ***************************************************************************************************** */

#define DOMAIN_NAME_DSG_STR "domain_name="


void BuiltConnection( PIX_LOG_LINE *pll )
{
   static int iixPrune1 = 0, iixPrune2;


   if ( 1 || pll->requestCategory == REQ_CAT_TOWEBSERVER ) {
#ifdef PRUNE_LESS_OFTEN
     /* Pruning the tree too often, causes much CPU overhead...
      * Pruning too infrequently wastes gobs and gobs of memory */

     if ( (++iixPrune1 & 1023) == 0 ) {
         PruneIPConnectorCounter( NULL, 0, &(pll->src.addr), 1 );
     }
#else
         PruneIPConnectorCounter( NULL, 0, &(pll->src.addr), 1 );
#endif

                   //printf ("[ADDCON:%d] {%d}{%d}\n", pll->src.addr.s_addr);
     AddToIPConnectorCounter(   &(pll->src.addr),     pll->timestamp,  pll->project,  1, 1  );
   }




    //printf("DEBUG: %s\n");
}

void RequestedURI( PIX_LOG_LINE * pll )
{
   static char odomain[512] = "";
   static char* pt, * opt;
   static int iixPrune1 = 0, iixPrune2;

   if ( pll->requestCategory == REQ_CAT_TOWEBSERVER ) {
     // printf("DEBUG: RequestedURI: Request To Web Server : %s\n", pll->uri);


#ifdef PRUNE_LESS_OFTEN
     /* Pruning the tree too often, causes much CPU overhead...  
      * Pruning too infrequently wastes gobs and gobs of memory */

     if ( (++iixPrune1 & 1023) == 0 ) {
         PruneIPRequestorCounter( NULL, 0, &(pll->src.addr), 1 );
     }
#else
         PruneIPRequestorCounter( NULL, 0, &(pll->src.addr), 1 );
#endif

     AddToIPRequestorCounter(   &(pll->src.addr),     pll->timestamp,  pll->project,  1, 1  );
   }


   /* Outgoing request from a web server */
   if ( pll->requestCategory == REQ_CAT_FROMWEBSERVER ) {
     // printf("DEBUG: RequestedURI: Request From Web Server : %s\n", pll->uri);

     if ( strncmp( pll->uri,  "/pbaseurl?",  8 )  == 0 ) 
     {
           pt = pll->uri + 8;
             
           if ( !strncmp(pt, DOMAIN_NAME_DSG_STR, sizeof(DOMAIN_NAME_DSG_STR)-1  )  ) {

                pt += sizeof(DOMAIN_NAME_DSG_STR); 
                opt = odomain;

                while ( *pt && *pt != '&' && *pt != ':' && *pt != '%' && isascii(*pt) && (isalnum(*pt) || ispunct(*pt)) ) {
                      *opt++ = *pt++;


                       /* If the domain name gets too long, truncate it. */
                      if ( opt - odomain >= 80 ) {
                           *opt += snprintf(opt, 10, "_TRUNCATED_");
                           *opt++ = '\0';
                           break;
                      }
                }

                *opt++ = '\0';

#ifdef DEBUG
printf("DEBUG: domain1=%s\n", odomain);
#endif


           }

     }
#define WEB_PREFIX_2 "/d/search/p/____xml/domain/"

     else if ( 0 && strncmp(pll->uri, WEB_PREFIX_2, sizeof(WEB_PREFIX_2) - 1 ) == 0 ) 
     {
             pt = pll->uri + sizeof(WEB_PREFIX_2);
             opt = odomain;

             while ( pt = strchr(pt+1, '&') ) {

                  if ( !strncmp( pt, "&url=", 5 ) ) {
                       pt += 5;

                       break;
                  } else if ( !strncmp( pt, "&serveUrl=", 10 ) ) {
                       pt += 10;

                       break;
                  }
             }

             while( pt && *pt && *pt != '&' && *pt != '%' && isascii(*pt) && (isalnum(*pt) || ispunct(*pt)) )   {
                    *opt++ = *pt++;


                   /* If the domain name gets too long, truncate it. */
                   if ( opt - odomain >= 80 ) {
                        *opt += snprintf(opt, 10, "_TRUNCATED_");
                        *opt++ = '\0';
                        break;
                   }
             }

             *opt++ = '\0';

//DEBUG: UNKNOWN: /d/search/p/___

     }
     else if ( *pll->uri == '/' ) {
             int ss=0;
             pt = pll->uri + 1;
             opt = odomain;

             while ( pt = strchr(pt+1, '&') ) {

                  if ( !strncmp( pt, "&url=", 5 ) ) {
                       pt += 5;

                       break;
                  } else if ( !strncmp( pt, "&serveUrl=", 10 ) ) {
                       pt += 10; ss=1;

                       break;
                  } else if ( !strncmp( pt, "&domain=", 8 ) ) {
                       pt += 8;

                       break;
                  }

             }

             while( pt && *pt && *pt != '&' && *pt != '%' && isascii(*pt) && (isalnum(*pt) || ispunct(*pt)) )   {
                    *opt++ = *pt++;


                   /* If the domain name gets too long, truncate it. */
                   if ( opt - odomain >= 80 ) {
                        *opt += snprintf(opt, 10, "_TRUNCATED_");
                        *opt++ = '\0';
                        break;
                   }
             }

             *opt++ = '\0';
     }
     else {
#ifdef DEBUG_UNKNOWN
printf("DEBUG: UNKNOWN: %s\n", pll->uri);
#endif
     }



     if (*odomain != '\0') {
          TriggerDomainCounter( odomain,  pll->timestamp,  (int)(pll->project),  1, 1 );
#ifdef PRUNE_LESS_OFTEN
          if ( (++iixPrune2 & 1023) == 0 ) {
              PruneDomainCounter( );
          }
#else
              PruneDomainCounter( );
#endif

     }




     


//void TriggerDomainCounter ( char     *            domain_name,
//                            time_t                timestamp,
//                            int                   proj )
//
   }

}


void DeniedRequest( PIX_LOG_LINE * pll )
{
     static char prettyIpAddr[42];
     static int  iixPrune = 0;


#ifdef DEBUG
     printf("DEBUG: Denied Request  SRC interface=%d addr=%s port=%d\n", pll->src.interface,
            inet_ntop(AF_INET, &(pll->src.addr), prettyIpAddr, sizeof(prettyIpAddr)), pll->src.port);
#endif



#ifdef PRUNE_LESS_OFTEN
     if ( (++iixPrune & 1023) == 0 ) {
         PruneDenyIPCounterTable( NULL, 0, &(pll->src.addr), 1 );
     }
#else
         PruneDenyIPCounterTable( NULL, 0, &(pll->src.addr), 1 );
#endif
     AddDenyToIPCounter(   &(pll->src.addr),     pll->timestamp,  pll->project,  1,  1   );

}




void DeniedRequestNoTCPConnection( PIX_LOG_LINE * pll )
{
}




//
//  ($tstext, $host, $facility, $pixpri, $pixcode, $pixmessg) = ($1, $2, $3, $4, $5, $6);
//  ###

void decode_new_log_line ( PIX_LOG_LINE * pll ) { pll->tstext[0] = '\0'; pll->prio = 0; pll->code = 0; pll->project = 0; }

DECODE_1_RESULT decode_month_name( char * tok,        /* 3-letter month abbreviation in ASCII */
                                   PIX_LOG_LINE * pll /* Store the result here */  )
{ 

   int bpcode = 0;

   bpcode = ( ( ((unsigned char)tok[0])  <<  24 ) | ( ((unsigned char)tok[1]) << 16 )
              | ( ((unsigned char)tok[2]) << 8  ) | ( ((unsigned char)tok[3])       ));

   switch ( bpcode ) 
   {
        case    0x4a616e00: /* Jan */     pll->month = 1;     return GOODTOKEN;
        case    0x4a756e00: /* Jun */     pll->month = 6;     return GOODTOKEN;
        case    0x4a756c00: /* Jul */     pll->month = 7;     return GOODTOKEN;

        case    0x46656200: /* Feb */     pll->month = 2;     return GOODTOKEN;

        case    0x4d617200: /* Mar */     pll->month = 3;     return GOODTOKEN;
        case    0x4d617900: /* May */     pll->month = 5;     return GOODTOKEN;

        case    0x41707200: /* Apr */     pll->month = 4;     return GOODTOKEN;
        case    0x41756700: /* Aug */     pll->month = 8;     return GOODTOKEN;

        case    0x53657000: /* Sep */     pll->month = 9;     return GOODTOKEN;
        case    0x4f637400: /* Oct */     pll->month = 10;    return GOODTOKEN;
        case    0x4e6f7600: /* Nov */     pll->month = 11;    return GOODTOKEN;
        case    0x44656300: /* Dec */     pll->month = 12;    return GOODTOKEN;
        default:                                              return BADTOKEN;
   }


   return BADTOKEN; 
};

/* We sure don't want to call mktime() for every log message, it's just too slow... */
DECODE_1_RESULT decode_day_of_month( char *tok, PIX_LOG_LINE* pll) 
{
   /* Evilhack, XOR-ing an ASCII digit w./ '0' turns it into its int value, in this case,
      hardwire string-to-int and base conversion for 2-digit numbers. */

   if (tok[1]) {
       pll->day = ( ( ( ((unsigned char)tok[0] ^ '0') * 10 ) )
                  + ( ( ((unsigned char)tok[1] ^ '0') ) ));
   } else {
       pll->day = ((unsigned char)tok[0]) ^ '0';
   }

   if ( pll->day & (32|64|128|256) ) { 
            /* If the high-order bits are set, then we have an erroneous date */
       return BADTOKEN;
   }

   return GOODTOKEN; 
};

DECODE_1_RESULT decode_hour_minute_second( char* tok, PIX_LOG_LINE* pll ) { 

   static time_t beginningOfYear = -1,  endOfYear = -1;
   static int monthIndicator = -1,
     baseOffsetTable[] = { 0, 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}, offsetTable[13] = {};
   int i;

  /* Make sure it looks like __:__:__  before trying to decode */

  if ( tok[0] != '\0' && tok[1] != '\0' && tok[2] == ':' &&
       tok[3] != '\0' && tok[4] != '\0' && tok[5] == ':' &&
       tok[6] != '\0' && tok[7] != '\0' ) 
  {


     pll->hour =    ( ( ( ((unsigned char)tok[0] ^ '0') * 10 ) )
                  + ( ( ((unsigned char)tok[1] ^ '0') ) ));

     pll->minute =  ( ( ( ((unsigned char)tok[3] ^ '0') * 10 ) )
                  +  ( ( ((unsigned char)tok[4] ^ '0') ) ));


     pll->second =  ( ( ( ((unsigned char)tok[6] ^ '0') * 10 ) )
                  +  ( ( ((unsigned char)tok[7] ^ '0') ) ));



       /* Now, to compute the complete timestamp, we're going to add an offset 
          associated with the year and month. */

        /* Build static tables; only needs to be done at startup, 
           or if we think the current year changed */
       if ( beginningOfYear == -1 || pll->month < monthIndicator) 
       {
            time_t iNow = time(NULL);
            struct tm* tm_p = localtime(&iNow);
            struct tm tm_o;


            monthIndicator = tm_p->tm_mon + 1;
            if (pll->month > monthIndicator) {
                monthIndicator = pll->month;
            }
              
            tm_o = *tm_p;
            tm_o.tm_sec = tm_o.tm_min = tm_o.tm_hour = tm_o.tm_mon = tm_o.tm_wday = tm_o.tm_yday = 0;
            tm_o.tm_mday = 1;

            beginningOfYear = mktime(&tm_o);

            tm_o.tm_wday = tm_o.tm_yday = 0;
            tm_o.tm_hour = 23;
            tm_o.tm_sec = tm_o.tm_min = 59;
            tm_o.tm_mon = 11;
            tm_o.tm_mday = 31;
            tm_o.tm_year = tm_p->tm_year;
            endOfYear = mktime(&tm_o);

            /* Adjust the offset table for leap years */
            if ( (1900+tm_o.tm_year) & 3 == 0   /* if the year is divisible by 4, then LY... */
                  &&
                   /* Except when not divisible by 400 and divisible by 100. */
                 ((1900+tm_o.tm_year) % 100 || !((1900+tm_o.tm_year) % 400))) 
            { 
                 baseOffsetTable[3] = 29;
            }
            else { 
                 baseOffsetTable[3] = 28;
            }


            /* Now we'll build the month index table */
            for(i = 0; i < 13; i++) {
                offsetTable[i] = baseOffsetTable[i]*86400 + (i > 0 ? offsetTable[i-1] : 0);
                printf ("DEBUG: offsetTable[%.2d] = %d\n", i, offsetTable[i]);
            }
       }


       pll->timestamp = beginningOfYear + offsetTable[ pll->month & 0x1F ]
                         + (pll->day - 1)*3600*24
                         + pll->hour*3600 
                         + pll->minute*60 
                         + pll->second;

       if ( pll->timestamp < 0 || pll->timestamp < beginningOfYear || pll->timestamp > endOfYear )  {
            printf("INVALID TIMESTAMP: %ld       [b=%ld,e=%ld]\n", pll->timestamp, beginningOfYear, endOfYear);
           return BADTOKEN;
       }


      return GOODTOKEN;
  }

  return BADTOKEN; 
}

DECODE_1_RESULT decode_log_facility_pri( char *token1, PIX_LOG_LINE* pll) { 
 char * marker;
 int j, b0, b1, b2;

 if ( marker = strchr(token1, '@') ) {
        return BADTOKEN;
 }
 else if ( marker = strchr(token1, '/') ) 
 {
      strncpy ( pll->host2, marker + 1,  sizeof( pll->host2 ) ) ;
      pll->host2[sizeof(pll->host2) - 1] = '\0';

      j = (int)(marker - token1);

      if ( j >= 0 )
      {
          j = ( j < sizeof(pll->host1) ) ? j
                                         : (sizeof(pll->host1) - 1);

          strncpy( pll->host1, token1, j);
          pll->host1[j] = '\0';
      }

      

     /* b0 = (     ( (unsigned char)pll->host[0] << 24 )       
               | ( (unsigned char)pll->host[1] << 16 )
               | ( (unsigned char)pll->host[2] <<  8 )
               | ( (unsigned char)pll->host[3]       )
           );    */

     if ( !strcmp(pll->host1, "A-Pix") ) {
         pll->project = PROJ_A;
     } else if (!strcmp(pll->host1, "B-Pix")) {
         pll->project = PROJ_B;
     } else if (!strcmp(pll->host1, "C-Pix")) {
         pll->project = PROJ_C;
     } else {
     }
     


 }


  return GOODTOKEN; 
}

int decode_pix_string ( char* token,  PIX_LOG_LINE *pix_log_line )
{
      if ( strncmp( token, "%PIX-", 5 ) ) 
           return BADTOKEN;

      if ( sscanf( token, "%%PIX-%d-%d:", &(pix_log_line->prio), &(pix_log_line->code) ) == 2 ) {
          return GOODTOKEN;
      }

      return BADTOKEN;
} 


int get_pix_line_data ( char *logbuf,
                        int   message_length,
                        PIX_LOG_LINE * pix_log_line )
{
       static char log_message [LOGBUF+2], *logp;
       char *tok = log_message;
       char *ptok;  /* Temporary token pointer */
       int argnum = 0, i = 0, nullc=0, found;
       DECODE_1_RESULT v;


       logp = strcpy( log_message, logbuf );
       decode_new_log_line ( pix_log_line );


       while ( tok = strsep(&logp, " ") )
       {
               switch ( argnum ) 
               {
                 case 0:  v=   decode_month_name          ( tok, pix_log_line );      break;
                 case 1:  if (!*tok && nullc++<3) { argnum--; break; }
                          v=   decode_day_of_month        ( tok, pix_log_line );      break;

                 case 2:  v=   decode_hour_minute_second  ( tok, pix_log_line );      break;

                 case 3:  v=   decode_log_facility_pri    ( tok, pix_log_line );      break;
                 case 4:  v=   decode_pix_string          ( tok, pix_log_line );

                         if (v == GOODTOKEN) {
                             /* Throw out messages with pix codes that aren't in our list */

                             found = 0;

                             /*
                              *   For now, this is an array lookup.
                              */

                             for(i = 0; i < sizeof(pixcodes_to_pass_through)/
                                            sizeof(*pixcodes_to_pass_through); i++)
                             {
                                   if (  pix_log_line->code == pixcodes_to_pass_through[i]  ) {
                                       found = 1;
                                       break;
                                   }
                             }

                             if ( !found ) {
                                 return BADTOKEN;
                             }

                             if ( (logp - log_message) > 0 && strlen(logbuf) > (logp-log_message) ) {
                                  strncpy( pix_log_line->messg, logbuf + (logp-log_message), 
                                           strlen(logbuf) - (logp - log_message)  );
                             }

//302013

                             // return GOODTOKEN;
                         }
                      break;

                 case 5:
                      if ( pix_log_line->code == 302013)
                           break;
                      else if ( pix_log_line->code == 304001) { 
                          if ( inet_pton(PTON_INET4, tok, &(pix_log_line->from_ipaddr)) >= 0 ) {
                              long fromVal = htonl(pix_log_line->from_ipaddr.s_addr);

                              pix_log_line->requestCategory = REQ_CAT_UNKNOWN;


                               if ( IsWebServer(fromVal, pix_log_line->project) )
                                    pix_log_line->requestCategory = REQ_CAT_FROMWEBSERVER;

                              break;
                          } else {
                              v = BADTOKEN;
                          }

                          //
                      }
                      else if ( pix_log_line->code == 106023 || pix_log_line->code == 106015 ) {

                           if ( strcmp(tok, "Deny") ) {
                                 return BADTOKEN;
                           }

                           break;

                      }

                      return v;

                 case 6:
                        if (pix_log_line->code == 302013 && tok && *tok == 'i') {
                             /* Inbound */
                             break;
                        }
                        if (pix_log_line->code == 304001 && tok && *tok == 'A') break;

                        if ( pix_log_line->code == 106015 ) {
                             if ( !strcmp(tok, "TCP") && ( tok = strsep(&logp, " ") )  && !strcmp(tok, "(no") &&
                                                         ( tok = strsep(&logp, " ") ) 
                                ) {
                                    
                                        break;
                             }

                        }
                        else if ( pix_log_line->code == 106023 ) {
                             pix_log_line->protocol = IPPROTO_IP;

                             if ( !strcmp(tok, "tcp") ) {
                                  pix_log_line->protocol = IPPROTO_TCP;
                                  break;
                             }
                             else if ( !strcmp(tok, "udp") ) {
                                  pix_log_line->protocol = IPPROTO_UDP;
                                  break;
                             }
                             else {
                                  struct protoent *protocol = getprotobyname(tok);

                                  if ( protocol != NULL ) {
                                        pix_log_line->protocol = protocol->p_proto;
                                  }
                             }


                             if ( pix_log_line->protocol == IPPROTO_IP )  { return BADTOKEN; }
                        }

                        return v;

                 case 7:
                        if (pix_log_line->code == 302013 && tok && *tok == 'T') {
                             break;  /* TCP */
                        }
                        if (pix_log_line->code == 304001) break;
                        else if (pix_log_line->code == 106015) {
                             if (!strcmp(tok, "from") && (tok = strsep(&logp, " "))) {
                                  if ( ptok = strchr(tok, '/') ) {

                                         *ptok = '\0';

                                          inet_pton(AF_INET, tok, &(pix_log_line->src.addr));
                                          pix_log_line->src.port = atoi(ptok + 1);
                                  }

                                  tok = strsep(&logp, " ");
                                  if (!tok)
                                       break;
                             }
     
                             if (tok && !strcmp(tok, "to") && (tok = strsep(&logp, " "))) {
                                  if ( ptok = strchr(tok, '/') ) {

                                         *ptok = '\0';

                                          inet_pton(AF_INET, tok, &(pix_log_line->dst.addr));
                                          pix_log_line->dst.port = atoi(ptok + 1);
                                  }

                                  tok = strsep(&logp, " ");
                                   break;
                             }

                        }
                        else if (pix_log_line->code == 106023) {
                             struct _place_part *place = NULL;

                            if ( !strcmp(tok, "src") && ( tok = strsep(&logp, " ") ) )
                                 place = &(pix_log_line->src);

                            if ( tok && !strcmp(tok, "dst") && ( tok = strsep(&logp, " ") ) )
                                 place = &(pix_log_line->dst);

                            if ( tok && !strcmp(tok, "by") ) {
                                  break;
                            }


                            if (place != NULL) { 
                                 argnum--;
                                 ptok = strchr(tok, ':');

                                 if ( !strncmp(tok, "inside:", 7) ) {         place->interface = INTF_INSIDE;  }
                                 else if ( !strncmp(tok, "outside:", 8) ) {   place->interface = INTF_OUTSIDE; }
                                 else  return BADTOKEN;


                                 if ( ptok ) {
                                      tok = ptok + 1;
                                      ptok = strchr(tok, '/');

                                      if ( ptok ) {
                                          *ptok = '\0';

                                          if ( inet_pton(AF_INET, tok, &(place->addr)) < 0) {
                                              *ptok = '/';
                                              break;
                                          }
                                          

                                          place->port = atoi( ptok + 1 );
                                      }                       
                                 }
                                  
                                 //  outside:89.110.9.193/1625
                                 break;
                            }


                            return BADTOKEN;
                        }
                        
                        return v;

                 case 8:
                        if (pix_log_line->code == 302013 && tok && *tok == 'c') {
                             break;  /* connection */
                        }

                        if (pix_log_line->code == 304001) 
                        {
                            pix_log_line->uri[0] = '\0';


                            if (ptok = strchr(tok, ':')) {
                                 *ptok = '\0';

                                 if ( inet_pton(PTON_INET4, tok, &(pix_log_line->to_ipaddr)) >= 0) {
                                      long toVal = htonl(pix_log_line->to_ipaddr.s_addr);

                                      if (IsWebServer(toVal, pix_log_line->project))
                                          pix_log_line->requestCategory = REQ_CAT_TOWEBSERVER;
                                 } else {
                                      return BADTOKEN;
                                 }

                                 *ptok = ':';
                            } else {
                                 break;
                            }


                            strncpy( pix_log_line->uri, ptok + 1, sizeof(pix_log_line->uri));
                            pix_log_line->uri[sizeof(pix_log_line->uri) - 1] = '\0';

                             // printf(" DEBUG:  %d-%d   %.2d:%.2d:%.2d [%d] [Project=%d] [RequestCat=%d] %X\n", pix_log_line->month, 
                             //             pix_log_line->day,
                             //             pix_log_line->hour, pix_log_line->minute, pix_log_line->second,
                             //   pix_log_line->timestamp,
                             //   pix_log_line->project, pix_log_line->requestCategory,
                             //   pix_log_line->from_ipaddr.s_addr);
                             // printf(" DEBUG URL: %s\n", tok);

/*
 * Here we can begin URI processing 
*/
                             return GOODTOKEN;

                             break;
                        } else if ( pix_log_line->code == 106023 ) {
                             return GOODTOKEN;
                        } else {

#ifdef DEBUG
printf("DEBUG -- %d\n", pix_log_line->code);
#endif
                        }

                 case 9:
//  outside:82.168.108.196/24777 (82.168.108.196/24777) to inside:69.46.226.167/80 (69.46.226.167/80)

                        if (pix_log_line->code == 302013) {
                             break;  /* <code> */
                        }
                        return v;

                 case 10:
                        if (pix_log_line->code == 302013 && tok && *tok == 'f') {
                             break;  /* for */
                        }
                        return v;

                 case 11:
                        if (pix_log_line->code == 302013 && tok && (ptok = strchr(tok, ':'))) {
                              char *ptok1;

                              pix_log_line->uri[0] = '\0';
                              ptok1 = ++ptok;
  

                              if ( (ptok = strchr(ptok1, '/')) ) {
                                   *ptok = '\0';

                                   if ( inet_pton(PTON_INET4, ptok1, &(pix_log_line->src.addr)) >= 0) {
                                        // pix_log_line->src.port = atoi(ptok+1);

                                       // long toVal = htonl(pix_log_line->from_ipaddr.s_addr);
  
                                       // if (IsWebServer(toVal, pix_log_line->project))
                                       //     pix_log_line->requestCategory = REQ_CAT_TOWEBSERVER;
                                   } else {
                                        return BADTOKEN;
                                   }
  
                                   *ptok = ':';
                              } else {
                                   break;
                              }


                              break;  /* outside:XXX */
                        }
                        return v;

                 case 12:
                        if (pix_log_line->code == 302013 )
                              break; /* (XXX/YYY) */
                        return v;

                 case 13:
                        if (pix_log_line->code == 302013 && tok && tok[0] == 't' && tok[1] == 'o' && tok[2] == '\0')
                              break;
                        return v;

                 case 14:
                        /* inside:69.46.226.167/80 (69.46.226.167/80) */
                        if (pix_log_line->code == 302013 &&  *tok == 'i' && (ptok = strchr(tok, ':'))) {
                              char* ptok1;

                              pix_log_line->uri[0] = '\0';
                              ptok1 = ++ptok;

 

                              if ( (ptok = strchr(ptok1, '/')) ) {
                                   *ptok = '\0';

                                   if (ptok[1] != '8' || ptok[2] != '0' || ptok[3] != '\0')
                                        return BADTOKEN;

                                   if ( inet_pton(PTON_INET4, ptok1, &(pix_log_line->dst.addr)) >= 0) {
                                       long toVal = htonl(pix_log_line->dst.addr.s_addr);
 
                                       if (IsWebServer(toVal, pix_log_line->project)) {
/*printf("TOWEBSERVER: %s  %s  %s\n", tok, ptok1, ptok);*/
                                            pix_log_line->requestCategory = REQ_CAT_TOWEBSERVER;
                                        } else {
printf("FILTER: [%s] [%s] [%s] {%X}: %d/%d\n", tok, ptok1, ptok+1, toVal, pix_log_line->project, IsWebServer(toVal, pix_log_line->project));
}

                                       pix_log_line->dst.port = atoi(ptok+1);
                                   } else {
                                        return BADTOKEN;
                                   }
 
                                   *ptok = ':';
                              } else {
                                   break;
                              }



                              break; /* inside:XXXX */
                        }
                        return v;

                 case 15:
                        if (pix_log_line->code == 302013 ) {

                               if (pix_log_line->requestCategory == REQ_CAT_TOWEBSERVER) {
                                   BuiltConnection(pix_log_line);
                               }

                              break; /* (XXX/YYY) */
                       }
                        return v;


                 default:
                      return v;
               }
              

               if ( v == BADTOKEN )
                   return v;

               argnum++;
       }


       return BADTOKEN;
}



void ReadTreeFile()
{
    FILE* fp = fopen (PROCPIX_DAT, "r");
    char buf[512+1]="", cmd[512+1], arg0[512+1], buf2[512+1], r_name[512+1];
    struct _CounterData data;
    struct _DomainCounterTreeNode *dom;
    struct _IPCounterTreeNode *ipo, *tndu;
    ReversalNode* rdns_node;
    char *sp, *sp2;
    int j = 0;

    if (fp == NULL)
           return;

    while ( fgets(buf, 512, fp) ) {
         if (buf[0] != '.')
             continue;

         if ( !strncmp(buf, ".REVERSAL ", 9) ) {
              int r_res,r_dummy,r_addr_n;
              time_t r_time;
                
              if ( sscanf(buf, ".REVERSAL %d %d %X %d %s", &r_res, &r_dummy, &r_addr_n, &r_time, r_name) >= 5 ) {
                   struct in_addr r_address = { s_addr: ntohl(r_addr_n) };
                   rdns_node = MakeReversalNode( r_address  );
                   AddReversalNode( rdns_node );

                   rdns_node->resolved = r_res;
                   strncpyzt( rdns_node->name, r_name, sizeof(rdns_node->name) );
                   rdns_node->attime = r_time;
                   rdns_node->resolved=2;
                   rdns_node->do_reverse = 1;

                   if ( tndu = LookupIPDenyCounter( rdns_node->addr ) ) {
                      if (!tndu->rdns) {
                          tndu->rdns = rdns_node;
                          rdns_node->refcnt++;
                      }
                   }


                   if ( tndu = LookupIPConnectorCounter( rdns_node->addr ) ) {
                      if (!tndu->rdns) {
                          tndu->rdns = rdns_node;
                          rdns_node->refcnt++;
                      }
                   }

                   if ( tndu = LookupIPRequestorCounter( rdns_node->addr ) ) {
                      if (!tndu->rdns) {
                          tndu->rdns = rdns_node;
                          rdns_node->refcnt++;
                      }
                   }  
              }
         }


         if ( sscanf(buf, "%s %s %d %d %ld %ld", cmd, arg0, &(data.total), &(data.recent), &(data.first), &(data.last) ) < 6 ) {
              continue;
         }


         sp = buf;
         j = 0;

         while ( (sp = strchr(sp+1, ':')) && (j < PROJ_SIZE) ) {
               for(sp2 = sp; *sp2 && *sp2 != ' '; sp2++ )
                    ;
               if (sp2 == sp)
                   continue;

               strncpy(buf2, sp, sp2 - sp);
               buf2[sp2 - sp] = '\0';

               sscanf(buf2, ":%d,%d,%ld,%ld",  &(data.proj_total[j]), &(data.proj_recent[j]), &(data.proj_first[j]), 
                                         &(data.proj_last[j]));
               j++;
         }




         data.recent=0;
         for(j=0;j<PROJ_SIZE;j++) {
              data.proj_recent[j]=0;
         }



         if (!strcmp(cmd, ".DOMAIN")) {
               dom = MakeDomainCounterObj( arg0 );

               (dom->data) = data;
               AddDomainCounter(dom);

               dom->is_new = 0;
               dom->has_changed = 0;
         }


         if (!strcmp(cmd, ".REQ")) {
               struct in_addr arg0_addr;

                if ( inet_pton(PTON_INET4, arg0, &(arg0_addr)) >= 0) {

                   ipo = MakeIPCounterObj( arg0_addr );

                   (ipo->data) = data;
                   AddIPRequestorCounter(ipo);

                   ipo->is_new = 0;
                   ipo->has_changed = 0;
                }
         }



         if (!strcmp(cmd, ".CON")) {
               struct in_addr arg0_addr;

                if ( inet_pton(PTON_INET4, arg0, &(arg0_addr)) >= 0) {

                   ipo = MakeIPCounterObj( arg0_addr );

                   (ipo->data) = data;
/*{
 FILE *fp = fopen("/root/debug_file.tmp", "a");
 char buf[512];

 if (fp) {
 fprintf(fp, "AddIPConnectorCounter(): %d\n", arg0_addr.s_addr);
 fclose(fp);
 }
}*/
                   AddIPConnectorCounter(ipo);

                   ipo->is_new = 0;
                   ipo->has_changed = 0;
                }
         }





         if (!strcmp(cmd, ".DENY")) {
               struct in_addr arg0_addr;

                if ( inet_pton(PTON_INET4, arg0, &(arg0_addr)) >= 0) {

                   ipo = MakeIPCounterObj( arg0_addr );

                   (ipo->data) = data;
                   AddIPDenyCounter(ipo);

                   ipo->is_new = 0;
                   ipo->has_changed = 0;
                }
         }

    }

    fclose(fp);

    PruneDomainCounter();
    PruneIPRequestorCounter(NULL,0,NULL,0);
    PruneIPConnectorCounter(NULL,0,NULL,0);
    PruneDenyIPCounterTable(NULL,0,NULL,0);
}



int readline(char *outbuf, int nbytes, int fd)
{
     char temp[5];
     int c, opos=0;

     outbuf[0] = '\0';

     while ( 1 )
     {
         if ( opos+1 >= nbytes ) {
             break;
         }

         c = read(fd,temp,1);

         if ( c == 0 ) {
             return 0;
         }
         else if ( c < 0 ) {
             return 0;
         }

         outbuf[opos++] = temp[0];

         if (temp[0] == '\n') {
             outbuf[opos++] = '\0';

             return 1;
         }
     }

     outbuf[opos] = '\0';
     return -opos;
}

int main(int argc, char ** argv)
{
     FILE *fp_pos = NULL;
     PIX_LOG_LINE pixline;
     off64_t nbytes, endpos;
     char buf[LOGBUF+2] = "";
     char *sposfile = NULL;
     const char* filen;
     char *p, *nextp;
     int fd;
     int start;
     int writelen;
     int c;
     int tomove = -1;
     int maxLines = -1;
     int projId;
     ssize_t x;

     char *buf_tok, *line;
     int lineNum = 0;
     struct in_addr dns_servers[2];


     struct ares_options  dns_options;


     alarm(1000);//

     setprotoent(1);
     SPLAY_INIT(&IPDenyCounterRoot);
     SPLAY_INIT(&IPRequestorCounterRoot);
     SPLAY_INIT(&IPConnectorCounterRoot);
     SPLAY_INIT(&DomainCounterRoot);
     SPLAY_INIT(&ReversalRoot);

     //dns_servers[0].s_addr = htonl(0x7F000001);
     //dns_servers[1].s_addr = htonl(PRETTY_ADDR(255,255,255,255));
     dns_options.timeout = 3; 
     dns_options.tries = 1;
     dns_options.lookups = "b";



     //dns_options.servers = dns_servers;
     //dns_options.nservers = 1;
     
     if ( ares_init_options(&dns_channel, &dns_options, ARES_OPT_TIMEOUT | ARES_OPT_TRIES | /*ARES_FLAG_PRIMARY |*/
                                                  /* ARES_FLAG_STAYOPEN |*/ ARES_FLAG_NOSEARCH | ARES_FLAG_NOCHECKRESP ) 
         != ARES_SUCCESS ) 
     {
        printf("Error initializing DNS\n");

        abort();
     }



     ReadTreeFile();

     signal(SIGUSR1, AllStats);


     if ( argc < 3 || !argv[1] || !argv[2] ) {
         printf("Usage: %s <nbytes>[:S<path>] <file>\n", argv[0]);
         return 0;
     } 

     filen = argv[2];
     nbytes = strtoll(argv[1], (char**)0, 10);

     fd = open(filen, O_RDONLY | O_LARGEFILE);
     if (fd == -1) { perror("open"); return; } 


     endpos = lseek64(fd, 0, SEEK_END);

     if (nbytes != 0) {        
         char *xp;
  
         if ( nbytes < 0 ) {
             maxLines = (-nbytes)/10;

             if ( lseek64(fd, nbytes, SEEK_END) < 0 ) {
                  perror("lseek64");
                  return;
             }
         } else {
             if ( lseek64(fd, nbytes, SEEK_SET) < 0 ) {
                   perror("lseek64");
                   return;
             }
         }

         if ( (xp = strchr(argv[1], ':')) && xp[1] == 'S' ) {
               char ndata[256], *ndata_pos;
               off64_t nval, nval2=1;               

               xp += 2;
               sposfile = xp;

               if (!strcmp(sposfile, argv[2]))
                   sposfile = NULL;

               if ( (fp_pos = fopen(sposfile, "r")) ) { 
                    if ( fgets(ndata, 255, fp_pos) ) {
                        nval = strtoll( ndata, &ndata_pos, 10);

                        if ( ndata_pos && *ndata_pos)
                             nval2 = atoll( ndata_pos );


                        if ( nval==nval2 && (nval < endpos)
                              && (nval > lseek64(fd, 0, SEEK_CUR))
                              && lseek64(fd, nval, SEEK_SET) < 0 ) {
                             perror("lseek64");
                        } else if (nval!=nval2) {
                            fprintf(stderr, "ERROR: %lld != %lld\n", nval, nval2);
                        }
                    }
                    fclose(fp_pos);
               }
         }

         while ( 1 ) 
         {
             c = read(fd, buf, 1);
             if (c == 0) {
                 break;
             }
             else if (c < 0) {
                 perror("read");
                 return;
             }
             else if (buf[0] == '\n') {
                 break;
             }

             continue;
         }
     }

     start = 0;

     while ( (x=read(fd, buf + start, LOGBUF - start)) > 0 ) {
          if ( maxLines != -1 && lineNum > maxLines )
               break;


           p = buf;
           x += start;
           tomove = -1;

           while ( nextp = strrchr(p+1, '\n') ) {
                  p = nextp;
           }

           writelen = (p - buf);

           if ( writelen < 1 ) {
                writelen = x;
           }
           else if ( writelen < x ) {
               start = x - writelen;
               tomove = 1;

               memmove(p+1, p, (x-writelen));
               *p = '\0';
           }
           
           buf_tok = buf;



           while ( line = strsep(&buf_tok, "\n") )
           {
                 lineNum++;

                 if ( (lineNum & (63)) == 0 ) {
                     if ((lineNum & 8191) == 0) {
                       printf("DEBUG: lineNum=%ld,  maxlines=%ld\n", lineNum, maxLines);
                       printf("DEBUG: Last Line was: %s\n", line);
                     
                       usleep(20000);
                     }
                       //printf("DEBUG: line=%d\n", lineNum);
                 }

                 if ( get_pix_line_data( line , strlen(line), &pixline ) != GOODTOKEN ) 
                       continue;


// printf("{ %s/%s ", pixline->host1, pixline->host2);

#ifdef DEBUG_PRINT
                 puts(line);
#endif


                 switch ( pixline.code ) {
                    case 302013: BuiltConnection( &pixline ); break;
                    case 304001: RequestedURI( &pixline );  break;
                    case 106023: DeniedRequest( &pixline ) ; break;
                    case 106015: DeniedRequestNoTCPConnection( &pixline ); break;
                    default: ; break;
                 }


                 
           }

           if ( tomove ) {
               if ( x >= writelen ) {
                   memmove(buf, p+1, (x - writelen));
               } else {
                    printf("DEBUG: WARN x < writelen ::\n");
               }
           }
     }
     printf("\n");
     printf("@END_POS=%lld\n", lseek64(fd,0,SEEK_CUR));

     if ( sposfile ) 
     {
               if ( (fp_pos = fopen(sposfile, "w")) ) { 
                    off64_t xxx = lseek64(fd,0,SEEK_CUR);

                    fprintf(fp_pos, "%lld %lld\n", xxx, xxx );
                    fclose(fp_pos);
               }
     }

     close(fd);

     for(projId = 0 ; projId < PROJ_SIZE ; projId++ ) {
         PrepareStats( projId, 1 );
     }
}

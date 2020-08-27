// Mysidia C 2007

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcre.h>
#include <string.h>

#define CMDBUF_FILE "/home/errorparse/errorparse.cmdbuf"
#define ERRORPARSE_X_OUTPUT "/home/errorparse/errorparse.out"


/* Begin classify list */
struct 
{
   char * re_text;  /* Regular Expression Text */
   char * cl_name;  /* Message type  */
   int     g_pref;  /* Global Preference -- lower number = earlier match*/


   /* Runtime info */
   pcre * compiled_object; 
}

msg_class[ ] = {

   {  "^\\s*Function: xml_socketopen",                           "xmls",         100   },
   {  "^\\s*Description: Unable to connect.* 192\\....\\.226\\.9",  "select1",      200   },
   {  "^Unable to connect.* 192\\.168\\....\\.8$",                 "select2",      300   },
   {  "^\\s*Description: CREATE",                                "loggerupdate", 400   },
   {  "^\\s*Description: UPDATE",                                "loggerupdate", 400   },
   {  "^\\s*Description: INSERT",                                "loggerupdate", 400   },
   {  "select(\\d)",                                             "select%.3s",     500   },
   {  "loggerupdate",                                            "loggerupdate", 600   },


   /* catch anything else as unknown */

   { (char*)0,                                                    "UNKNOWN",      0x7fffffff },
},
msg_class_temp;
/* End classify table */


void do_compile()
{
    int i, maxi=0;
    char const *errptr;
    int  erroffset;
    int  flag=1;

    for(i = 0 ; msg_class[i].re_text != 0; i++) {
       msg_class[i].compiled_object = pcre_compile( msg_class[i].re_text, 0,
                &errptr, &erroffset, NULL);

       if ( msg_class[i].compiled_object == NULL )  {
           fprintf(stderr, "ERROR Compiling regular expression:  %s   (%s)\n",  msg_class[i].re_text, errptr);
       } 
       maxi++;
    }
 
    while ( flag == 1 )
    {
       flag = 0;
    
       for(i = 0 ; i < maxi ; i++) {

           if ( msg_class[i].g_pref > msg_class[i+1].g_pref ) {
               msg_class_temp = msg_class[i];
               msg_class[i] = msg_class[i+1];
               msg_class[i+1] = msg_class_temp;
               flag=1;
           }
       }
    }
}


int valid_string( const char * text )
{
   const char* p;

   while (*p != '\0') { if (!isascii(*p)) return 0; p++; }
   return 1;
}



int safe_string( const char * text )
{
   const char* p = text;

   while (*p != '\0') {
       if (!isascii(*p) || (!isalnum(*p) && !ispunct(*p) && *p != '.'))
            return 0;
       p++;
   }
   return 1;
}



int valid_email( const char * text )
{
   const char* p = text;
   int atseen = 0;

   if (!isascii(*text) || !isalpha(*text)) {
        return 0;
   }

   while (*p != '\0') {
      if (*p == '@') {
          if ( atseen )
               return 0;
          atseen = 1;
          p++;

          continue;
      }
      if (!isascii(*p))
           return 0;
      if (!isalnum(*p)) {
          if ( atseen ) {
               if (  *p != '-' && *p != '.' ) 
                   return 0;
          }

          if (!ispunct(*p) && *p != '.' && *p != '-')
              return 0;
      }
      p++;
   }
   return 1;
}

int main()
{
  FILE *fp;
  FILE *fpout;
  time_t curtime, xtime;
  char env_ext2[256]="";
  char server_name[256] = "UNKNOWN";
  char from_address[256];
  char from_host[256] = "UNKNOWN";
  char record_host[256] = "";
  char msgtype[256] = "UNKNOWN";
  char buffer[1024];
  char *p;
  int hostid = 0;

  do_compile();

  if (!(fp = fopen(CMDBUF_FILE, "a"))) {
       perror("fopen");
       exit(1);
  }

  curtime = time(0);
  xtime = time(0);

  if ( xtime % 300 > 0 ) {
        xtime -= (xtime % 300);
  }

  if ( p = getenv("SENDER") ) {
      strncpy(from_address, p, sizeof(from_address));
      from_address[sizeof(from_address) - 1] = '\0';
  }

  if ( p = getenv("EXT2") ) {
      strncpy(env_ext2, p, sizeof(env_ext2));
      env_ext2[sizeof(env_ext2) - 1] = '\0';
  }

  if ( (p = getenv("EXT2")) && *p && isascii(*p) && !isspace(*p) && safe_string(p) ) {
       strncpy(record_host, p, sizeof(record_host));
       record_host[sizeof(record_host) - 1] = '\0';
       while ( p = strchr(record_host, '.') )
            *p = '_';
  } else if ( valid_email(from_address) ) {
       char * hostpart;

       if ( hostpart = strchr(from_address, '@') ) {
          strncpy(record_host, hostpart+1, sizeof(record_host));
          record_host[sizeof(record_host) - 1] = '\0';
       }
  }

  if ( fpout = fopen(ERRORPARSE_X_OUTPUT, "a") )
  {
        int ovector[25],x;
        char outbuf[256]="";
       
         
        fprintf(fpout, "\n");

        fprintf(fpout, "X-From-Addr: %s\n"
                       "X-Ext2: %s :: %s\n"
                       "X-Info: %s %s", from_address, env_ext2, record_host,
                                        "", ""
                                     /* x->first_time, x->last_time, x->count, x->server */);
        while(fgets(buffer, 512, stdin))
        {
              if (!strcmp(msgtype, "UNKNOWN"))
              { 
                  int i;

                  for(i = 0; msg_class[i].re_text != NULL; i++) {
                      if (!msg_class[i].compiled_object)
                            continue;

                     outbuf[0] = '\0';
                     x= pcre_exec(msg_class[i].compiled_object, NULL, buffer, strlen(buffer), 0, /*options*/0,
                                    ovector, sizeof(ovector)/sizeof(ovector[0]));

                     if (x > 0) {
                          strncpy(msgtype, msg_class[i].cl_name, sizeof(msgtype));
                          msgtype[sizeof(msgtype) - 1] = '\0';

                          if (x > 1) {

                             if (   pcre_copy_substring( buffer, ovector, x, 1, outbuf, sizeof(outbuf) - 1  ) > 0 ) {
                                  sprintf(msgtype, msg_class[i].cl_name, outbuf);
                             } else { outbuf[0] = '\0'; }

                          }
                     }

#ifdef DEBUG
                     fprintf(stderr, "DEBUG: PCRE_EXEC=%d\n", x);
#endif
                  }

              }
              fprintf(fpout, "%s", buffer);
        }
        fclose(fpout);
  }

  fprintf(fp, "H %s %s %d\n", record_host, msgtype, time(0));
  fclose(fp);
  exit(0);

}

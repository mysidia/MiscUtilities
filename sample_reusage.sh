#!/bin/sh

#
# Example file size  sampling script for est_retime
#

# echo '1 * * * * /root/sample_reusage.sh ' >> /etc/crontab
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
VSPOOL=/var/spool/capturequeue/
RCOUNT=/root/v/sample_rtpcount
RRETAIN=/root/v/sample_rtpretain

du -ms ${VSPOOL}`date --date='1 hour ago'  +%Y-%m-%d/%H/*/A`  >> /root/v/sample_rusage`date +%Y_%m_%d`
du -ms ${VSPOOL}`date --date='1 hour ago'  +%Y-%m-%d/%H/*/B`  >> /root/v/sample_gusage`date +%Y_%m_%d`

a=`date +%Y-%m-%dT%H:%M:%S`

( find ${VSPOOL}`date +%Y-%m-%d` -maxdepth 4 -mtime -1 -name A ;
  find ${VSPOOL}`date +%Y-%m-%d --date='1 day ago'` -maxdepth 4 -mtime -1 -name A ) | sort | uniq| wc -l| awk -v a="$a" '{printf "%-10s  %s\n", a,$1}'   >> $RCOUNT

( find ${VSPOOL}`date +%Y-%m-%d` -maxdepth 4 -mtime -1 -name A ;
  find ${VSPOOL}`date +%Y-%m-%d --date='1 day ago'` -maxdepth 4 -mtime -1 -name A ) | sort | uniq  | cut -d'/' -f5-7 | awk -v a="$a" -F/ 'BEGIN{l="";u=""}; {x=sprintf("%sT%s:%s", $1,$2,$3); if (l=="" || x<l){l=x}; if (u=="" || x>u){u=x}}; END{printf "%s %s %s\n",a,l,u}'  >> $RRETAIN




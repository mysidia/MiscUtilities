#!/bin/sh


trap - SIGPIPE
/usr/bin/tail -n 200 /var/log/radius/radius.log 

#!/bin/sh
/usr/bin/tail -n 9000 /var/log/radius/radius.log | { /bin/grep "Login incorrect" |fgrep -v '(Home Server says so)'| /bin/sed 's/\[\([^\/]*\)\/\?\(.*\)\]/\[\1\]/'; exit 0; }

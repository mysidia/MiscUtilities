#!/bin/sh

tail -n 100000 /var/log/a-pix /var/log/b-pix /var/log/c-pix |grep 'Built inbound' |sed 's/TCP connection [0-9]* for outside:\([0-9\.]*\)\/\([0-9]*\) \(([0-9\./]*)\) /TCP connection (number) for outside:\1\/XX /' |cut -c16- |sort -rn |uniq -c  |sort -rn |head |less


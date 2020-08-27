#!/bin/sh
set -x
#gcc -o /usr/local/bin/mail-event-inputd -lpcre -lm   mail-event-inputd.c  -m64
gcc -o /usr/local/bin/mail-event-inputd  mail-event-inputd.c  -lpcre -lm -m64

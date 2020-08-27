# Copyright (C) 2007 Mysidia 


build: errbuf_watcher error_read.parse2

install:
	cp error_read.parse2 /home/errorparse
	cp errbuf_watcher    /home/errorparse


clean:
	rm -f errbuf_watcher errbuf_watcher.o
	rm -f error_read.parse2 error_read.parse2.o

errbuf_watcher:      errbuf_watcher.o

error_read.parse2:   error_read.parse2.o
	gcc -o error_read.parse2 error_read.parse2.o -lpcre

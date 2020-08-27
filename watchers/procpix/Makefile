all: build

clean:
	rm -f procpix readextract
	rm -f procpix.o readextract.o

build: procpix readextract

procpix: procpix.o
	gcc -o procpix procpix.o -lcares

procpix.o: procpix.c tree.h
	gcc -c procpix.c -ggdb

PRJ=xsesta06
CC=gcc
#CC=g++
CFLAGS= -pedantic -std=c99 -g -lpcap #++11

all: $(PRJ)

$(PRJ): $(PRJ).c
	        $(CC) $(PRJ).c $(CFLAGS) -o $(PRJ)

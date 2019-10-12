SRC=main.c functions.c
BIN=xsesta06
CC=gcc
#CC=g++
CFLAGS= -Wall -pedantic -std=c99 -g -lm -lpcap #++11

$(BIN): $(SRC)
	        $(CC) $(SRC) $(CFLAGS) -o $(BIN)

run: $(BIN)
					./$(BIN) -q www.fit.vutbr.cz -d dns.google.com -w whois.ripe.net
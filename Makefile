SRC=main.c functions.c
BIN=xsesta06
#CC=gcc
CC=g++
CFLAGS=  -pedantic -std=c++11 -g -lm -lpcap #99-Wall

$(BIN): $(SRC)
	        $(CC) $(SRC) $(CFLAGS) -o $(BIN)

run: $(BIN)
					./$(BIN) -q www.fit.vutbr.cz -d dns.google.com -w whois.ripe.net
					
runip: $(BIN)
					./$(BIN) -q 147.229.9.23 -d dns.google.com -w 193.0.6.135
					
runip2: $(BIN)
					./$(BIN) -q 8.8.8.8 -d dns.google.com -w 193.0.6.135
					
runhyb: $(BIN)
					./$(BIN) -q 147.229.9.23 -d dns.google.com -w whois.ripe.net
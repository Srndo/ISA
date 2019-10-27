SRC=main2.c functions.c
BIN=xsesta06
#CC=gcc
CC=g++
CFLAGS=  -pedantic -std=c++11 -g -lm -lpcap #99-Wall

$(BIN): $(SRC)
	        $(CC) $(SRC) $(CFLAGS) -o $(BIN)

run: $(BIN)
					./$(BIN) -q www.fit.vutbr.cz -d dns.google.com -w whois.ripe.net
					
run2: $(BIN)
					./$(BIN) -q www.fit.vutbr.cz -d cesnet.cz -w whois.iana.org
					
run3: $(BIN)
					./$(BIN) -q www.fit.vutbr.cz -d dns.google.com -w whois.arin.net
					
runip2: $(BIN)
					./$(BIN) -q 147.229.9.23 -d dns.google.com -w whois.iana.org
					
runip3: $(BIN)
					./$(BIN) -q 147.229.9.23 -d dns.google.com -w whois.arin.net
					
runip: $(BIN)
					./$(BIN) -q 147.229.9.23 -d dns.google.com -w whois.ripe.net

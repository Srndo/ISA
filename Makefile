SRC=main2.c functions.c
BIN=xsesta06
#CC=gcc
CC=g++
CFLAGS=  -pedantic -std=c++11 -g -lm #-lpcap #99-Wall

$(BIN): $(SRC)
	        $(CC) $(SRC) $(CFLAGS) -lresolv -o $(BIN)

run: $(BIN)
					./$(BIN) -q www.fit.vutbr.cz -w whois.ripe.net
					
run2: $(BIN)
					./$(BIN) -q www.mobilmania.cz -d 8.8.8.8 -w whois.iana.org
					
run3: $(BIN)
					./$(BIN) -q fit.vutbr.cz -d 208.67.222.222 -w whois.arin.net
					
run4: $(BIN)
					./$(BIN) -q www.seznam.cz -d 8.8.8.8 -w whois.arin.net
					
runip2: $(BIN)
					./$(BIN) -q 147.229.9.23 -d 8.8.8.8 -w whois.iana.org
					
runip3: $(BIN)
					./$(BIN) -q 147.229.9.23  -w whois.arin.net
					
runip: $(BIN)
					./$(BIN) -q 2001:67c:1220:809::93e5:917 -d 8.8.8.8 -w whois.ripe.net

runipip: $(BIN)
					./$(BIN) -q 147.229.9.23 -w 193.0.6.135

Whois tazatel 
Autor: Šimon Šesták (xsesta06)

Ceľom projektu bolo vytvoriť aplikáciu v C/C++. Vytvoril som program, ktorý po internete
posiela pakety na Whois servery, odpoveď od týchto serverov následne spracuje a vypíše ju vo formátovanej verzii.
Program na vstupe spracuje vstupné argumenty vďaka ktorým zistí na ktorý server sa má posielať žiadosť o zaslanie 
informácií o určenej doméne (sub-doméne, IP adrese, ...).


Aplikácia je rozdelená do dvoch zdrojových a jedného hlavičkového súboru.
Main()  -   hlavná funkcia, využíva getopt() pre parsovanie argumentov, resolv() pre zistenie DNS záznamov, vytvára socket 
                a pripája sa k whois serveru kde posiela dotaz na ziskanie infromácií ohľadom domény / IP adresy

Help()  -   pomocná funkcia využívaná pre oznámenie užívateľovi o korektnom využívaní argumentov

Err_argumets() -  pomocná funkcia pre ukončenie programu v prípade chyby zle zadaných argumentov

Err_exit(int, string) -  pomocná funkcia pre ukončenie programu v prípade chyby, zabezpečuje taktiež chybový výpis

Set_dns_server(int, char *) - pomocná funkcia pre nastavenie DNS resolvera na základe zadanej IP adresy "-d [IP]"

Resolver(char *, int *, char *) - pomocná funkcia pre dotazovanie DNS resolvera

Printf_cname(string, int *) -   pomocná funkcia pre výpis CNAME záznamu

Print_soa_admin_email(string) -   pomocná funkcia pre výpis SOA záznamu a admin emailu 

Printf_ns(string) -   pomocná funkcia pre výpis NS záznamu

Printf_mx(string) -   pomocná funkcia pre výpis MX záznamu

Printf_regex(regex, char *, int *) -   pomocná funkcia pre výpis informácií z whois odpovede

Printf_whois(char *) -   pomocná funkcia pre formátovaný výpis informácií z whois odpovede, zabezpečuje výpis podobných infromácií skupinovo


Návod na použitie
Rozbalte v priečinku, spuste terminál. V termináli použite pre preklad príkaz "make". 
Ak chcete vidieť typycké spustenia programu môžte použiť príkazy "make run", "make run [2-4]", "make runipip", "make runip", "make runip[2-3]". 
Ináč sa program spúšta v tvare: 

./isa-tazatel -q <IP | hostname> -d <IP> -w <IP | hostname>

-q <IP|hostname>, povinný argument
-w <IP|hostname WHOIS serveru>, který bude dotazován, povinný argument
-d <IP>, ktorý bude dotazovaný, nepovinný argument pričom implicitne sa používa DNS resolver v operačnom systéme


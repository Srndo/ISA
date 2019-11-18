#include "functions.h"

// fce for chceck if string is IP address
int isip(const char *src) {
    char buf[16];
    if (inet_pton(AF_INET, src, buf)) {
        return 4;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return 6;
    }
    return 0;
}

void help(){
    printf("-q <IP|hostname>, povinný argument\n");
    printf("-w <IP|hostname WHOIS serveru>, který bude dotazován, povinný argument\n");
    printf("-d <IP|hostname DNS serveru>, který bude dotazován, nepovinný argument přičemž implicitně se bere 1.1.1.1\n");
}

int err_arguments(){
    fprintf(stderr,"Bad usage of arguments\n");
    help();
    return 1;
}

int error_exit(int code, std::string str){
    fprintf(stderr, "%s\n",str.c_str());
    return code;
}

void set_dns_server(int *dflag, char *dns_server){
    if(*dflag){
        if(isip(dns_server) == 4){
            res_init();
            struct sockaddr_in dns;
            dns.sin_family = AF_INET;
            dns.sin_port = htons(53);
            inet_pton(AF_INET, dns_server, &dns.sin_addr);
            _res.nsaddr_list[0] = dns;
            _res.nscount = 1;
        }
    }
}

//ZDROJ: https://stackoverflow.com/questions/51401982/dns-retrieving-host-ip-address-using-resolv-h
int resolver(const char *dname, int *dflag, char *dns_server){
    printf("FOR: %s\n", dname);
    set_dns_server(dflag, dns_server);
    
#ifndef NDEBUG
    printf("DNS: %s\n", inet_ntoa(_res.nsaddr_list[0].sin_addr));
#endif
    
    union {
        HEADER hdr;
        u_char buf[NS_PACKETSZ];
    } response;
    
    int responseLen;
    ns_msg handle;
    int nType, cname_flag = FALSE;
    char dispbuf[NS_PACKETSZ];
    std::string str;
    
    for (int j = 0; j < 7; j++) {
        switch (j) {
            case 0:
                nType = ns_t_a;
                break;
            case 1:
                nType = ns_t_aaaa;
                break;
            case 2:
                nType = ns_t_soa;
                break;
            case 3:
                nType = ns_t_ptr;
                break;
            case 4:
                nType = ns_t_cname;
                break;
            case 5:
                nType = ns_t_ns;
                break;
            case 6:
                nType = ns_t_mx;
                break;
        }
        
        responseLen = res_search(dname, ns_c_in, nType, (u_char *)&response, sizeof(response));
        set_dns_server(dflag, dns_server); //sometimes res_search set IP to default, so reset it to our DNS
        
        if (responseLen < 0)
            continue;
        
        if (ns_initparse(response.buf, responseLen, &handle) < 0)
            continue;
        
        ns_rr rr;
        int rrnum;
        
        for (rrnum = 0; rrnum < (ns_msg_count(handle, ns_s_an)); rrnum++)
        {
            if (ns_parserr(&handle, ns_s_an, rrnum, &rr) < 0)
            {
                fprintf(stderr, "ERROR PARSING RRs\n");
                exit(-1);
            }
            
            switch(ns_rr_type(rr)){
                case ns_t_a:
                    struct in_addr in;
                    memcpy(&in.s_addr, ns_rr_rdata(rr), sizeof(in.s_addr));
                    printf("A:\t\t%s\n", inet_ntoa(in));
                    break;
                    
                case ns_t_aaaa:
                    struct in6_addr in6;
                    char ipv6[INET6_ADDRSTRLEN];
                    memcpy(&in6.s6_addr, ns_rr_rdata(rr), sizeof(in6.s6_addr));
                    inet_ntop(AF_INET6, &in6.s6_addr, ipv6, sizeof(ipv6));
                    printf("AAAA:\t\t%s\n", ipv6);
                    break;
                
                case ns_t_soa:
                    ns_sprintrr(&handle, &rr, NULL, NULL, reinterpret_cast<char*> (dispbuf), sizeof (dispbuf));
                    str.assign(dispbuf, strlen(dispbuf));
                    print_soa_admin_email(str);
                    break;
                    
                case ns_t_ptr:
//                    ns_sprintrr(&handle, &rr, NULL, NULL, reinterpret_cast<char*> (dispbuf), sizeof (dispbuf));
                    printf("PTR: \n");
//                    printf("%s\n",dispbuf);
                    break;
                    
                case ns_t_cname:
                    ns_sprintrr(&handle, &rr, NULL, NULL, reinterpret_cast<char*> (dispbuf), sizeof (dispbuf));
                    str.assign(dispbuf, strlen(dispbuf));
                    printf_cname(dispbuf, &cname_flag);
                    break;
                    
                case ns_t_ns:
                    ns_sprintrr(&handle, &rr, NULL, NULL, reinterpret_cast<char*> (dispbuf), sizeof (dispbuf));
                    str.assign(dispbuf, strlen(dispbuf));
                    print_ns(str);
                    break;
                    
                case ns_t_mx:
                    ns_sprintrr(&handle, &rr, NULL, NULL, reinterpret_cast<char*> (dispbuf), sizeof (dispbuf));
                    str.assign(dispbuf, strlen(dispbuf));
                    print_mx(dispbuf);
                break;
            }
        }
    }
    printf("\n");
    return 0;
}
//DONE: A, AAAA, SOA, MX, NS, CNAME,
//TODO:  PTR

void printf_cname(std::string const& s, int *flag){
    if(*flag)
        return;
    std::string::size_type pos_first = s.find("CNAME");
    std::string pom = s.substr(pos_first + 6);
    char *cstr = new char[pom.length() + 1];
    strcpy(cstr, pom.c_str());
    printf("CNAME:\t\t%s\n", cstr);
    *flag = TRUE;
}

void print_soa_admin_email(std::string const& s){
    std::string::size_type pos_last = s.find("(");
    std::string::size_type pos_first = s.find("SOA");
    std::string pom;
    
    const char *x = " ";
    pom = s.substr(pos_first + 4, pos_last - 27); // + 4 positon from SOA to start identification admin, -27 from last character to end of identifacion admin
    char *cstr = new char[pom.length() + 1];
    strcpy(cstr, pom.c_str());
    
    char *token = strtok(cstr, x);
    printf("SOA:\t\t%s\n", token);
    
    token = strtok(NULL, x);
    for(int i = 0; i < strlen(token); i++){ //TODO: upraviť pre prípad meno.priezvisko@doména
        if(token[i] == '.'){
            token[i] = '@';
            break;
        }
    }
    printf("admin email:\t%s\n", token);
}

void print_ns(std::string const& s){
    std::string::size_type pos_first = s.find("NS");
    std::string pom = s.substr(pos_first + 3);
    char *cstr = new char[pom.length() + 1];
    strcpy(cstr, pom.c_str());
    printf("NS:\t\t%s\n", cstr);
}

void print_mx(std::string const& s){
    std::string::size_type pos_first = s.find("MX");
    std::string pom = s.substr(pos_first + 3);
    char *cstr = new char[pom.length() + 1];
    strcpy(cstr, pom.c_str());
    printf("MX:\t\t%s\n", cstr);
}

void print_regex(const std::regex rx, char *output, int *out_flag){
    const char *x = "\n";
    char *pom = (char *)malloc((strlen(output) + 1) * sizeof(char));
    strcpy(pom, output);
    char *token = strtok(pom, x);
    while(token != NULL){
        if(std::regex_match(token, rx)){
            printf("%s\n", token);
            *out_flag = TRUE;
        }
        token = strtok(NULL, x);
    }
    free(pom);
}

void print_whois(char *output){
    const std::regex rx_inetnum("inetnum.*");
    const std::regex rx_netname("netname.*");
    const std::regex rx_descr("descr.*");
    const std::regex rx_country("country.*");
    const std::regex rx_admin("admin-c.*");
    const std::regex rx_address("address.*");
    const std::regex rx_phone("phone.*");
    const std::regex rx_inet6num("inet6num.*");
    const std::regex rx_NetRange("NetRange.*");
    const std::regex rx_NetName("NetName.*");
    int out_flag = FALSE;
    
    print_regex(rx_inetnum, output, &out_flag);
    print_regex(rx_inet6num, output, &out_flag);
    print_regex(rx_NetRange, output, &out_flag);
    print_regex(rx_netname, output, &out_flag);
    print_regex(rx_NetName, output, &out_flag);
    print_regex(rx_country, output, &out_flag);
    print_regex(rx_admin, output, &out_flag);
    print_regex(rx_address, output, &out_flag);
    print_regex(rx_phone, output, &out_flag);
    print_regex(rx_descr, output, &out_flag);
    
    if(out_flag == FALSE)
        printf("No log for this ip / domain on this whois server.\nOr regex not recognize something, try it again.\n");
}



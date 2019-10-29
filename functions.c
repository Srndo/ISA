#include "functions.h"

int isip(const char *src) {
    char buf[16];
    if (inet_pton(AF_INET, src, buf)) {
        return 0;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return 0;
    }
    return 1;
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

//https://stackoverflow.com/questions/51401982/dns-retrieving-host-ip-address-using-resolv-h
int resolver(const char *dname){
    union {
        HEADER hdr;
        u_char buf[NS_PACKETSZ];
    } response;
    
    int responseLen;
    res_init();
    ns_msg handle;
    int nType = ns_t_a;
    char dispbuf[NS_PACKETSZ];
    std::string str;
    
    for (int j = 0; j < 4; j++) {
        switch (j) {
            case 1:
                nType = ns_t_aaaa;
                break;
            case 2:
                nType = ns_t_soa;
                break;
            case 3:
                nType = ns_t_mx;
                break;
        }
            
        responseLen = res_search(dname, ns_c_in, nType, (u_char *)&response, sizeof(response));
        
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
                    printf("A:\t%s\n", inet_ntoa(in));
                    break;
                    
                case ns_t_aaaa:
                    printf("AAAA: \n");
                    break;
                    
                case ns_t_mx:
                    ns_sprintrr(&handle, &rr, NULL, NULL, reinterpret_cast<char*> (dispbuf), sizeof (dispbuf));
                    
                    printf("admin mail:\t%s\n", dispbuf);
                    break;
                    
                case ns_t_ptr:
                    printf("ns_t_ptr");
                    break;
                    
                case ns_t_soa:
                    ns_sprintrr(&handle, &rr, NULL, NULL, reinterpret_cast<char*> (dispbuf), sizeof (dispbuf));
                    
                    str.assign(dispbuf, strlen(dispbuf));
                    print_soa(str);
                    break;
            }
        }
    }
    return 0;
}

void print_soa(std::string const& s){
    std::string::size_type pos_last = s.find("(");
    std::string::size_type pos_first = s.find("SOA");
    std::string pom;
    
    const char *x = " ";
    pom = s.substr(pos_first + 4, pos_last - 29); // + 4 positon from SOA to start identification admin, -29 from last character to end of identifacion admin
    char *cstr = new char[pom.length() + 1];
    strcpy(cstr, pom.c_str());
    printf("SOA:\t%s\n", strtok(cstr, x));
}

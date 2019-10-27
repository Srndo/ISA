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

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

int DnsLookup(char *hostname, char *ip){
  /*
  int sockfd;  
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_in *ip_access;
  int rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo(hostname, "http", &hints, &servinfo)) != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      exit(1);
  }

  for(p = servinfo; p != NULL; p = p->ai_next){
    ip_access = (struct sockaddr_in *) p->ai_addr;
    pritnf("IP: %s\n",inet_ntoa(ip_access->sin_addr));
  }

  if (p == NULL) {
      // looped off the end of the list with no connection
      fprintf(stderr, "failed to connect\n");
      exit(2);
  }

  freeaddrinfo(servinfo);
  */
  return 0;
}

//int print_response(char *str){
//    char c;
//    while(
//}

//std::string get_last_word(const std::string& s) {
//  auto index = s.find_last_of(' ');
//  return s.substr(++index);
//}

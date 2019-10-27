#include <regex>
#include "functions.h"

#define BUFFER 8124
#define DEBUG


int main(int argc, char **argv) {
    int sock, msg_size, i;
    socklen_t len;
    struct sockaddr_in local, server, dns;
    char buffer[BUFFER];
    uid_t uid;
    struct hostent *servent_local, *servent_server, *servent_dns;
    struct passwd *uname;
    
    
    int opt;
    extern char *optarg;
    char client[100], whois_server[100], dns_server[100] = "\0";
    int qflag = 0;
    int wflag = 0;
    int dflag = 0;
    int out_flag = 0;
    
    if(argc < 5 || argc > 7){
        return err_arguments();
    }
    
    while((opt = getopt(argc, argv, ":q:w:d:")) != -1){
        switch(opt){
            case 'q':
                strcpy(client, optarg);
                qflag++;
                break;
            case 'w':
                strcpy(whois_server, optarg);
                wflag++;
                break;
            case 'd':
                strcpy(dns_server, optarg);
                dflag++;
                break;
            case '?':
            default:
                return err_arguments();
        }
    }
    
    if(qflag != 1 || wflag != 1){
        return err_arguments();
    }
    
    memset(&server,0,sizeof(server)); // erase the server structure
    memset(&local,0,sizeof(local));   // erase local address structure
    
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(whois_server, "whois", &hints, &servinfo)) != 0) {
        fprintf(stderr, "Whois getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("connect");
            close(sockfd);
            continue;
        }

        break; // if we get here, we must have connected successfully
    }
    
    if (p == NULL) {
        // looped off the end of the list with no connection
        fprintf(stderr, "failed to connect\n");
        exit(2);
    }
#ifdef DEBUG
    else
        printf("Succefull connect to server\n");


    char host[256];
    getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof (host), NULL, 0, NI_NUMERICHOST);
    puts(host);
#endif
    
    memset(&servinfo, 0, sizeof servinfo);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(client, NULL, &hints, &servinfo)) != 0) {
        fprintf(stderr, "Client getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    
//https://github.com/angrave/SystemProgramming/wiki/Networking,-Part-2:-Using-getaddrinfo
    getnameinfo(servinfo->ai_addr, servinfo->ai_addrlen, client, sizeof (client), NULL, 0, NI_NUMERICHOST);
    strcat(client, "\r\n");
    
#ifdef DEBUG
    printf("Client: %s\n", client);
#endif
    
    freeaddrinfo(servinfo); // all done with this structure
    
    i = 1; // initialize for while condition
    printf("=== WHOIS ===\n");
    while(i != 0){
        
#ifdef DEBUG
        printf("WHILE Client: %s\n", client);
#endif
        i = write(sockfd, client, strlen(client));
        if (i == -1)
            return error_exit(1, "buffer send write() failed");
        
        if((i = read(sockfd, buffer, BUFFER)) == -1)
            return error_exit(1, "buffer send read() failed");
        else if(i == 0){
            if(out_flag == 0)
                printf("No log for this ip / domain: %s on this whois server.",client );
            break;
        }
        else{
            char *token;
            const char *x = "\n";
            
            token = strtok(buffer, x);
            
            while( token != NULL ) {
                const std::regex my_regex("inetnum.*");
                const std::regex my_regex2("netname.*");
                const std::regex my_regex3("descr.*");
                const std::regex my_regex4("country.*");
                const std::regex my_regex5("admin-c.*");
                const std::regex my_regex6("address.*");
                const std::regex my_regex7("phone.*");
                const std::regex my_regex8("inet6num.*");
                const std::regex my_regex9("NetRange.*");
                const std::regex my_regex10("NetName.*");

                if(std::regex_match(token, my_regex) ||
                   std::regex_match(token, my_regex2) ||
                   std::regex_match(token, my_regex3) ||
                   std::regex_match(token, my_regex4) ||
                   std::regex_match(token, my_regex5) ||
                   std::regex_match(token, my_regex6) ||
                   std::regex_match(token, my_regex7) ||
                    std::regex_match(token, my_regex8) ||
                    std::regex_match(token, my_regex9) ||
                    std::regex_match(token, my_regex10)){
                     printf("%s\n", token );
                        out_flag = 1;
                    }
                
                token = strtok(NULL, x);
            }
        }
    }
    return 0;
}

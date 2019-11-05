#include "functions.h"

#define NDEBUG

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
    char client[100] = "\0", whois_server[100] = "\0", dns_server[100] = "\0";
    int qflag = FALSE;
    int wflag = FALSE;
    int dflag = FALSE;
    int out_flag = FALSE;
    
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
    
    if(qflag != TRUE || wflag != TRUE){
        return err_arguments();
    }
    
    char client_dns[100];
    strcpy(client_dns, client);
    
    printf("=== DNS ===\n");
    
    if (isip(client) == 4) { //https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
        resolver(client); //resolver with IP
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, client_dns, &sa.sin_addr);
        
        int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), client_dns, sizeof(client_dns), NULL, 0, NI_NAMEREQD); //get hostname for whois
        if(res)
            error_exit(res, gai_strerror(res));
    }
    else if(isip(client) == 6)
        return error_exit(0, "getnameinfo() not supported ipv6\n");
    
    if(isip(client) == 0){      //add www. if not set for query all informations
        if(client[0] != 'w' && client[1] != 'w' && client[2] != 'w'){
            char pom[100] = "www.";
            strcat(pom, client);
            strcpy(client, pom);
        }
    }
    resolver(client_dns); //resolver with dname with www.
    
    if(client_dns[0] == 'w'){   //remove www. for query more informations (get those which not queried from before)
        char pom[100] = "\0";
        for(int i = 0, j = 0; client_dns[i] != '\0'; i++){
            if(client_dns[i] == 'w')
                continue;
            if(client_dns[i] == '.' && client_dns[i - 1] == 'w' && i <= 3)
                continue;
            
            pom[j++] = client_dns[i];
        }
        resolver(pom); //resolver without www.
    }
    
    memset(&server,0,sizeof(server)); // erase the server structure
    memset(&local,0,sizeof(local));   // erase local address structure
    
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;
    
    if ((rv = getaddrinfo(whois_server, "whois", &hints, &servinfo)) != 0) { //get IP address of whois server
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
    
    if (p == NULL) // looped off the end of the list with no connection
        return error_exit(2, "failed to connect\n");
        
#ifdef DEBUG
    else
        printf("Succefull connect to server\n");
    
    
    char host[256];
    getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof (host), NULL, 0, NI_NUMERICHOST);
    puts(host);
#endif
    
    memset(&servinfo, 0, sizeof servinfo);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if ((rv = getaddrinfo(client, NULL, &hints, &servinfo)) != 0) { //get IP address of server which user want info
        fprintf(stderr, "Client getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    
    //https://github.com/angrave/SystemProgramming/wiki/Networking,-Part-2:-Using-getaddrinfo
    getnameinfo(servinfo->ai_addr, servinfo->ai_addrlen, client, sizeof (client), NULL, 0, NI_NUMERICHOST);
    strcat(client, "\r\n"); // add 2 new lines for correct
    
#ifdef DEBUG
    printf("Client: %s\n", client);
#endif
    
    freeaddrinfo(servinfo); // all done with this structure
    
    i = 1; // initialize for while condition
    int realloc_num = 1; // if need realloc this var will be incremented for another realloc
    char *output = (char *)malloc(sizeof(char) * ALLOC_OUTPUT); // allocate memory for output
    if(!output)
        return error_exit(1, "INTERNAL ERROR: memory not allocated");
    
    printf("=== WHOIS ===\n");
    while(i != 0){ // reading response from server until EOF
        
#ifdef DEBUG
        printf("WHILE Client: %s\n", client);
#endif
        i = write(sockfd, client, strlen(client)); // send query to server
        if (i == -1)
            return error_exit(1, "buffer send write() failed");
        
        if((i = read(sockfd, buffer, BUFFER)) == -1) // read response
            return error_exit(1, "buffer send read() failed");
        else if(i == 0){
            if(out_flag == FALSE)
                printf("No log for this ip / domain: %s on this whois server.",client );
            break;
        }
        else{ // get information only we want
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
                    
                    if(strlen(token) + strlen(output) + 1 >= ALLOC_OUTPUT * realloc_num){ // if inforamtion is longer than allocated area realloc
                        output = (char *)realloc(output,sizeof(char) * (ALLOC_OUTPUT * ++realloc_num));
                        if(!output)
                            return error_exit(1, "INTERNAL ERROR: memory not reallocated");
                    }
                    if(strstr(output, token) == NULL){ // save only non-duplicited informations
                        strcat(output, token);
                        strcat(output, "\n");
                    }
                    out_flag = 1; // information were queried
                }
                token = strtok(NULL, x); // do again with new line of info
            }
        }
    }
    if(out_flag == TRUE)
        print_whois(output);
    free(output);
    return 0;
}

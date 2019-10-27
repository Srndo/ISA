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
//    int wflag = 0;
    int dflag = 0;
    
    if(argc < 5 || argc > 7){
        return err_arguments();
    }
    
    while((opt = getopt(argc, argv, ":q:w:d:")) != -1){
        switch(opt){
            case 'q':
                strcpy(client, optarg);
                qflag++;
                break;
//            case 'w':
//                strcpy(whois_server, optarg);
//                wflag++;
//                break;
//            case 'd':
//                strcpy(dns_server, optarg);
//                dflag++;
//                break;
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
    
    //if (isip(whois_server) != 0) {
    if((servent_server = gethostbyname(whois_server)) == NULL)
        return error_exit(1, "gethostbyname() failed");
    
    // copy the first parameter to the server.sin_addr structure
    //printf("%s\n",inet_ntoa(servent->h_addr));
    memcpy(&server.sin_addr,servent_server->h_addr,servent_server->h_length);
    
    if((servent_local = gethostbyname(client)) == NULL) //NEFUNGUJE
        return error_exit(1, "gethostbyname() failed");
    
    // copy the first parameter to the server.sin_addr structure
    //printf("%s\n",inet_ntoa(servent->h_addr));
    memcpy(&local.sin_addr,servent_local->h_addr,servent_local->h_length);
    
    if((servent_dns = gethostbyname(dns_server)) == NULL) //NEFUNGUJE
        return error_exit(1, "gethostbyname() failed");
    
    // copy the first parameter to the server.sin_addr structure
    //printf("%s\n",inet_ntoa(servent->h_addr));
    memcpy(&dns.sin_addr,servent_dns->h_addr,servent_dns->h_length);
    /*}
     else{
     server.sin_addr.s_addr = inet_addr(whois_server);
     printf("%d\n", inet_addr(whois_server));
     }*/
    server.sin_family = AF_INET;
    server.sin_port = htons(43);
    
    if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) //create client Socket
        return error_exit(1,"socket() failed");
    
    #ifdef DEBUG
        printf("* Socket successfully created\n");
    #endif
    
    uid = getuid();
    uname = getpwuid(uid);
    
    // connect to the remote server
    // client port and IP address are assigned automatically by the operating system
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == -1)
        return error_exit(1,"connect() failed");
    
    // obtain the local IP address and port using getsockname()     NEEDED ?
    /*
     len = sizeof(local);
     if (getsockname(sock,(struct sockaddr *) &local, &len) == -1)
     return error_exit(1,"getsockname() failed");
     */
    #ifdef DEBUG
        printf("* Client successfully connected from %s, port %d (%d) to %s, port %d (%d)\n", inet_ntoa(local.sin_addr),ntohs(local.sin_port),local.sin_port,inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);
    #endif
    
    i = write(sock,buffer,strlen(buffer));
    if (i == -1){
        return error_exit(1,"initial write() failed");
    }
    
    if ((i = read(sock,buffer,BUFFER)) == -1){  // read an initial string
    return error_exit(1,"initial read() failed");
    } else {
    printf("%.*s\n",i,buffer);
    }
    
    //keep communicating with server
    // read input data from STDIN (console) until end-of-line (Enter) is pressed
    // when end-of-file (CTRL-D) is received, msg_size == 0
    
    strcpy(client, inet_ntoa(local.sin_addr));
    strcat(client, "\r\n");
    strcpy(buffer, client);
    msg_size = strlen(buffer);
    printf("=== WHOIS ===\n");
    while((msg_size=read(STDIN_FILENO,buffer,BUFFER)) > 0){
//    if (dns_server[0] != '\0') {
//        strcpy(dns_server, inet_ntoa(dns.sin_addr));
//        strcat(dns_server, "\r\n");
//        strcpy(buffer, dns_server);
//        msg_size = strlen(buffer);
//        printf("=== DNS ===\n");
//
//        for(int j = 0; j < 2 ; j++){
//            i = write(sock,buffer,msg_size);             // send data to the server
//            if (i == -1)                                 // check if data was sent correctly
//                return error_exit(1,"write() failed");
//            else if (i != msg_size)
//                return error_exit(1,"write(): buffer written partially");
//
//            if ((i = read(sock,buffer, BUFFER)) == -1)   // read the answer from the server
//                return error_exit(1,"read() failed");
//            else if (i > 0)
//            {
//                char *token;
//                const char *x = "\n";
//
//                token = strtok(buffer, x);
//
//                while( token != NULL ) {
//                    //                const std::regex my_regex("A:.*");
//                    //                const std::regex my_regex2("AAAA.*");
//                    //                const std::regex my_regex3("SOA.*");
//                    //                const std::regex my_regex4("admin email.*");
//                    //
//                    //                if(std::regex_match(token, my_regex) ||
//                    //                   std::regex_match(token, my_regex2) ||
//                    //                   std::regex_match(token, my_regex3) ||
//                    //                   std::regex_match(token, my_regex4))
//                    printf("%s\n", token );
//                    token = strtok(NULL, x);
//                }
//            }
//        }
//    }
    
//    strcpy(client, inet_ntoa(local.sin_addr));
//    strcat(client, "\r\n");
//    strcpy(buffer, client);
//    msg_size = strlen(buffer);
//    printf("=== WHOIS ===\n");
    
//    for(int j = 0; j < 2 ; j++){
        i = write(sock,buffer,msg_size);             // send data to the server
        if (i == -1)                                 // check if data was sent correctly
            return error_exit(1,"write() failed");
        else if (i != msg_size)
            return error_exit(1,"write(): buffer written partially");
        
        if ((i = read(sock,buffer, BUFFER)) == -1)   // read the answer from the server
            return error_exit(1,"read() failed");
        else if (i > 0)
        {
            char *token;
            const char *x = "\n";
            
            token = strtok(buffer, x);
            
            while( token != NULL ) {
//                const std::regex my_regex("inetnum.*");
//                const std::regex my_regex2("netname.*");
//                const std::regex my_regex3("descr.*");
//                const std::regex my_regex4("country.*");
//                const std::regex my_regex5("admin-c.*");
//                const std::regex my_regex6("address.*");
//                const std::regex my_regex7("phone.*");
//
//                if(std::regex_match(token, my_regex) ||
//                   std::regex_match(token, my_regex2) ||
//                   std::regex_match(token, my_regex3) ||
//                   std::regex_match(token, my_regex4) ||
//                   std::regex_match(token, my_regex5) ||
//                   std::regex_match(token, my_regex6) ||
//                   std::regex_match(token, my_regex7))
                    printf("%s\n", token );
                
                token = strtok(NULL, x);
            }
        }
//    }
    }
    // reading data until end-of-file (CTRL-D)
    
    if (msg_size == -1)
        return error_exit(1,"reading failed");
    close(sock);
    
    #ifdef DEBUG
        printf("* Closing the client socket ...\n");
    #endif
    
    return 0;
}

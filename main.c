
#include "functions.h"

#define BUFFER 8124
#define DEBUG


int main(int argc, char **argv) {
  int sock, msg_size, i;
  socklen_t len;
  struct sockaddr_in local, server;
  char buffer[BUFFER];
  uid_t uid;   
  struct hostent *servent;                  
  struct passwd *uname;
  
  
  int opt;
  extern char *optarg;
  char client[100], whois_server[100], dns_server[100];
  int qflag = 0;
  int wflag = 0;
  int dflag = 0;
  
  if(argc < 5 || argc > 7){
    return err_arguments();    
  }
  
  while((opt = getopt(argc, argv, ":q:w:d:")) != -1){
    switch(opt){
      case 'q':
        printf("option: %c | %s\n", opt, optarg);
        strcpy(client, optarg);
        qflag++;
        break;
      case 'w':
        printf("option: %c | %s\n", opt, optarg);
        strcpy(whois_server, optarg);
        wflag++;
        break;
      case 'd':
        printf("option: %c | %s\n", opt, optarg);
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
  
  strcpy(whois_server, "whois.ripe.net");
  
  memset(&server,0,sizeof(server)); // erase the server structure
  memset(&local,0,sizeof(local));   // erase local address structure

   //if (isip(whois_server) != 0) {
     if((servent = gethostbyname(whois_server)) == NULL) //NEFUNGUJE
      return error_exit(1, "gethostbyname() failed");
     
      // copy the first parameter to the server.sin_addr structure
      //printf("%s\n",inet_ntoa(servent->h_addr));
      memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 
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
  
  //strcpy(buffer,client);  
  
  i = send(sock,buffer,strlen(buffer),0);
  if (i == -1){
    return error_exit(1,"initial write() failed");
  }

  if ((i = read(sock,buffer,BUFFER)) == -1){  // read an initial string
    return error_exit(1,"initial read() failed");
  } else {
    printf("%.*s\n",i,buffer);
  }

  //keep communicating with server
  while((msg_size=read(STDIN_FILENO,buffer,BUFFER)) > 0) 
      // read input data from STDIN (console) until end-of-line (Enter) is pressed
      // when end-of-file (CTRL-D) is received, msg_size == 0
  { 
    i = write(sock,buffer,msg_size);             // send data to the server
    if (i == -1)                                 // check if data was sent correctly
      return error_exit(1,"write() failed");
    else if (i != msg_size)
      return error_exit(1,"write(): buffer written partially");
    
    if ((i = read(sock,buffer, BUFFER)) == -1)   // read the answer from the server
      return error_exit(1,"read() failed");
    else if (i > 0)
      printf("%.*s",i,buffer);                   // print the answer
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
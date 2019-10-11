#include<stdio.h> 
#include<string.h>    
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<netdb.h>
#include <sys/types.h>

int isip(const char *src);
void help();
int err_arguments();
int error_exit(int code, char *str);
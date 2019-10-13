#include <ctype.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>    
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <pwd.h>
#include <string>

int isip(const char *src);
void help();
int err_arguments();
int error_exit(int code, std::string str);
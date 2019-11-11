#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ctype.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pwd.h>
#include <iostream>
#include <regex>
#include <resolv.h>

#define BUFFER 8124
#define TRUE 1
#define FALSE 0
#define ALLOC_OUTPUT 100
#define NDEBUG

int isip(const char *src);
void help();
int err_arguments();
int error_exit(int code, std::string str);
int resolver(const char *dname);
void print_soa_admin_email(std::string const& s);
void print_whois(char *output);
void print_ns(std::string const& s);
void printf_cname(std::string const& s, int *flag);
void print_mx(std::string const& s);
#endif

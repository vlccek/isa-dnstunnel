//
// Created by jvlk on 4.11.22.
//

#ifndef COMMON_H
#define COMMON_H
#include "dns_receiver_events.h"
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "dns.h"
#include "Base64/base64.h"
#include "stdbool.h"

#define InternalError(message, args...)    PrintErrorExit("%15s:%d | in %s() | " message "\n", 99 ,__FILE__, __LINE__,  __FUNCTION__, ## args)
#define PrintErrorExit(format, ERR_CODE, ...)    do{  fprintf(stderr, format, __VA_ARGS__); fflush(stderr); exit(ERR_CODE);}while(0)
#define checkNullPointer(p)   if ((p) == NULL){InternalError("Mememory err :("); exit(99);} // pro malloc
#define debug 1

#define initIndicator "init"

#define printlog(format, ...)    do{  fprintf(stderr, format, __VA_ARGS__);}while(0)
#define log(message, args...)    if (debug == 1) {printlog("%15s:%d | in %s() | " message "\n", __FILE__, __LINE__,  __FUNCTION__, ## args);}

#define PORT 8080
#define MAXLINE 1024
#define DNS_PORT 7654

#define maxQNameLen 253

#define maxSubDomainLen 63
#define udpLen 65536

#define maxSubDomainLenBeforeEncodes ((maxSubDomainLen * 3 / 4) - 4) // from Base64 implematation


int createSocketClient(struct sockaddr_in *ipadd4, const char *ipadd);
int createSocketServer(struct sockaddr_in *servaddr, const char *ipadd);

#endif //COMMON_H

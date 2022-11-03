//
// Created by jvlk on 19.10.22.
//

#ifndef DNSTUNNEL_SERVER_H
#define DNSTUNNEL_SERVER_H

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

#define InternalError(message, args...)    PrintErrorExit("%15s:%d | in %s() | " message "\n", 99 ,__FILE__, __LINE__,  __FUNCTION__, ## args)
#define PrintErrorExit(format, ERR_CODE, ...)    do{  fprintf(stderr, format, __VA_ARGS__); fflush(stderr); exit(ERR_CODE);}while(0)

const unsigned maxQNameLen = 253;
const unsigned maxSubDomainLen = 63;

#endif //DNSTUNNEL_SERVER_H

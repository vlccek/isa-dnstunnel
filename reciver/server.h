//
// Created by jvlk on 4.11.22.
//

#ifndef SERVER_H
#define SERVER_H
#include "common.h"
#include "dns.h"
#include "base16.h"
#include "dns_receiver_events.h"


void reallocDesTable();
char *extractFileName(const char *qname);
char *exctractBaseDomain(const char *qname);
bool isQnameBaseDomain(const int *pid, const char *qname);
bool isQnameToBaseDomain(char *qname, char *base);
#endif //SERVER_H

//
// Created by jvlk on 4.11.22.
//

#ifndef SERVER_H
#define SERVER_H
#include "common.h"
#include "dns.h"
#include "base16.h"


void reallocDesTable();
char *extractFileName(const char *qname);
char *exctractBaseDomain(const char *qname);
bool isQnameBaseDomain(const int *pid, const char *qname);
#endif //SERVER_H

//
// Created by jvlk on 24.10.22.
//

#include <inttypes.h>


#ifndef DNSTUNNEL_DNS_H
#define DNSTUNNEL_DNS_H
#include "common.h"

#define refuseDNS 0x05




typedef struct __attribute__((packed))
{
	unsigned short id; // identification number

	unsigned char rd: 1; // recursion desired
	unsigned char tc: 1; // truncated message
	unsigned char aa: 1; // authoritive answer
	unsigned char opcode: 4; // purpose of message
	unsigned char qr: 1; // query/response flag

	unsigned char rcode: 4; // response code
	unsigned char cd: 1; // checking disabled
	unsigned char ad: 1; // authenticated data
	unsigned char z: 1; // its z! reserved
	unsigned char ra: 1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
} dns_header;

typedef struct __attribute__((packed))
{
	uint16_t qtype;
	uint32_t qclass;
} dns_qestion;

// Struct for answer's data witch dont have variable len
typedef struct __attribute__((__packed__)) {
    // Name - same as in qestion
    uint16_t type;
    uint16_t qclass;
    uint32_t ttl;
    uint16_t rdlength;
    // RDATA
} dns_response;

int insertDnsHeader(void *outBuff, int id, int qr, int rc);

int insertQName(void *outBuff, const char *qname);

int insertName(void *outBuff, const char *qname);

int insertQinfo(void *buff, int qclass, int qtype, int pacLen);

int insertAinfo(void *buff, int type, int class, int ttl, unsigned pacLen);

void extractDataFromDnsQ(char *in, char **qname, dns_header **header);

void extractDataFromResponse(char *in, char **qname, dns_header **header, dns_response **resp);

void changeToDnsNameFormat(char *dns, char *host);

#endif //DNSTUNNEL_DNS_H

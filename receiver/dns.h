//
// Created by jvlk on 24.10.22.
//

#include <inttypes.h>

#ifndef DNSTUNNEL_DNS_H
#define DNSTUNNEL_DNS_H


#pragma pack(push, 1)
typedef struct {
    uint16_t id; // id of comunication
    char qr: 1;
    char opcode: 4;
    char aa: 1;
    char rd: 1;
    char ra: 1; //
    char zero: 1; // allways set to zero
    char rcode: 1; // return codec

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header;
#pragma pack(pop)

#pragma pack(push, 1)
struct R_DATA {
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint32_t data_len;
};
#pragma pack(pop)

#endif //DNSTUNNEL_DNS_H

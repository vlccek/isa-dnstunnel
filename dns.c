//
// Created by jvlk on 24.10.22.
//

#include "dns.h"
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

int insertQName(void *outBuff, const char *qname)
{
	outBuff = outBuff + sizeof(dns_header);

	strcpy(outBuff, qname);
	return strlen(qname);
}

int insertName(void *outBuff, const char *qname)
{
	return insertQName(outBuff, qname);
}

int insertQinfo(void *buff, int qclass, int qtype, int pacLen)
{
	dns_qestion *qinfo = (dns_qestion *)(buff + pacLen + 1);
	qinfo->qclass = htons(qclass);
	qinfo->qtype = htons(qtype);
	return sizeof(dns_qestion);
}

int insertAinfo(void *buff, int type, int class, int ttl, unsigned pacLen)
{
	answer_not_variable_len_members *ans = (answer_not_variable_len_members *)(buff + pacLen + 1);

	ans->ans_type = 0xc0; // pointer
	ans->name_offset = 0x0c;
	ans->type = htons(1);
	ans->qclass = htons(class);
	ans->ttl = htonl(ttl);
	ans->rdlength = sizeof(in_addr_t);
	inet_pton(AF_INET, "10.10.10.10", &ans->rdlength + sizeof(ans->rdlength));
	return sizeof(answer_not_variable_len_members) + sizeof(in_addr_t);
}

/*
 * Vrací delku paketu
 */
int insertDnsHeader(void *outBuff, int id, int qr)
{
	dns_header *dns_h = (dns_header *)outBuff;

	dns_h->id = (unsigned short)htons(id);
	dns_h->qr = qr;
	dns_h->opcode = 0;
	dns_h->aa = 0;
	dns_h->tc = 0;
	dns_h->rd = 1;
	dns_h->ra = 0;
	dns_h->z = 0;
	dns_h->ad = 0;
	dns_h->cd = 0;
	dns_h->rcode = 0;
	dns_h->q_count = htons(1);
	dns_h->ans_count = 0;
	dns_h->auth_count = 0;
	dns_h->add_count = 0;

	log("Creating header of dns packet. ID: %d", dns_h->id);

	return sizeof(dns_header);
}


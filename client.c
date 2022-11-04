//
// Created by jvlk on 19.10.22.
//

#include <stdbool.h>
#include "client.h"
#include "dns_receiver_events.h"
#include "dns_sender_events.h"


void ChangetoDnsNameFormat(char *dns, char *host)
{
	int lock = 0, i;
	strcat((char *)host, ".");

	for (i = 0; i < strlen((char *)host); i++) {
		if (host[i] == '.') {
			*dns++ = i - lock;
			for (; lock < i; lock++) {
				*dns++ = host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++ = '\0';
}

int insertQName(void *outBuff, const char *qname)
{
	outBuff = outBuff + sizeof(dns_header);
	char tmpstr[maxQNameLen];
	strncpy(tmpstr, qname, maxQNameLen);

	ChangetoDnsNameFormat(outBuff, (char *)&tmpstr);
	return (int)strlen(outBuff) - 1;
}

/*
 * Vrací delku paketu
 */
int insertDnsHeader(void *outBuff, int id)
{
	dns_header *dns_h = (dns_header *)outBuff;

	dns_h->id = (unsigned short)htons(id);
	dns_h->qr = 0;
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

	return sizeof(dns_header);
}

int insertQinfo(void *buff, int qclass, int qtype, int pacLen)
{
	dns_qestion *qinfo = (dns_qestion *)(buff + pacLen + 1);
	qinfo->qclass = htons(qclass);
	qinfo->qtype = htons(qtype);
	return sizeof(dns_qestion);
}

bool readData(FILE *fp, const char *domain, char *buff)
{
	memset(buff, 0, maxQNameLen);
	int i, buffCount = 0, domainNameCount = 0;
	unsigned maxDataLen = maxQNameLen - (unsigned)strlen(domain) - 1; // -1 becouse dot after domain

	char tmpbuff[maxSubDomainLenBeforeEncodes] = {0};
	char *encoded_text;


	while (((maxSubDomainLen * domainNameCount) + buffCount) < maxDataLen && i != EOF) {
		while ((i = fgetc(fp)) != EOF) {
			tmpbuff[buffCount++] = (char)i;
			if (buffCount % maxSubDomainLenBeforeEncodes == 0) {
				break;
			}
		}

		encoded_text = base64_encode(tmpbuff);
		strcat(buff, encoded_text);
		strcat(buff, ".");
		free(encoded_text);
		buffCount = 0, domainNameCount++;
	}
	strcat(buff, domain);
	return i != EOF;
}

int main(int argc, char *argv[])
{
	if (!(argc == 4 || argc == 6)) {
		InternalError("Not enought/too much params: %d. Expecting 4 or 6", argc - 1);
	}
	char *baseHost = NULL, *dstFilePath = NULL, *srcFilePath = NULL;
	int index = 0;
	if (argc == 6) {
		index = 2;
	}
	baseHost = argv[index + 1];
	dstFilePath = argv[index + 2];
	srcFilePath = argv[index + 3];

	FILE *dstFile = fopen(srcFilePath, "r");
	if (dstFile == NULL) {
		InternalError("Can't open file!  %s", srcFilePath);
	}

	struct sockaddr_in sa;
	int bytes_sent;
	unsigned char buf[65536];
	int pacLen = 0; // lenght of packet

	char example[254];
	int sock = createSocketClient(&sa, "127.0.0.1");


	while (readData(dstFile, baseHost, example)) {
		pacLen += insertDnsHeader(&buf, 0);
		pacLen += insertQName(&buf, example);
		pacLen += insertQinfo(&buf, 1, 1, pacLen);

		bytes_sent =
			sendto(sock, &buf, pacLen, 0, (struct sockaddr *)&sa, (size_t)sizeof sa);
		if (bytes_sent < 0) {
			printf("Error sending packet: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		pacLen = 0;
		printf("%d bytes sended \n", bytes_sent);
		fflush(stdout);
	}

	close(sock); /* close the socket */
	return 0;

}

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


size_t readChunck(FILE *fp, char buff[maxSubDomainLen])
{
	size_t buffCount = fread(buff, (size_t)1, (size_t)31, fp);
	buff[buffCount] = '\0';
	return buffCount;
}

/* Read new chars from file and encodes it. Len is lenght of encoded text
 */
char *readDecodesChunck(FILE *fp, int *len)
{
	char buff[maxSubDomainLen + 1];
	int subchunkLen = (int)readChunck(fp, buff);
	log("Reading text: `%s`", buff);

	char *encoded = tobase16(buff, subchunkLen);
	log("Encoded to base16: `%s`", encoded);
	*len = subchunkLen * 2;
	return encoded;

}

bool readData(FILE *fp, const char *domain, char *buff)
{
	char *qname = buff;
	memset(qname, 0, maxQNameLen);
	unsigned ussableQnameLen = maxQNameLen - (unsigned)strlen(domain) - 1; // -1 becouse dot after domain
	char *decoded_text;
	int chuckLen = 0, qnameC = 0;
	static bool last = false;

	while (qnameC + maxSubDomainLen < ussableQnameLen && !last) {
		decoded_text = readDecodesChunck(fp, &chuckLen);
		if (chuckLen == 0) {
			last = true;
		}
		qname[qnameC++] = (char)chuckLen;
		memcpy(&qname[qnameC], decoded_text, chuckLen);
		qnameC += chuckLen;

		free(decoded_text);

	}
	char tmp[maxQNameLen];
	char domaninTmp[maxQNameLen];
	strcpy(domaninTmp, domain);
	ChangetoDnsNameFormat(tmp, domaninTmp);
	strcat(qname, tmp);
	log("Qstring: \n		`%s`", qname);
	return chuckLen != 0 || qnameC != 0;
}


/*
 * true = good, false = not good
 */
bool checkConfirmationPac(char *buf)
{
	char *qname;
	dns_header *dns_h;
	dns_response *dns_r;
	extractDataFromResponse(buf, &qname, &dns_h, &dns_r);

	return dns_h->rcode == 0;
}

void sendInitPacket(int sock, char *dstFilePath, struct sockaddr *sa, char *domain)
{

	char buf[udpLen];

	char data[maxQNameLen];
	char *dstfileEncoded = tobase16(dstFilePath, (int)strlen((dstFilePath)));
	sprintf(data, "%s.%s.%s", initIndicator, dstfileEncoded, domain);


	char tmp[maxQNameLen];
	ChangetoDnsNameFormat(tmp, data);
	free(dstfileEncoded);

	int pacLen = 0; // lenght of packet
	pacLen += insertDnsHeader(&buf, getpid(), 0, refuseDNS);
	pacLen += insertQName(&buf, tmp);
	pacLen += insertQinfo(&buf, 1, 1, pacLen);

	unsigned len;
	if (!sendRecv(sock, buf, pacLen, buf, udpLen, sa, &len)) {
		PrintErrorExit("Server not responding %d", EXIT_FAILURE, len);
	}

	if (!checkConfirmationPac(buf)) {
		PrintErrorExit("Confirmation message is not in good format. %d", EXIT_FAILURE, len);
	};

}

void sendEndingPacket(int sock, struct sockaddr *sa, char *domain)
{
	log("Sending ending packet")
	char buf[udpLen];
	char data[maxQNameLen];
	sprintf(data, "%s.%s", closeIndicator, domain);


	char tmp[maxQNameLen];
	ChangetoDnsNameFormat(tmp, data);

	int pacLen = 0; // lenght of packet
	pacLen += insertDnsHeader(&buf, getpid(), 0, refuseDNS);
	pacLen += insertQName(&buf, tmp);
	pacLen += insertQinfo(&buf, 1, 1, pacLen);

	unsigned len;
	if (!sendRecv(sock, buf, pacLen, buf, udpLen, sa, &len)) {
		PrintErrorExit("Server not responding %d", EXIT_FAILURE, len);
	}

	if (!checkConfirmationPac(buf)) {
		PrintErrorExit("Confirmation message is not in good format. %d", EXIT_FAILURE, len);
	};
}

int main(int argc, char *argv[])
{
	if (!(argc == 4 || argc == 6)) {
		InternalError("Not enought/too much params: %d. Expecting 4 or 6", argc - 1);
	}
	char *baseHost = NULL, *dstFilePath = NULL, *srcFilePath = NULL, *ipDnsServer;
	int index = 0;
	if (argc == 6) {
		ipDnsServer = argv[3];
		index = 2;
	}
	else {
		// todo parser DNS IP
	}
	baseHost = argv[index + 1];
	dstFilePath = argv[index + 2];
	srcFilePath = argv[index + 3];

	log("Opening file %s", srcFilePath);
	FILE *dstFile = fopen(srcFilePath, "r");
	if (dstFile == NULL) {
		InternalError("Can't open file!  %s", srcFilePath);
	}

	struct sockaddr_in sa;
	int bytes_sent;
	char buf[udpLen];
	int pacLen = 0; // lenght of packet
	unsigned int len;

	char data[254];
	int sock = createSocketClient(&sa, "127.0.0.1");

	sendInitPacket(sock, dstFilePath, (struct sockaddr *)&sa, baseHost);

	while (readData(dstFile, baseHost, data)) {
		pacLen += insertDnsHeader(&buf, getpid(), 0, 0);
		pacLen += insertQName(&buf, data);
		pacLen += insertQinfo(&buf, 1, 1, pacLen);

		bytes_sent = sendto(sock, &buf, pacLen, 0, (struct sockaddr *)&sa, (size_t)sizeof sa);
		if (bytes_sent < 0) {
			printf("Error sending packet: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		pacLen = 0;
		log("%d bytes sended", bytes_sent);
		memset(&buf, 0, udpLen);

	}

	sendEndingPacket(sock, (struct sockaddr *)&sa, baseHost);

	close(sock); /* close the socket */
	return 0;

}

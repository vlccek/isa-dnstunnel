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


int readChunck(FILE *fp, char buff[maxSubDomainLen])
{
	int i, buffCount = 0;
	while ((i = fgetc(fp)) != EOF) {
		buff[buffCount++] = (char)i;
		if (buffCount == maxSubDomainLenBeforeEncodes) {
			break;
		}
	}
	buff[buffCount] = '\0';
	return buffCount;
}

/* Read new chars from file and encodes it. Len is lenght of encoded text
 */
char *readDecodesChunck(FILE *fp, int *len)
{
	char buff[maxSubDomainLen + 1];
	readChunck(fp, buff);
	log("Reading text: `%s`", buff);

	char *encoded = base64_encode(buff);
	log("Encoded to base64: `%s`", encoded);
	*len = (int)strlen(encoded);
	return encoded;

}

bool readData(FILE *fp, const char *domain, char *buff)
{
	char *qname = buff;
	unsigned ussableQnameLen = maxQNameLen - (unsigned)strlen(domain) - 1; // -1 becouse dot after domain
	char *decoded_text;
	int chuckLen = 0, qnameC = 0;

	while (qnameC + maxSubDomainLen < ussableQnameLen) {
		decoded_text = readDecodesChunck(fp, &chuckLen);
		if (chuckLen == 0) {
			break;
		}
		qname[qnameC++] = (char)chuckLen;
		strcpy(&qname[qnameC], decoded_text);
		qnameC += chuckLen;

		free(decoded_text);

	}
	char tmp[maxQNameLen];
	char domaninTmp[maxQNameLen];
	strcpy(domaninTmp, domain);
	ChangetoDnsNameFormat(tmp, domaninTmp);
	strcat(qname, tmp);
	log("Qstring: \n		`%s`", qname);
	return chuckLen != 0;
}

void sendInitPacket(int sock, char *dstFilePath, struct sockaddr *sa, char *domain)
{

	unsigned char buf[65536];

	char data[maxQNameLen];
	char *dstfileEncoded = base64_encode(dstFilePath);
	sprintf(data, "%s.%s.%s", initIndicator, dstfileEncoded, domain);


	char tmp[maxQNameLen];
	ChangetoDnsNameFormat(tmp, data);
	free(dstfileEncoded);

	int pacLen = 0; // lenght of packet
	pacLen += insertDnsHeader(&buf, getpid(), 0);
	pacLen += insertQName(&buf, tmp);
	pacLen += insertQinfo(&buf, 1, 1, pacLen);

	int bytes_sent = sendto(sock, &buf, pacLen, 0, sa, (size_t)sizeof(*sa));
	if (bytes_sent < 0) {
		printf("Error sending packet: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	log("Init packet was sent. %d bytes sended", bytes_sent);
	unsigned len;
	recvfrom(sock, &buf, sizeof(buf), MSG_WAITALL, (struct sockaddr *)&sa, &len);

	printf("%s", buf);

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

	char data[254];
	int sock = createSocketClient(&sa, "127.0.0.1");

	sendInitPacket(sock, dstFilePath, (struct sockaddr *)&sa, baseHost);

	while (readData(dstFile, baseHost, data)) {
		pacLen += insertDnsHeader(&buf, 0, 0);
		pacLen += insertQName(&buf, data);
		pacLen += insertQinfo(&buf, 1, 1, pacLen);

		bytes_sent = sendto(sock, &buf, pacLen, 0, (struct sockaddr *)&sa, (size_t)sizeof sa);
		if (bytes_sent < 0) {
			printf("Error sending packet: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		pacLen = 0;
		log("%d bytes sended", bytes_sent);
		memset(buf, 0, sizeof(buf));
		fflush(stdout);
	}

	close(sock); /* close the socket */
	return 0;

}

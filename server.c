//
// Created by jvlk on 4.11.22.
//

#include "server.h"

#define fdTableDefSize 2

typedef struct
{
	// Fd of file where is written
	FILE **fdTable;
	// counts of active transfers
	int activeTransfers;
	// size of fdTable and transfer IDS
	unsigned sizeOfTransferIds;
	// id from dns headers
	int *transferIds;
	// Base domain save in DNS format.
	char **baseDomains;
} filesDescriptorTable_t;

filesDescriptorTable_t descriptorTable = {NULL, 0, 0, NULL, NULL};

// table of files that are transferred


void reallocDesTable();
char *extractFileName(const char *qname);
char *exctractBaseDomain(const char *qname);
bool isQnameBaseDomain(const int *pid, const char *qname);
FILE *getFileDescriptor(int id)
{
	for (int i = 0; i < descriptorTable.activeTransfers; i++) {
		if (descriptorTable.transferIds[i] == id) {
			return descriptorTable.fdTable[i];
		}
	}
	return NULL;
}

char *getBaseDomain(int id)
{
	for (int i = 0; i < descriptorTable.activeTransfers; i++) {
		if (descriptorTable.transferIds[i] == id) {
			return descriptorTable.baseDomains[i];
		}
	}
	return NULL;
}

/*
 * Creates file where is transferred text is saved
 */
void createTransfer(char *filename, int pid, char *baseDomain)
{
	if (descriptorTable.sizeOfTransferIds < descriptorTable.activeTransfers + 1) {
		reallocDesTable();
	}
	descriptorTable.fdTable[descriptorTable.activeTransfers] = fopen(filename, "w+");
	checkNullPointer(descriptorTable.fdTable[descriptorTable.activeTransfers]);
	descriptorTable.transferIds[descriptorTable.activeTransfers] = pid;
	descriptorTable.baseDomains[descriptorTable.activeTransfers] = baseDomain;
	descriptorTable.activeTransfers++;

}
void reallocDesTable()
{
	if (descriptorTable.transferIds == NULL) {
		checkNullPointer(descriptorTable.transferIds = malloc(sizeof(int *) * fdTableDefSize));
		checkNullPointer(descriptorTable.fdTable = malloc(sizeof(FILE *) * fdTableDefSize));
		checkNullPointer(descriptorTable.baseDomains = malloc(sizeof(char *) * fdTableDefSize));
		descriptorTable.sizeOfTransferIds = fdTableDefSize;
	}
	else {
		unsigned newsize = descriptorTable.sizeOfTransferIds * 2;
		checkNullPointer(descriptorTable.transferIds = realloc(descriptorTable.transferIds,
															   sizeof(int *) * newsize));
		checkNullPointer(descriptorTable.fdTable = realloc(descriptorTable.transferIds,
														   sizeof(FILE *) * newsize));
		checkNullPointer(descriptorTable.baseDomains = realloc(descriptorTable.baseDomains,
															   sizeof(FILE *) * newsize));
		descriptorTable.sizeOfTransferIds = newsize;
	}
}

/*
 * Create record about new transfer
 */
char *addToTransfers(char *qname, int PID)
{
	char *fileName = extractFileName(qname);
	char *basedomain = exctractBaseDomain(qname);

	createTransfer(fileName, PID, basedomain);
	return fileName;

}
char *exctractBaseDomain(const char *qname)
{
	int sizeinit = strlen(initIndicator);
	int sizeofFileName = (int)qname[sizeinit + 1];
	const char *basedomainstart = qname + 1 + sizeinit + 1 + sizeofFileName + 1;

	char *basedomain;
	checkNullPointer(basedomain = malloc(sizeof(char) * strlen(basedomainstart)));
	strcpy(basedomain, basedomainstart);

	return basedomain;
}
char *extractFileName(const char *qname)
{
	char *fileName;

	int sizeinit = strlen(initIndicator);
	int sizeofFileName = (int)qname[sizeinit + 1];
	char encodedFileName[maxSubDomainLen] = {0};
	strncpy(encodedFileName, qname + sizeinit + 1 + 1, sizeofFileName);

	fileName = base64_decode(encodedFileName);
	return fileName;
}

unsigned short getPID(const char *dnsPacket)
{
	return ((dns_header *)dnsPacket)->id;

}

/*
 * Check if its init packet if no return false otherwise crete file descriptor available via getFileDescriptor by id
 * of transfer
 */
bool isInit(char *qname, unsigned short pid)
{
	int sizeinit = strlen(initIndicator);
	if (strncmp(qname + 1, initIndicator, sizeinit) == 0) { // 5init#nameOfFile.base.domain
		addToTransfers(qname, pid); // 5init#nameOfFile.base.domain
		return true;
	}
	else {
		return false;
	}
}

/*
 * ounts lenght of qname in packet.
 */
int lenQname(char *buff)
{
	return strlen(buff + sizeof(dns_header));
}
/* takes pointer to dns packet, and returns pointr to array of decoded strings. IF returns NULL, its init packet
*/
char **getDataFromDnsPacket(char *in, int *pid)
{
	char *qname = in + sizeof(dns_header);
	*pid = getPID(in);

	if (isInit(qname, *pid)) {
		return NULL;
	}

	char **output = malloc(sizeof(char *) * MAXSUBDOMAINWITHDATA); // todo move it
	int i = 0;
	int nextNameLen = 0;
	char encodedStr[maxSubDomainLen], *decodedChunk;

	do {
		// printf("%d", nextNameLen);
		nextNameLen = (int)*(qname++);
		if (isQnameBaseDomain(pid, qname)) {
			for (int l = i; l < MAXSUBDOMAINWITHDATA; l++)
				output[l] = NULL;
			break;
		}
		strncpy(encodedStr, qname, nextNameLen);
		encodedStr[nextNameLen] = '\0';
		qname += nextNameLen;

		decodedChunk = base64_decode(encodedStr);
		log("Decoded data: %s", decodedChunk);
		output[i++] = decodedChunk;
	}
	while (nextNameLen != 0);

	return output;
}
bool isQnameBaseDomain(const int *pid, const char *qname)
{ return strcmp(qname, getBaseDomain(*pid)) == 0; }

int main(int argc, char *argv[])
{
	struct sockaddr_in sa, ca;
	memset(&ca, 0, sizeof(ca));

	char bufRec[udpLen];
	char bufSend[udpLen];

	unsigned len = sizeof(ca);
	unsigned bytesSend;
	unsigned bytesRec;
	unsigned pacLen = 0;

	int id;
	dns_header *header;
	char *qname;

	int sock = createSocketServer(&sa, "127.0.0.1");
	while (1) {
		log("Waiting for data....")
		bytesRec = recvfrom(sock, bufRec, udpLen, MSG_WAITALL, (struct sockaddr *)&ca, &len);
		log ("%d bytes was recived", bytesRec)
		char **data = getDataFromDnsPacket(bufRec, &id);
		extractDataFromDnsQ(bufRec, &qname, &header);

		if (data == NULL) {
			log("Init packet id: %d, basedomain: %s", id, getBaseDomain(id));

			pacLen += insertDnsHeader(bufSend, id, 1, 0);
			pacLen += insertName(bufSend, qname);
			pacLen += insertAinfo(bufSend, 1, 1, 1000, pacLen);
			bytesSend = sendto(sock, bufSend, pacLen, MSG_CONFIRM, (struct sockaddr *)&ca, (size_t)sizeof ca);
			pacLen = 0;
			continue;
		}
		else {
			for (int i = 0; i < 5 && data[i] != NULL; i++) {
				fprintf(getFileDescriptor(id), "%s", data[i]);
				printf("%s", data[i]);
				fflush(stdout);
				// free(data[i]);
			}
		}
		// free(data)
	}
//	printf("hovnod: %s", base64_decode(bufRec + sizeof(dns_header)));
}
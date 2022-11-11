//
// Created by jvlk on 4.11.22.
//

#include "server.h"

#define fdTableDefSize 2

typedef struct
{
	FILE *fd;
	int transferIds;
	char baseDomains[255];
} trio_file_id_domain;

typedef struct
{
	// counts of active transfers
	int activeTransfers;
	// size of fd and transfer IDS
	unsigned sizeOfTransferIds;
	trio_file_id_domain *table;

} filesDescriptorTable_t;

filesDescriptorTable_t descriptorTable = {0, 0, NULL};

// table of files that are transferred



trio_file_id_domain *gettrioTableMember(int id)
{
	for (int i = 0; i < descriptorTable.activeTransfers; i++) {
		if (descriptorTable.table[i].transferIds == id) {
			return &descriptorTable.table[i];
		}
	}
	return NULL;
}

FILE *getFileDescriptor(int id)
{
	trio_file_id_domain *member = gettrioTableMember(id);

	if (member == NULL) {
		return NULL;
	}
	else {
		return member->fd;
	}
}

char *getBaseDomain(int id)
{
	trio_file_id_domain *member = gettrioTableMember(id);

	if (member == NULL) {
		return NULL;
	}
	else {
		return member->baseDomains;
	}
}

bool checkIfNotExist(int pid)
{
	return gettrioTableMember(pid) == NULL ? false : true;
}
/*
 * Creates file where is transferred text is saved
 */
void createTransfer(char *filename, int pid, char *baseDomain)
{
	if (checkIfNotExist(pid)) {
		log("Warning transfer with id: `%d` already exists", pid);
		return;
	}
	if (descriptorTable.activeTransfers < descriptorTable.activeTransfers + 1) {
		reallocDesTable();
	}
	descriptorTable.table[descriptorTable.activeTransfers].fd = fopen(filename, "w+");
	checkNullPointer(descriptorTable.table[descriptorTable.activeTransfers].fd);
	descriptorTable.table[descriptorTable.activeTransfers].transferIds = pid;
	strcpy(descriptorTable.table[descriptorTable.activeTransfers].baseDomains, baseDomain);
	descriptorTable.activeTransfers++;

}
void reallocDesTable()
{
	if (descriptorTable.table == NULL) {
		checkNullPointer(descriptorTable.table = calloc(sizeof(trio_file_id_domain *) * fdTableDefSize, 0));
		descriptorTable.sizeOfTransferIds = fdTableDefSize;
	}
	else {
		unsigned newsize = descriptorTable.sizeOfTransferIds * 2;
		checkNullPointer(descriptorTable.table = realloc(descriptorTable.table,
														 sizeof(int *) * newsize));
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

	fileName = frombase16(encodedFileName, (int)strlen(encodedFileName));
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

bool isClosing(char *qname, unsigned short pid)
{
	int sizeofclosing = strlen(initIndicator);
	if (strncmp(qname + 1, closeIndicator, sizeofclosing - 1) == 0) { // 5init#nameOfFile.base.domain
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
char **getDataFromDnsPacket(char *in, int *pid, int *lens)
{
	char *qname = in + sizeof(dns_header);
	*pid = getPID(in);

	if (isInit(qname, *pid) || isClosing(qname, *pid)) {
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

		decodedChunk = frombase16(encodedStr, nextNameLen);
		log("Decoded data: %s", decodedChunk);
		lens[i] = nextNameLen / 2;
		output[i++] = decodedChunk;
	}
	while (nextNameLen != 0);

	return output;
}
bool isQnameBaseDomain(const int *pid, const char *qname)
{ return strncmp(qname, getBaseDomain(*pid), strlen(getBaseDomain(*pid))) == 0; }

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

	int id, lens[5];
	dns_header *header;
	char *qname;


	int sock = createSocketServer(&sa, "127.0.0.1");
	while (1) {
		log("Waiting for data....")
		bytesRec = recvfrom(sock, bufRec, udpLen, MSG_WAITALL, (struct sockaddr *)&ca, &len);
		log ("%d bytes was recived", bytesRec)
		extractDataFromDnsQ(bufRec, &qname, &header);
		id = header->id;

		if (isInit(qname, id)) {
			log("Init packet id: %d, basedomain: %s", id, getBaseDomain(id));

			pacLen += insertDnsHeader(bufSend, id, 1, 0);
			pacLen += insertName(bufSend, qname);
			pacLen += insertAinfo(bufSend, 1, 1, 1000, pacLen);
			bytesSend = sendto(sock, bufSend, pacLen, MSG_CONFIRM, (struct sockaddr *)&ca, (size_t)sizeof ca);

			continue;
		}
		else if (isClosing(qname, id)) {
			log("Ending packet id: %d, basedomain: %s", id, getBaseDomain(id));

			pacLen += insertDnsHeader(bufSend, id, 1, 0);
			pacLen += insertName(bufSend, qname);
			pacLen += insertAinfo(bufSend, 1, 1, 1000, pacLen);
			bytesSend = sendto(sock, bufSend, pacLen, MSG_CONFIRM, (struct sockaddr *)&ca, (size_t)sizeof ca);

			fclose(getFileDescriptor(id));
			continue;
		}
		else {
			char **data = getDataFromDnsPacket(bufRec, &id, lens);
			for (int i = 0; i < 5 && data[i] != NULL; i++) {
				fwrite(data[i], 1, lens[i], getFileDescriptor(id));
				// free(data[i]);
			}
		}
		pacLen = 0;
		memset(bufRec, 0, udpLen);
		// free(data)
	}
//	printf("hovnod: %s", base16_decode(bufRec + sizeof(dns_header)));
}
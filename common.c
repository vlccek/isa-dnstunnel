//
// Created by jvlk on 4.11.22.
//

#include "common.h"




int createSocketClient(struct sockaddr_in *ipadd4, const char *ipadd)
{/* create an Internet, datagram, socket using UDP */
	int sock;
	(sock) = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ((sock) == -1) {
		/* if socket failed to initialize, exit */
		printf("Error Creating Socket");
		exit(EXIT_FAILURE);
	}

	/* Zero out socket address */
	memset(ipadd4, 0, sizeof(*ipadd4));

	/* The address is IPv4 */
	(*ipadd4).sin_family = AF_INET;

	/* IPv4 addresses is a uint32_t, convert a string representation of the octets to the appropriate value */
	(*ipadd4).sin_addr.s_addr = inet_addr(ipadd);

	/* sockets are unsigned shorts, htons(x) ensures x is in network byte order, set the port to 7654 */
	(*ipadd4).sin_port = htons(DNS_PORT);


	return sock;
}
int createSocketServer(struct sockaddr_in *servaddr, const char *ipadd)
{/* create an Internet, datagram, socket using UDP */
	int sock;
	(sock) = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ((sock) == -1) {
		/* if socket failed to initialize, exit */
		printf("Error Creating Socket");
		exit(EXIT_FAILURE);
	}

	/* Zero out socket address */
	memset(servaddr, 0, sizeof(*servaddr));

	/* The address is IPv4 */
	(*servaddr).sin_family = AF_INET;

	/* IPv4 addresses is a uint32_t, convert a string representation of the octets to the appropriate value */
	(*servaddr).sin_addr.s_addr = INADDR_ANY;

	/* sockets are unsigned shorts, htons(x) ensures x is in network byte order, set the port to 7654 */
	(*servaddr).sin_port = htons(DNS_PORT);

	if (bind(sock, (const struct sockaddr *)servaddr, sizeof(*servaddr)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void setTimeout(int sockID, int waiting, int waitingmss)
{
	struct timeval tv;
	tv.tv_sec = waiting;
	tv.tv_usec = waitingmss;
	if (setsockopt(sockID, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		perror("Error");
	}

}

/*
 * Send buffsend, waits TIMEOUT seconds if not responds. repeat this ATTEMPTS times. Recived data are in buffrec.
 * If return true buffrec is not empty
 */
bool sendRecv(int sock,
			  char *buffsend,
			  int buffsendlen, // how many will be sent
			  char *buffrec,
			  size_t buffSizeRec,
			  struct sockaddr *sa,
			  unsigned int *saSize)
{

	int bytes_sent;
	setTimeout(sock, TIMEOUT, 0);

	for (int i = 0; i < ATTEMPTS; i++) {
		log("Waiting for answer from server, attempt %d/%d ...", i + 1, ATTEMPTS);
		bytes_sent = sendto(sock, buffsend, buffsendlen, 0, sa, (size_t)sizeof(*sa));
		if (bytes_sent < 0) {
			printf("Error sending packet: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		log("%d was sended", bytes_sent);

		if (recvfrom(sock, buffrec, buffSizeRec, MSG_WAITALL, (struct sockaddr *)sa, saSize) > 0) {
			return true;
		}
		log("Nothing recived. Trying again ...");
	}

	return false;

}
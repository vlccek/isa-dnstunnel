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
int createSocketServer(struct sockaddr_in *ipadd4, const char *ipadd)
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
	(*ipadd4).sin_addr.s_addr = INADDR_ANY;

	/* sockets are unsigned shorts, htons(x) ensures x is in network byte order, set the port to 7654 */
	(*ipadd4).sin_port = htons(DNS_PORT);

	if (bind(sock, (const struct sockaddr *)ipadd4, sizeof(*ipadd4)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	return sock;
}